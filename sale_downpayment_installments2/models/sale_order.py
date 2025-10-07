from odoo import models, fields, api
from odoo.exceptions import UserError
from dateutil.relativedelta import relativedelta


class SaleOrder(models.Model):
    _inherit = 'sale.order'

    # -----------------------------
    # Fields
    # -----------------------------
    payment_type = fields.Selection([
        ('cash', 'Immediate Cash Payment'),
        ('installment', 'Installment Payment')
    ], string="Payment Type", default='cash', required=True)

    show_installment_section = fields.Boolean(
        string="Show Installment Section",
        compute="_compute_show_installment_section",
        store=False
    )

    down_payment_required = fields.Monetary(string="Total Down Payment")
    down_payment_paid_now = fields.Monetary(string="Paid Now")
    down_payment_due_date = fields.Date(string="Down Payment Due Date")
    down_payment_locked = fields.Boolean(string="Down Payment Locked", default=False)

    is_down_payment_complete = fields.Boolean(
        string="Down Payment Completed",
        compute="_compute_down_payment_complete",
        store=True
    )

    first_installment_amount = fields.Monetary(string="First Installment Amount")
    installment_months = fields.Integer(string="Number of Months", default=5)
    installment_start_date = fields.Date(string="Installment Start Date")

    installment_breakdown = fields.Char(
        compute="_compute_installment_breakdown",
        string="Installment Breakdown"
    )

    remaining_payment = fields.Monetary(
        string="Remaining Payment After Down Payment",
        compute="_compute_remaining_payment",
        store=True
    )

    next_down_payment_amount = fields.Monetary(
        string="Next Down Payment Amount",
        compute="_compute_next_down_payment_amount",
        store=False,
        readonly=True
    )

    installment_ids = fields.One2many(
        'sale.installment.plan',
        'sale_order_id',
        string="Installments"
    )

    # -----------------------------
    # Computations
    # -----------------------------
    @api.depends('payment_term_id', 'payment_type')
    def _compute_show_installment_section(self):
        for order in self:
            order.show_installment_section = order.payment_type == 'installment'

    @api.depends('amount_total', 'installment_ids.paid', 'installment_ids.amount')
    def _compute_remaining_payment(self):
        for order in self:
            total_installment_paid = sum(order.installment_ids.filtered(lambda i: i.paid).mapped('amount'))
            down_paid = sum(order.env['account.move'].search([
                ('invoice_origin', '=', order.name),
                ('payment_state', '=', 'paid')
            ]).mapped('amount_total'))
            order.remaining_payment = max(order.amount_total - down_paid - total_installment_paid, 0.0)

    @api.depends('down_payment_required', 'down_payment_paid_now')
    def _compute_next_down_payment_amount(self):
        for order in self:
            order.next_down_payment_amount = max(
                (order.down_payment_required or 0.0) - (order.down_payment_paid_now or 0.0),
                0.0
            )

    @api.depends('first_installment_amount', 'installment_months', 'down_payment_required', 'amount_total', 'payment_type')
    def _compute_installment_breakdown(self):
        for order in self:
            if order.payment_type != 'installment':
                order.installment_breakdown = ''
                continue

            total = order.amount_total
            down = order.down_payment_required or 0.0
            first = order.first_installment_amount or 0.0
            months = order.installment_months

            if months < 1 or first > (total - down):
                order.installment_breakdown = 'Invalid configuration'
                continue

            remaining = total - down - first
            other_months = months - 1

            if other_months <= 0:
                order.installment_breakdown = f"One Installment: {first:.2f}"
            else:
                per_month = round(remaining / other_months, 2)
                order.installment_breakdown = f"First: {first:.2f}, Then: {per_month:.2f} x {other_months}"

    @api.depends('down_payment_required')
    def _compute_down_payment_complete(self):
        """Automatically check if down payment invoices are fully paid."""
        for order in self:
            invoices = self.env['account.move'].search([
                ('invoice_origin', '=', order.name),
                ('state', '=', 'posted'),
                ('payment_state', '=', 'paid')
            ])
            total_paid = sum(invoices.mapped('amount_total'))
            order.is_down_payment_complete = total_paid >= (order.down_payment_required or 0.0)

    # -----------------------------
    # Onchange
    # -----------------------------
    @api.onchange('payment_term_id')
    def _onchange_payment_term_set_payment_type(self):
        if self.payment_term_id:
            name = self.payment_term_id.name.lower()
            self.payment_type = 'installment' if any(k in name for k in ['installment', 'monthly', 'payment plan']) else 'cash'
        else:
            self.payment_type = 'cash'

    # -----------------------------
    # Actions
    # -----------------------------
    def action_register_down_payment(self):
        """
        Generate the down payment invoice,
        and immediately create installment invoices for visibility/tracking,
        even if down payment is not yet paid.
        """
        for order in self:
            if order.down_payment_locked:
                raise UserError("Down payment has already been registered.")

            if order.down_payment_required <= 0:
                raise UserError("Invalid down payment amount.")

            # ✅ Create and post Down Payment invoicee
            down_invoice = order._create_invoice_for_down_payment(order.down_payment_required)
            down_invoice.invoice_origin = order.name
            down_invoice.action_post()

            # ✅ Lock down payment section
            order.down_payment_locked = True

            # ✅ Automatically generate Installment plan and invoices
            order._generate_installments_automatically()

            # ✅ Activity Log
            order._create_activity("Down Payment and Installment Invoices Generated", fields.Date.today())

    def _generate_installments_automatically(self):
        """Generate installment invoices immediately after down payment invoice creation."""
        for order in self:
            if order.payment_type != 'installment':
                continue

            total = order.amount_total
            down = order.down_payment_required or 0.0
            first = order.first_installment_amount or 0.0
            months = order.installment_months or 1
            remaining = total - down

            if remaining <= 0:
                continue

            rest = remaining - first
            per_month = round(rest / max(months - 1, 1), 2)

            # Clear any existing installments
            order.installment_ids.unlink()

            base_date = order.installment_start_date or fields.Date.today()

            for i in range(months):
                due_date = base_date + relativedelta(months=i)
                amount = first if i == 0 else per_month

                plan = self.env['sale.installment.plan'].create({
                    'sale_order_id': order.id,
                    'installment_number': i + 1,
                    'amount': amount,
                    'due_date': due_date,
                    'paid': False,
                    'locked': True,
                })

                # ✅ Create and post invoice
                invoice = order._create_invoice_for_installment(plan)
                invoice.invoice_origin = order.name
                invoice.action_post()
                plan.invoice_id = invoice.id

    # -----------------------------
    # Helpers
    # -----------------------------
    def _create_invoice_for_down_payment(self, amount):
        """Create down payment invoice."""
        revenue_account = self.env['account.account'].search([
            ('account_type', '=', 'income')
        ], limit=1)
        if not revenue_account:
            raise UserError("No income account found for invoice creation.")

        return self.env['account.move'].create({
            'move_type': 'out_invoice',
            'partner_id': self.partner_id.id,
            'invoice_origin': self.name,
            'invoice_date': fields.Date.today(),
            'invoice_line_ids': [(0, 0, {
                'name': 'Down Payment',
                'quantity': 1,
                'price_unit': amount,
                'account_id': revenue_account.id,
            })]
        })

    def _create_invoice_for_installment(self, plan):
        """Create an invoice for a specific installment."""
        revenue_account = self.env['account.account'].search([
            ('account_type', '=', 'income')
        ], limit=1)
        if not revenue_account:
            raise UserError("No income account found for invoice creation.")

        return self.env['account.move'].create({
            'move_type': 'out_invoice',
            'partner_id': self.partner_id.id,
            'invoice_origin': self.name,
            'invoice_date': plan.due_date,
            'invoice_line_ids': [(0, 0, {
                'name': f'Installment {plan.installment_number}',
                'quantity': 1,
                'price_unit': plan.amount,
                'account_id': revenue_account.id,
            })]
        })

    def _create_activity(self, summary, deadline=None):
        """Create system activity log."""
        self.env['mail.activity'].create({
            'res_model_id': self.env['ir.model']._get_id('sale.order'),
            'res_id': self.id,
            'activity_type_id': self.env.ref('mail.mail_activity_data_todo').id,
            'summary': summary,
            'date_deadline': deadline or fields.Date.today(),
            'user_id': self.user_id.id,
        })

    # -----------------------------
    # Overrides
    # -----------------------------
    @api.model
    def create(self, vals):
        payment_term = self.env['account.payment.term'].browse(vals.get('payment_term_id'))
        if payment_term:
            name = payment_term.name.lower()
            vals['payment_type'] = 'installment' if any(k in name for k in ['installment', 'monthly', 'payment plan']) else 'cash'
        return super().create(vals)

    def write(self, vals):
        payment_term = self.env['account.payment.term'].browse(vals.get('payment_term_id'))
        if payment_term:
            name = payment_term.name.lower()
            vals['payment_type'] = 'installment' if any(k in name for k in ['installment', 'monthly', 'payment plan']) else 'cash'
        return super().write(vals)
