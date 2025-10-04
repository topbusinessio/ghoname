from odoo import models, fields, api
from odoo.exceptions import UserError
from datetime import date
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
    is_down_payment_complete = fields.Boolean(string="Down Payment Completed", default=False)

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
        """Controls visibility of installment-related sections."""
        for order in self:
            order.show_installment_section = (
                order.payment_type == 'installment'
            )

    @api.depends('amount_total', 'down_payment_required')
    def _compute_remaining_payment(self):
        for order in self:
            order.remaining_payment = max(order.amount_total - (order.down_payment_required or 0.0), 0.0)

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

    # -----------------------------
    # Onchange - Control payment type from Payment Terms
    # -----------------------------
    @api.onchange('payment_term_id')
    def _onchange_payment_term_set_payment_type(self):
        """Automatically set payment_type based on Payment Terms name."""
        if self.payment_term_id:
            name = self.payment_term_id.name.lower()
            if any(k in name for k in ['installment', 'monthly', 'payment plan']):
                self.payment_type = 'installment'
            else:
                self.payment_type = 'cash'
        else:
            self.payment_type = 'cash'

    # -----------------------------
    # Actions
    # -----------------------------
    def action_register_down_payment(self):
        for order in self:
            if order.down_payment_paid_now <= 0 or order.down_payment_paid_now > order.down_payment_required:
                raise UserError("Invalid amount paid now.")

            order._create_invoice_for_down_payment(order.down_payment_paid_now)

            if order.down_payment_paid_now < order.down_payment_required:
                order._create_activity("Collect Remaining Down Payment", order.down_payment_due_date)
            else:
                order.is_down_payment_complete = True
                order._create_activity("Down Payment Completed", fields.Date.today())

    def action_generate_installments(self):
        """Generates installment records and alerts."""
        for order in self:
            if order.payment_type != 'installment':
                raise UserError("This action is only for installment-based payments.")

            if order.installment_months < 2:
                raise UserError("At least two installments are required.")

            if order.down_payment_required and not order.is_down_payment_complete:
                raise UserError("Please complete the down payment before generating installments.")

            total = order.amount_total
            down = order.down_payment_required or 0.0
            first = order.first_installment_amount or 0.0
            remaining = total - down

            if first > remaining:
                raise UserError("First installment cannot exceed remaining amount after down payment.")

            rest = remaining - first
            per_month = round(rest / (order.installment_months - 1), 2)

            # Clear existing installments
            order.installment_ids.unlink()

            due_date = order.installment_start_date or fields.Date.today()

            if first:
                self.env['sale.installment.plan'].create({
                    'sale_order_id': order.id,
                    'installment_number': 1,
                    'amount': first,
                    'due_date': due_date,
                })

            for i in range(1, order.installment_months):
                due_date += relativedelta(months=1)
                self.env['sale.installment.plan'].create({
                    'sale_order_id': order.id,
                    'installment_number': i + 1,
                    'amount': per_month,
                    'due_date': due_date,
                })

            # 🔔 Add follow-up alert
            order._create_activity("Send Installment Invoice", order.installment_start_date)

    # -----------------------------
    # Helpers
    # -----------------------------
    def _create_invoice_for_down_payment(self, amount):
        """Creates an invoice for the specified down payment amount."""
        revenue_account = self.env['account.account'].search([
            ('user_type_id.type', '=', 'income')
        ], limit=1)

        if not revenue_account:
            raise UserError("No income account found to post the down payment invoice.")

        invoice = self.env['account.move'].create({
            'move_type': 'out_invoice',
            'partner_id': self.partner_id.id,
            'invoice_date': fields.Date.today(),
            'invoice_line_ids': [(0, 0, {
                'name': 'Down Payment',
                'quantity': 1,
                'price_unit': amount,
                'account_id': revenue_account.id,
            })]
        })
        invoice.action_post()

    def _create_activity(self, summary, deadline=None):
        """Generic method to schedule a visible activity alert on the sales order."""
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
        return super(SaleOrder, self).create(vals)

    def write(self, vals):
        payment_term = self.env['account.payment.term'].browse(vals.get('payment_term_id'))
        if payment_term:
            name = payment_term.name.lower()
            vals['payment_type'] = 'installment' if any(k in name for k in ['installment', 'monthly', 'payment plan']) else 'cash'
        return super(SaleOrder, self).write(vals)
