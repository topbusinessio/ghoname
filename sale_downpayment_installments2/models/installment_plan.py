from odoo import models, fields, api
from datetime import date


class InstallmentPlan(models.Model):
    _name = 'sale.installment.plan'
    _description = 'Installment Payment Plan'
    _order = 'due_date asc'

    # -----------------------------
    # Fields
    # -----------------------------
    sale_order_id = fields.Many2one(
        'sale.order',
        string='Sale Order',
        ondelete='cascade',
        required=True
    )

    installment_number = fields.Integer(string="Installment No.")
    amount = fields.Monetary(string="Installment Amount", required=True)
    due_date = fields.Date(string="Due Date", required=True)

    # 💰 Currency
    currency_id = fields.Many2one(
        related='sale_order_id.currency_id',
        readonly=True,
        store=True
    )

    # 🔒 Locked once generated
    locked = fields.Boolean(string="Locked", default=False, readonly=True)

    # 🧾 Linked Invoice
    invoice_id = fields.Many2one(
        'account.move',
        string="Invoice",
        readonly=True,
        ondelete='set null',
        help="The customer invoice automatically created for this installment."
    )

    # 💵 Dynamic Payment Tracking
    amount_paid = fields.Monetary(
        string="Amount Paid",
        compute="_compute_invoice_payment",
        store=True,
        currency_field="currency_id"
    )

    amount_remaining = fields.Monetary(
        string="Amount Remaining",
        compute="_compute_invoice_payment",
        store=True,
        currency_field="currency_id"
    )

    # 📊 Auto Payment Status (computed)
    payment_status = fields.Selection(
        [
            ('pending', 'Pending'),
            ('paid', 'Paid'),
            ('overdue', 'Overdue')
        ],
        string='Payment Status',
        compute='_compute_payment_status',
        store=True
    )

    # -----------------------------
    # Computations
    # -----------------------------
    @api.depends('invoice_id.payment_state', 'due_date', 'amount_remaining')
    def _compute_payment_status(self):
        """Compute real-time payment status based on invoice + due date."""
        today = date.today()
        for rec in self:
            if not rec.invoice_id:
                rec.payment_status = 'pending'
                continue

            invoice = rec.invoice_id

            if invoice.payment_state == 'paid' or rec.amount_remaining == 0:
                rec.payment_status = 'paid'
            elif rec.due_date and rec.due_date < today and rec.amount_remaining > 0:
                rec.payment_status = 'overdue'
            else:
                rec.payment_status = 'pending'

    @api.depends('invoice_id.amount_total', 'invoice_id.amount_residual', 'invoice_id.payment_state')
    def _compute_invoice_payment(self):
        """Automatically track how much has been paid for this installment."""
        for rec in self:
            if rec.invoice_id:
                invoice = rec.invoice_id
                rec.amount_paid = invoice.amount_total - invoice.amount_residual
                rec.amount_remaining = invoice.amount_residual
            else:
                rec.amount_paid = 0.0
                rec.amount_remaining = rec.amount

    # -----------------------------
    # Behavior
    # -----------------------------
    @api.model_create_multi
    def create(self, vals_list):
        """Automatically lock each installment once created."""
        records = super().create(vals_list)
        for rec in records:
            rec.locked = True
        return records

    def action_open_invoice(self):
        """Convenience action to quickly open the linked invoice."""
        for rec in self:
            if not rec.invoice_id:
                continue
            return {
                'name': 'Installment Invoice',
                'type': 'ir.actions.act_window',
                'view_mode': 'form',
                'res_model': 'account.move',
                'res_id': rec.invoice_id.id,
                'target': 'current',
            }
