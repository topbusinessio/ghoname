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
    paid = fields.Boolean(string="Paid", default=False)

    # 💰 Currency
    currency_id = fields.Many2one(
        related='sale_order_id.currency_id',
        readonly=True,
        store=True
    )

    # 🔒 Lock installments once generated
    locked = fields.Boolean(string="Locked", default=False, readonly=True)

    # 🧾 Link to generated invoice
    invoice_id = fields.Many2one(
        'account.move',
        string="Invoice",
        readonly=True,
        ondelete='set null',
        help="The customer invoice automatically created for this installment."
    )

    # 📊 Payment status tracking
    payment_status = fields.Selection(
        [
            ('paid', 'Paid'),
            ('due', 'Due'),
            ('overdue', 'Overdue')
        ],
        string='Status',
        compute='_compute_payment_status',
        store=True
    )

    # -----------------------------
    # Computations
    # -----------------------------
    @api.depends('paid', 'due_date')
    def _compute_payment_status(self):
        """Compute payment status based on due date and paid flag."""
        today = date.today()
        for record in self:
            if record.paid:
                record.payment_status = 'paid'
            elif record.due_date and record.due_date < today:
                record.payment_status = 'overdue'
            else:
                record.payment_status = 'due'

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
