from odoo import models, fields, api
from odoo.tools import date_utils
from datetime import date


class InstallmentPlan(models.Model):
    _name = 'sale.installment.plan'
    _description = 'Installment Payment Plan'
    _order = 'due_date asc'

    sale_order_id = fields.Many2one(
        'sale.order', string='Sale Order', ondelete='cascade', required=True
    )
    installment_number = fields.Integer(string="Installment No.")
    amount = fields.Monetary(string="Installment Amount", required=True)
    due_date = fields.Date(string="Due Date", required=True)
    paid = fields.Boolean(string="Paid", default=False)
    currency_id = fields.Many2one(
        related='sale_order_id.currency_id', readonly=True, store=True
    )

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

    @api.depends('paid', 'due_date')
    def _compute_payment_status(self):
        today = date.today()
        for record in self:
            if record.paid:
                record.payment_status = 'paid'
            elif record.due_date and record.due_date < today:
                record.payment_status = 'overdue'
            else:
                record.payment_status = 'due'
