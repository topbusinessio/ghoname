from odoo import models, fields

class SaleOrder(models.Model):
    _inherit = 'sale.order'

    opay_account_number = fields.Char(
        related="partner_id.opay_account_number",
        store=False,
        readonly=True
    )
