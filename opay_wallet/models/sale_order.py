from odoo import models, fields

class SaleOrder(models.Model):
    _inherit = 'sale.order'

    opay_wallet_number = fields.Char(
        related="partner_id.wallet_account_number",
        store=False,
        readonly=True
    )
