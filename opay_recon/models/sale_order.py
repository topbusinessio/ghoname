from odoo import models, fields

class SaleOrder(models.Model):
    _inherit = 'sale.order'

    partner_wallet_account_number = fields.Char(
        string="Opay Wallet Number",
        related="partner_id.wallet_account_number",
        store=False,
        readonly=True
    )
    partner_wallet_balance = fields.Float(
        string="Opay Wallet Balance",
        related="partner_id.wallet_balance",
        store=False,
        readonly=True
    )
