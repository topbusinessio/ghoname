from odoo import models, fields

class Partner(models.Model):
    _inherit = 'res.partner'
    
    wallet_id = fields.Char(string="Opay Wallet ID", copy=False)
    wallet_account_number = fields.Char(string="Opay Wallet Number", copy=False)
    wallet_balance = fields.Float(string="Opay Wallet Balance", readonly=True)
    