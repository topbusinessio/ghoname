from odoo import models, fields, api

class AccountPayment(models.Model):
    _inherit = 'account.payment'
    # Add OPay specific fields
    opay_order_no = fields.Char(string='OPay Order No')
    opay_notes = fields.Char(string='OPay Pay No')
    opay_merchant_id = fields.Char(string='Merchant ID')
    opay_status = fields.Char(string='OPay Status')
    opay_sender_name = fields.Char(string='Sender Name')
    opay_sender_account = fields.Char(string='Sender Account')
    opay_transaction_time = fields.Datetime(string='Transaction Time')
