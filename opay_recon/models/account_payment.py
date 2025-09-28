from odoo import models, fields, api

class AccountPaymentMethod(models.Model):
    _inherit = 'account.payment.method'
    is_opay = fields.Boolean(string='Is OPay')

class AccountPayment(models.Model):
    _inherit = 'account.payment'
    # Add OPay specific fields
    opay_order_no = fields.Char(string='OPay Order No')
    opay_pay_no = fields.Char(string='OPay Pay No')
    opay_merchant_id = fields.Char(string='Merchant ID')
    opay_status = fields.Char(string='OPay Status')
    opay_sender_name = fields.Char(string='Sender Name')
    opay_sender_account = fields.Char(string='Sender Account')
    opay_settlement_amount = fields.Float(string='Settlement Amount')
    opay_transaction_time = fields.Datetime(string='Transaction Time')
    opay_additional_info = fields.Text(string='Additional Information')
