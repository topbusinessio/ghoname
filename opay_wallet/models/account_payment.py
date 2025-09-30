from odoo import models, fields, api

class AccountPaymentMethod(models.Model):
    _inherit = 'account.payment.method'
    is_opay = fields.Boolean(string='Is OPay')

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
    opay_wallet_id = fields.Many2one('opay.wallet', string='OPay Wallet')
    
    # Run get opay wallet balance when payment is created or updated
    @api.model_create_multi
    def create(self, vals_list):
        payments = super(AccountPayment, self).create(vals_list)
        # Get the balance from the linked OPay wallet if exists
        for payment in payments:
            if payment.opay_wallet_id:
                payment.opay_wallet_id.get_balance()
        return payments
