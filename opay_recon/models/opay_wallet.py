# -*- coding: utf-8 -*-
import logging

from odoo import _, models, fields, api
from odoo.exceptions import UserError


from . import helpers

_logger = logging.getLogger(__name__)

class OpayWallet(models.Model):
    _name = 'opay.wallet'
    _description = 'Opay Wallet'

    name = fields.Char(required=True, readonly=True,)
    reference = fields.Char(readonly=True, copy=False)
    partner_id = fields.Many2one('res.partner', string='Customer', required=True, ondelete='cascade', readonly=True)
    account_number = fields.Char(readonly=True)
    balance = fields.Float(readonly=True)
    currency_id = fields.Many2one('res.currency', string='Currency', required=True,
                                  default=lambda self: self.env.company.currency_id, readonly=True)
    payments = fields.One2many('account.payment', 'opay_wallet_id')
    payment_count = fields.Integer(compute='_compute_payment_count')
    last_query = fields.Datetime(string='Last Balance Query', readonly=True)

    @api.depends('payments')
    def _compute_payment_count(self):
        for wallet in self:
            wallet.payment_count = self.env['account.payment'].sudo().search_count([('opay_wallet_id', '=', wallet.id)])

    def get_balance(self):
        self.ensure_one()
        o_client_auth_key = self.env['ir.config_parameter'].sudo().get_param('opay.client_auth_key', default=False)
        o_merchant_private_key = self.env['ir.config_parameter'].sudo().get_param('opay.merchant_private_key', default=False)
        o_public_key = self.env['ir.config_parameter'].sudo().get_param('opay.opay_public_key', default=False)
        o_merchant_id = self.env['ir.config_parameter'].sudo().get_param('opay.opay_merchant_id', default=False)
        
        if not all([o_client_auth_key, o_merchant_private_key, o_public_key, o_merchant_id]):
            raise UserError("Opay configuration is incomplete. Please check the settings.")

        try:
            balance_info = helpers.query_wallet_balance(
                self.account_number,
                o_client_auth_key,
                o_merchant_id,
                o_public_key,
                o_merchant_private_key
            )
            self.write({
                'balance': balance_info.get('amount', 0.0),
                'last_query': balance_info.get('timestamp', fields.Datetime.now())
            })
            return True
        except Exception as e:
            self.env['bus.bus']._sendone(self.env.user.partner_id, 'simple_notification', {
                'type': 'danger',
                'title': _("Warning"),
                'message': _(f"Failed to fetch Opay wallet balance: {e}")
            })
            return False

    def action_payments(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': 'Payments',
            'view_mode': 'tree',
            'res_model': 'account.payment',
            'domain': [('opay_wallet_id', '=', self.id)],
            # 'context': "{'create': False}"
        }