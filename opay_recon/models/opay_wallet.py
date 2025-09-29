# -*- coding: utf-8 -*-
import logging
import random
import string
import requests
import json
import time
import base64
from odoo import models, fields, api
from odoo.exceptions import UserError

# --- Opay RSA-related imports ---
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from . import helpers

_logger = logging.getLogger(__name__)

class OpayWallet(models.Model):
    _name = 'opay.wallet'
    _description = 'Opay Wallet'

    name = fields.Char(string='Account Name', required=True)
    reference = fields.Char(string='Reference', readonly=True, copy=False)
    partner_id = fields.Many2one('res.partner', string='Customer', required=True, ondelete='cascade')
    account_number = fields.Char(string='Deposit Code', readonly=True)
    balance = fields.Float(string='Balance', default=0.0, readonly=True)
    currency_id = fields.Many2one('res.currency', string='Currency', required=True,
                                  default=lambda self: self.env.company.currency_id)
    payments = fields.One2many('account.payment', 'opay_wallet_id', string='Payments')
    last_query = fields.Datetime(string='Last Balance Query', readonly=True)

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
        except Exception as e:
            _logger.error(f"Failed to fetch Opay wallet balance: {e}")
            raise UserError(f"Failed to fetch Opay wallet balance: {e}")