# -*- coding: utf-8 -*-
from odoo import models, fields


class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    opay_client_auth_key = fields.Char("Auth Key", config_parameter='opay.client_auth_key')
    opay_merchant_private_key = fields.Char("Private Key", config_parameter='opay.merchant_private_key')
    opay_public_key = fields.Char("Public Key", config_parameter='opay.opay_public_key')
    opay_merchant_id = fields.Char("Merchant ID", config_parameter='opay.opay_merchant_id')
    opay_account_prefix = fields.Char("Account Prefix", config_parameter='opay.account_prefix', default='OPAY')
