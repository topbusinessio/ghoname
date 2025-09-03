# -*- coding: utf-8 -*-
import logging
import random
import string
import requests
import hashlib
import hmac
import json
import time
from odoo import models, fields, api
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)

# --- Opay Configuration ---
class OpayConfig(models.Model):
    _name = 'opay.config'
    _description = 'Opay Configuration'

    opay_api_key = fields.Char(string='Opay API Key', required=True)
    opay_secret_key = fields.Char(string='Opay Secret Key', required=True)
    opay_merchant_id = fields.Char(string='Opay Merchant ID', required=True)
    account_prefix = fields.Char(string='Account Prefix', default='OPAY',
                                 help="Prefix for generated virtual accounts.")
    is_test_mode = fields.Boolean(string='Test Mode', default=False)

# --- Opay Wallet ---
class OpayWallet(models.Model):
    _name = 'opay.wallet'
    _description = 'Opay Wallet'

    name = fields.Char(string='Account Name', required=True)
    partner_id = fields.Many2one('res.partner', string='Customer', required=True, ondelete='cascade')
    account_number = fields.Char(string='Deposit Code', readonly=True)
    balance = fields.Float(string='Balance', default=0.0, readonly=True)
    currency_id = fields.Many2one('res.currency', string='Currency', required=True,
                                  default=lambda self: self.env.company.currency_id)
    state = fields.Selection([
        ('draft', 'Draft'),
        ('active', 'Active'),
        ('suspended', 'Suspended'),
    ], default='draft', string='State')

    @api.model
    def _create_virtual_account(self, customer):
        _logger.info("Creating Opay deposit account for customer: %s", customer.name)

        params = self.env['ir.config_parameter'].sudo()
        account_prefix = params.get_param('opay_wallet.account_prefix', default='OPAY')
        client_auth_key = params.get_param('opay_wallet.opay_api_key', default='')
        secret_key = params.get_param('opay_wallet.opay_secret_key', default='')
        merchant_id = params.get_param('opay_wallet.opay_merchant_id', default='')
        test_mode = params.get_param('opay_wallet.is_test_mode') == 'True'

        if test_mode:
            random_number = str(random.randint(1000000000, 9999999999))
            generated_account = f"{account_prefix}{random_number}"
            _logger.info("Test mode: generated dummy account %s", generated_account)
            return generated_account

        missing = []
        if not client_auth_key: missing.append("API Key")
        if not secret_key: missing.append("Secret Key")
        if not merchant_id: missing.append("Merchant ID")
        if not customer.name: missing.append("Customer Name")
        if missing:
            raise UserError(f"Missing required parameter(s): {', '.join(missing)}")

        phone = ""
        if customer.phone:
            phone = customer.phone.replace(" ", "").replace("+", "")
            if phone.startswith("0"):
                phone = "234" + phone[1:]
            if not phone.isdigit():
                raise UserError(f"Invalid phone number format for {customer.name}: {customer.phone}")

        ref_id = ''.join(random.choices(string.ascii_letters + string.digits, k=15))

        biz_payload = {
            "opayMerchantId": merchant_id,
            "refId": ref_id,
            "name": customer.name,
            "accountType": "Merchant",
            "sendPassWordFlag": "N"
        }
        if phone:
            biz_payload["phone"] = phone
        if customer.email:
            biz_payload["email"] = customer.email

        # --- Prepare paramContent ---
        param_content = json.dumps(biz_payload, separators=(',', ':'), sort_keys=True)

        # --- ✅ FIXED: Correct HMAC-SHA512 signing with proper order ---
        timestamp = str(int(time.time() * 1000))
        sign_string = param_content + client_auth_key + timestamp  # ✅ Corrected order
        signature = hmac.new(secret_key.encode(), sign_string.encode(), hashlib.sha512).hexdigest()

        # ✅ FIXED: Remove clientAuthKey from payload body
        payload = {
            "version": "V1.0.1",
            "bodyFormat": "JSON",
            "timestamp": timestamp,
            "signType": "SHA512",
            "sign": signature,
            "paramContent": param_content
        }

        # ✅ FIXED: Add clientAuthKey to headers instead
        headers = {
            "Content-Type": "application/json",
            "clientAuthKey": client_auth_key  # This should be in headers, not body
        }
        
        api_url = "https://payapi.opayweb.com/api/v2/third/depositcode/generateStaticDepositCode"

        try:
            _logger.info("🔹 Opay Headers: %s", {k: v[:10] + "..." if len(v) > 10 else v for k, v in headers.items()})
            _logger.info("🔹 Opay Payload: %s", json.dumps(payload, indent=4))
            _logger.info("🔹 Sign String: %s", f"{param_content[:50]}...{client_auth_key[:10]}...{timestamp}")
            
            response = requests.post(api_url, json=payload, headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json()

            _logger.info("🔹 Opay API Response: %s", json.dumps(data, indent=2))

            if data.get("code") == "00000" and data.get("data", {}).get("depositCode"):
                account_number = data["data"]["depositCode"]
                _logger.info("✅ Opay deposit account successfully created: %s", account_number)
                return account_number
            else:
                error_msg = data.get("message", "Unknown error")
                error_code = data.get("code", "Unknown")
                _logger.error("❌ Opay API error: %s (code: %s)", error_msg, error_code)
                raise UserError(f"❌ Opay API error: {error_msg} (code: {error_code})")

        except requests.exceptions.RequestException as e:
            _logger.error("❌ Connection error: %s", str(e))
            raise UserError(f"❌ Connection to Opay API failed: {str(e)}")
        except Exception as e:
            _logger.error("❌ Unexpected error: %s", str(e))
            raise UserError(f"❌ Unexpected error occurred: {str(e)}")

    @api.model
    def create(self, vals):
        _logger.info("Creating wallet with vals: %s", vals)
        wallet = super(OpayWallet, self).create(vals)
        if wallet.partner_id:
            try:
                account_number = wallet._create_virtual_account(wallet.partner_id)
                wallet.write({'account_number': account_number, 'state': 'active'})
                _logger.info("Wallet updated with deposit account: %s", account_number)
            except UserError as e:
                wallet.write({'state': 'draft'})
                _logger.warning("Failed to create wallet for %s: %s", wallet.partner_id.name, str(e))
                raise UserError(f"Wallet creation failed for {wallet.partner_id.name}.\n{str(e)}")
        return wallet

# --- Opay Payment ---
class OpayPayment(models.Model):
    _name = 'opay.payment'
    _description = 'Opay Payment'

    name = fields.Char(string='Payment Reference', required=True)
    transaction_id = fields.Char(string='Transaction ID', readonly=True)
    amount = fields.Float(string='Amount', readonly=True)
    status = fields.Char(string='Status', readonly=True)
    sale_order_id = fields.Many2one('sale.order', string='Sale Order', readonly=True)
    payment_date = fields.Datetime(string='Payment Date', readonly=True, default=fields.Datetime.now)

    @api.model
    def create(self, vals):
        payment = super(OpayPayment, self).create(vals)
        if payment.sale_order_id and payment.status == 'SUCCESS':
            payment.sale_order_id.write({'state': 'paid'})
            _logger.info("Sale Order %s marked as paid", payment.sale_order_id.name)
        return payment

# --- Extend res.partner ---
class ResPartner(models.Model):
    _inherit = 'res.partner'

    wallet_id = fields.Many2one('opay.wallet', string="Opay Wallet", ondelete="restrict")
    wallet_account_number = fields.Char(related='wallet_id.account_number', string="Wallet Deposit Code", readonly=True)
    wallet_balance = fields.Float(related='wallet_id.balance', string="Wallet Balance", readonly=True)

    def _sanitize_phone_for_opay(self, phone):
        if not phone:
            return ""
        phone = phone.replace(" ", "").replace("+", "")
        if phone.startswith("0"):
            phone = "234" + phone[1:]
        return ''.join(filter(str.isdigit, phone))

    @api.model
    def create(self, vals):
        if vals.get("phone"):
            vals["phone"] = self._sanitize_phone_for_opay(vals["phone"])

        partner = super(ResPartner, self).create(vals)

        if vals.get("customer_rank", 0) > 0 and not partner.wallet_id:
            _logger.info("Creating Opay wallet for new customer: %s", partner.name)
            wallet_vals = {
                'name': partner.name,
                'partner_id': partner.id,
                'currency_id': self.env.company.currency_id.id,
            }
            try:
                wallet = self.env['opay.wallet'].create(wallet_vals)
                partner.wallet_id = wallet.id
                _logger.info("Opay wallet created with deposit code: %s", wallet.account_number)
            except UserError as e:
                _logger.warning("Failed to create wallet for customer %s: %s", partner.name, str(e))
                raise UserError(f"Failed to create Opay wallet for {partner.name}.\n{str(e)}")

        return partner

    def write(self, vals):
        if vals.get("phone"):
            vals["phone"] = self._sanitize_phone_for_opay(vals["phone"])
        return super(ResPartner, self).write(vals)