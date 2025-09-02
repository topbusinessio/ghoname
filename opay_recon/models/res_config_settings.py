# -*- coding: utf-8 -*-
import random
import string
from odoo import models, fields, api
from odoo.exceptions import UserError
import logging
import requests
import json
import hmac
import hashlib
import time

_logger = logging.getLogger(__name__)


def generate_ref_id(length=15):
    """Generate a 15-character alphanumeric Ref ID for OPay."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    opay_account_prefix = fields.Char(
        string="Account Prefix",
        config_parameter='opay_wallet.account_prefix',
        default='OPAY',
        help="The prefix to use for generating Opay wallet account numbers."
    )

    opay_api_key = fields.Char(
        string="Opay API Key",
        config_parameter='opay_wallet.opay_api_key',
        help="Enter the API key provided by Opay for authentication."
    )

    opay_secret_key = fields.Char(
        string="Opay Secret Key",
        config_parameter='opay_wallet.opay_secret_key',
        help="Enter the secret key provided by Opay for secure transactions."
    )

    opay_merchant_id = fields.Char(
        string="Opay Merchant ID",
        config_parameter='opay_wallet.opay_merchant_id',
        help="Merchant ID provided by Opay for live transactions."
    )

    opay_test_mode = fields.Boolean(
        string="Test Mode",
        config_parameter='opay_wallet.is_test_mode',
        default=True,
        help="Enable Test Mode to generate dummy Opay accounts instead of calling the live API."
    )

    @api.model
    def get_values(self):
        res = super(ResConfigSettings, self).get_values()
        params = self.env['ir.config_parameter'].sudo()
        res.update(
            opay_account_prefix=params.get_param('opay_wallet.account_prefix', 'OPAY'),
            opay_api_key=params.get_param('opay_wallet.opay_api_key', ''),
            opay_secret_key=params.get_param('opay_wallet.opay_secret_key', ''),
            opay_merchant_id=params.get_param('opay_wallet.opay_merchant_id', ''),
            opay_test_mode=params.get_param('opay_wallet.is_test_mode', 'True') == 'True',
        )
        return res

    def set_values(self):
        super(ResConfigSettings, self).set_values()

        try:
            params = self.env['ir.config_parameter'].sudo()
            params.set_param('opay_wallet.account_prefix', self.opay_account_prefix or 'OPAY')
            params.set_param('opay_wallet.opay_api_key', self.opay_api_key or '')
            params.set_param('opay_wallet.opay_secret_key', self.opay_secret_key or '')
            params.set_param('opay_wallet.opay_merchant_id', self.opay_merchant_id or '')
            params.set_param('opay_wallet.is_test_mode', self.opay_test_mode)
            _logger.info("✅ Opay configuration updated successfully. Test mode: %s", self.opay_test_mode)
        except Exception as e:
            _logger.error("❌ Error saving Opay configuration: %s", str(e))
            raise UserError(f"Failed to save Opay configuration: {str(e)}")

    @api.model
    def validate_live_credentials(self):
        """Validate live API credentials without saving."""
        if self.opay_test_mode:
            raise UserError("Cannot validate Live credentials in Test Mode.")

        missing = []
        if not self.opay_api_key:
            missing.append("API Key")
        if not self.opay_secret_key:
            missing.append("Secret Key")
        if not self.opay_merchant_id:
            missing.append("Merchant ID")
        if missing:
            raise UserError(f"Missing required fields for Live Mode: {', '.join(missing)}")

        timestamp = str(int(time.time() * 1000))
        ref_id = generate_ref_id()
        biz_payload = {
            "opayMerchantId": self.opay_merchant_id,
            "refId": ref_id,
            "name": self.env.user.partner_id.name or "Odoo User",
            "phone": self.env.user.phone or "2348012345678",
            "accountType": "Merchant",
            "sendPassWordFlag": "N"
        }

        # Inner payload
        param_content = json.dumps(biz_payload, separators=(',', ':'), sort_keys=True)

        # ✅ Generate HMAC-SHA512 signature (correct for Opay)
        sign_string = param_content + self.opay_api_key + timestamp
        signature = hmac.new(
            self.opay_secret_key.encode(),
            sign_string.encode(),
            hashlib.sha512  # ✅ Use SHA512 as per Opay documentation
        ).hexdigest()

        # ✅ Fixed: Remove clientAuthKey from payload body
        payload = {
            "version": "V1.0.1",
            "bodyFormat": "JSON",
            "timestamp": timestamp,
            "signType": "SHA512",  # ✅ Must match the hash algorithm
            "sign": signature,
            "paramContent": param_content,
        }

        # ✅ Fixed: Add clientAuthKey to headers
        headers = {
            "Content-Type": "application/json",
            "clientAuthKey": self.opay_api_key  # ✅ Must be in headers, not body
        }

        try:
            _logger.info("🔹 Validating Opay credentials...")
            _logger.info("🔹 Headers: %s", {k: v[:10] + "..." if len(v) > 10 else v for k, v in headers.items()})
            _logger.info("🔹 Payload: %s", json.dumps(payload, indent=2))
            
            resp = requests.post(
                "https://payapi.opayweb.com/api/v2/third/depositcode/generateStaticDepositCode",
                headers=headers,
                json=payload,
                timeout=15
            )
            resp.raise_for_status()
            result = resp.json()

            _logger.info("🔹 Opay API Response: %s", json.dumps(result, indent=2))

            if result.get("code") != "00000":
                msg = result.get('message', 'Unknown error')
                payload_pretty = json.dumps(payload, indent=4, sort_keys=True)
                result_pretty = json.dumps(result, indent=4, sort_keys=True)
                raise UserError(
                    f"❌ Opay validation failed: {msg}\n\nPayload Sent:\n{payload_pretty}\n\nFull Response:\n{result_pretty}"
                )

            deposit_code = result.get("data", {}).get("depositCode", "N/A")
            _logger.info("✅ Live credentials validated successfully. Deposit code: %s", deposit_code)
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': 'Success!',
                    'message': f'✅ Opay credentials validated successfully!\nTest deposit code: {deposit_code}',
                    'type': 'success',
                    'sticky': False,
                }
            }

        except requests.exceptions.RequestException as e:
            payload_pretty = json.dumps(payload, indent=4, sort_keys=True)
            _logger.error("❌ Connection error: %s\nPayload: %s", str(e), payload_pretty)
            raise UserError(f"❌ Connection to Opay API failed: {str(e)}\n\nPayload Sent:\n{payload_pretty}")

    def test_opay_connection(self):
        """Test button to validate credentials"""
        return self.validate_live_credentials()