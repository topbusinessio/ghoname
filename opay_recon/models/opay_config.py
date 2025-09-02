# -*- coding: utf-8 -*-
from odoo import models, fields, api
from odoo.exceptions import UserError
import logging
import hashlib
import hmac
import json
import time
import requests
import random
import string

_logger = logging.getLogger(__name__)


def generate_ref_id(length=15):
    """Generate a 15-character alphanumeric Ref ID for OPay."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


class OpayConfig(models.Model):
    _name = 'opay.config'
    _description = 'Opay Configuration'

    account_prefix = fields.Char(string='Account Prefix', default='OPAY')
    opay_api_key = fields.Char(string='Opay API Key')
    opay_secret_key = fields.Char(string='Opay Secret Key')
    merchant_id = fields.Char(string='Opay Merchant ID')
    test_mode = fields.Boolean(string='Test Mode', default=True)

    # -------------------------------
    # Store + Retrieve Config
    # -------------------------------
    def set_values(self):
        """Save Opay configuration to ir.config_parameter"""
        params = self.env['ir.config_parameter'].sudo()
        params.set_param('opay_wallet.account_prefix', self.account_prefix or 'OPAY')
        params.set_param('opay_wallet.opay_api_key', self.opay_api_key or '')
        params.set_param('opay_wallet.opay_secret_key', self.opay_secret_key or '')
        params.set_param('opay_wallet.opay_merchant_id', self.merchant_id or '')
        params.set_param('opay_wallet.is_test_mode', self.test_mode)
        _logger.info("✅ Opay configuration saved. Test mode: %s", self.test_mode)

    @api.model
    def get_config_value(self, key):
        """Retrieve configuration values from ir.config_parameter"""
        try:
            value = self.env['ir.config_parameter'].sudo().get_param(key, default='')
            if not value:
                _logger.warning("⚠️ Config value for %s is not set.", key)
            return value
        except Exception as e:
            _logger.error("❌ Error retrieving configuration for key %s: %s", key, str(e))
            raise UserError(f"Error retrieving configuration for key {key}: {str(e)}")

    @api.model
    def is_test_mode(self):
        return self.get_config_value('opay_wallet.is_test_mode') == 'True'

    @api.model
    def get_merchant_credentials(self):
        """Retrieve merchant credentials and validate in live mode"""
        creds = {
            'merchant_id': self.get_config_value('opay_wallet.opay_merchant_id'),
            'api_key': self.get_config_value('opay_wallet.opay_api_key'),
            'secret_key': self.get_config_value('opay_wallet.opay_secret_key')
        }

        if not self.is_test_mode():
            missing = [k for k, v in creds.items() if not v]
            if missing:
                msg = f"❌ Missing merchant credentials: {', '.join(missing)}"
                _logger.error(msg)
                raise UserError(msg)

        return creds

    # -------------------------------
    # ✅ FIXED: Correct API Signing for OPay
    # -------------------------------
    @api.model
    def generate_signature(self, param_content: str, api_key: str, secret_key: str, timestamp: str) -> str:
        """
        ✅ FIXED: Generate HMAC-SHA512 signature for OPay API requests
        Correct format: HMAC-SHA512(paramContent + apiKey + timestamp, secret_key)
        """
        try:
            # ✅ Correct signature string format
            raw_string = f"{param_content}{api_key}{timestamp}"
            
            # ✅ Use HMAC-SHA512 (not plain SHA256)
            signature = hmac.new(
                secret_key.encode(),
                raw_string.encode(),
                hashlib.sha512
            ).hexdigest()
            
            _logger.debug("Generated HMAC-SHA512 signature for: %s...%s...%s", 
                         param_content[:50], api_key[:10], timestamp)
            return signature
        except Exception as e:
            msg = f"❌ Error generating signature: {str(e)}"
            _logger.error(msg)
            raise UserError(msg)

    @api.model
    def build_headers(self, api_key: str) -> dict:
        """✅ FIXED: Return correct OPay headers - clientAuthKey must be in headers"""
        return {
            "Content-Type": "application/json",
            "clientAuthKey": api_key,  # ✅ This is the critical fix
        }

    @api.model
    def build_payload(self, param_content: str, signature: str, timestamp: str) -> dict:
        """✅ Build the correct payload structure for OPay"""
        return {
            "version": "V1.0.1",
            "bodyFormat": "JSON",
            "timestamp": timestamp,
            "signType": "SHA512",  # ✅ Must match the hash algorithm
            "sign": signature,
            "paramContent": param_content
        }

    # -------------------------------
    # ✅ FIXED: Live Credential Validation
    # -------------------------------
    @api.model
    def validate_live_credentials(self):
        """Validate credentials against Opay API in live mode"""
        if self.is_test_mode():
            _logger.info("Test mode enabled, skipping live credential validation.")
            return

        creds = self.get_merchant_credentials()
        timestamp = str(int(time.time() * 1000))

        # ✅ FIXED: Use correct payload structure for deposit code generation
        biz_payload = {
            "opayMerchantId": creds['merchant_id'],  # ✅ Correct field name
            "refId": generate_ref_id(),              # ✅ Required field
            "name": "Odoo Test Account",
            "phone": "2348012345678",                # ✅ Required field
            "accountType": "Merchant",               # ✅ Required field
            "sendPassWordFlag": "N"                  # ✅ Required field
        }

        # Convert to JSON string
        param_content = json.dumps(biz_payload, separators=(',', ':'), sort_keys=True)
        
        # Generate signature
        signature = self.generate_signature(param_content, creds['api_key'], creds['secret_key'], timestamp)
        
        # Build request components
        headers = self.build_headers(creds['api_key'])
        payload = self.build_payload(param_content, signature, timestamp)

        try:
            _logger.info("🔹 Validating Opay credentials...")
            _logger.info("🔹 Headers: %s", {k: v[:10] + "..." if len(v) > 10 else v for k, v in headers.items()})
            _logger.info("🔹 Payload: %s", json.dumps(payload, indent=2))

            response = requests.post(
                "https://payapi.opayweb.com/api/v2/third/depositcode/generateStaticDepositCode",
                headers=headers,
                json=payload,
                timeout=15
            )
            
            response.raise_for_status()
            result = response.json()
            
            _logger.info("🔹 Opay API Response: %s", json.dumps(result, indent=2))

            if result.get("code") != "00000":
                msg = result.get('message', 'Unknown error')
                error_code = result.get("code", "Unknown")
                payload_pretty = json.dumps(payload, indent=4, sort_keys=True)
                result_pretty = json.dumps(result, indent=4, sort_keys=True)
                raise UserError(
                    f"❌ Opay validation failed: {msg} (code: {error_code})\n\n"
                    f"Payload Sent:\n{payload_pretty}\n\nFull Response:\n{result_pretty}"
                )

            deposit_code = result.get("data", {}).get("depositCode", "N/A")
            _logger.info("✅ Opay credentials validated successfully. Test deposit code: %s", deposit_code)
            return deposit_code

        except requests.exceptions.RequestException as e:
            payload_pretty = json.dumps(payload, indent=4, sort_keys=True)
            msg = f"❌ Connection to Opay API failed: {str(e)}\n\nPayload Sent:\n{payload_pretty}"
            _logger.error(msg)
            raise UserError(msg)
        except Exception as e:
            msg = f"❌ Unexpected error during validation: {str(e)}"
            _logger.error(msg)
            raise UserError(msg)