# -*- coding: utf-8 -*-
import random
import string
import logging
import requests
import json
import time
import base64
import hashlib
from odoo import models, fields, api
from odoo.exceptions import UserError

# --- Opay RSA-related importss ---
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

_logger = logging.getLogger(__name__)

# --- Opay RSA Utility Functions ---
MAX_DECRYPT_TYPE = 128
MAX_ENCRYPT_BYTE = 117


def _json_dumps(json_data):
    """Dumps a dictionary to a sorted JSON string."""
    return json.dumps(json_data, sort_keys=True, separators=(',', ':'))


def _encrypt_by_public_key(input_str, public_key):
    """Encrypts content with a public key."""
    rsa_key_bytes = base64.b64decode(public_key)
    key = RSA.import_key(rsa_key_bytes)
    cipher = PKCS1_v1_5.new(key)
    input_bytes = input_str.encode()
    input_length = len(input_bytes)
    offset = 0
    result_bytes = bytearray()
    while input_length - offset > 0:
        if input_length - offset > MAX_ENCRYPT_BYTE:
            cache = cipher.encrypt(input_bytes[offset:offset + MAX_ENCRYPT_BYTE])
            offset += MAX_ENCRYPT_BYTE
        else:
            cache = cipher.encrypt(input_bytes[offset:])
            offset = input_length
        result_bytes.extend(cache)
    return base64.b64encode(result_bytes).decode()


def _decrypt_by_private_key(text, private_key):
    """Decrypts ciphertext with a private key."""
    key_bytes = base64.b64decode(private_key)
    key = RSA.import_key(key_bytes)
    cipher = PKCS1_v1_5.new(key)
    encrypted_data = base64.b64decode(text)
    input_len = len(encrypted_data)
    out = bytearray()
    offset = 0
    i = 0
    while input_len - offset > 0:
        if input_len - offset > MAX_DECRYPT_TYPE:
            cache = cipher.decrypt(encrypted_data[offset:offset + MAX_DECRYPT_TYPE], None)
        else:
            cache = cipher.decrypt(encrypted_data[offset:], None)
        out.extend(cache)
        i += 1
        offset = i * MAX_DECRYPT_TYPE
    return out.decode()


def _generate_sign(param_content, timestamp):
    """Generates SHA256 signature = SHA256(paramContent + timestamp)."""
    raw_str = f"{param_content}{timestamp}"
    return hashlib.sha256(raw_str.encode()).hexdigest()


def _verify_response_signature(response_content, opay_public_key):
    """Verifies response signature using OPay’s public key."""
    try:
        sign = response_content.get("sign")
        timestamp = response_content.get("timestamp")
        data = response_content.get("data")
        code = response_content.get("code")
        message = response_content.get("message")

        # OPay expects sign = SHA256(paramContent + timestamp) on their side
        raw_str = f"{data}{timestamp}"
        expected_sign = hashlib.sha256(raw_str.encode()).hexdigest()
        return sign == expected_sign
    except Exception as e:
        _logger.error("Signature verification failed: %s", str(e))
        return False


def _analytic_response(response_content, merchant_private_key, opay_public_key):
    """Analyses Opay's API response, verifies signature, and decrypts the data."""
    if response_content.get('code') != '00000':
        error_msg = response_content.get('message', 'Unknown error from Opay.')
        error_code = response_content.get('code', 'N/A')
        raise UserError(f"Opay API call failed. Code: {error_code}, Message: {error_msg}")

    enc_text = response_content.get('data')
    if not enc_text:
        raise UserError("Opay API response data is missing.")

    if not _verify_response_signature(response_content, opay_public_key):
        raise UserError("Opay API response signature verification failed.")

    # Decrypt response data
    return _decrypt_by_private_key(enc_text, merchant_private_key)


# --- Generate Ref ID ---
def generate_ref_id(length=15):
    """Generate a 15-character alphanumeric Ref ID for OPay."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


# --- Res Config Settings ---
class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    # New fields for RSA authentication
    opay_client_auth_key = fields.Char(
        string="Opay Client Auth Key",
        config_parameter='opay.client_auth_key',
        help="The client authentication key for Opay API."
    )
    opay_merchant_private_key = fields.Char(
        string="Merchant Private Key",
        config_parameter='opay.merchant_private_key',
        help="Your RSA private key, used for decrypting responses."
    )
    opay_public_key = fields.Char(
        string="Opay Public Key",
        config_parameter='opay.opay_public_key',
        help="Opay's RSA public key, used for encrypting requests."
    )
    opay_merchant_id = fields.Char(
        string="Opay Merchant ID",
        config_parameter='opay.opay_merchant_id',
        help="Merchant ID provided by Opay."
    )
    opay_account_prefix = fields.Char(
        string="Account Prefix",
        config_parameter='opay.account_prefix',
        default='OPAY',
        help="The prefix to use for generating Opay wallet account numbers."
    )
    opay_test_mode = fields.Boolean(
        string="Test Mode",
        config_parameter='opay.is_test_mode',
        default=True,
        help="Enable Test Mode to generate dummy Opay accounts."
    )

    @api.model
    def get_values(self):
        res = super().get_values()
        params = self.env['ir.config_parameter'].sudo()
        res.update(
            opay_client_auth_key=params.get_param('opay.client_auth_key', ''),
            opay_merchant_private_key=params.get_param('opay.merchant_private_key', ''),
            opay_public_key=params.get_param('opay.opay_public_key', ''),
            opay_merchant_id=params.get_param('opay.opay_merchant_id', ''),
            opay_account_prefix=params.get_param('opay.account_prefix', 'OPAY'),
            opay_test_mode=params.get_param('opay.is_test_mode', 'True') == 'True',
        )
        return res

    def set_values(self):
        super().set_values()
        params = self.env['ir.config_parameter'].sudo()
        params.set_param('opay.client_auth_key', self.opay_client_auth_key or '')
        params.set_param('opay.merchant_private_key', self.opay_merchant_private_key or '')
        params.set_param('opay.opay_public_key', self.opay_public_key or '')
        params.set_param('opay.opay_merchant_id', self.opay_merchant_id or '')
        params.set_param('opay.account_prefix', self.opay_account_prefix or 'OPAY')
        params.set_param('opay.is_test_mode', self.opay_test_mode)
        _logger.info("✅ Opay configuration updated. Test mode: %s", self.opay_test_mode)

    def test_opay_connection(self):
        """Test button to validate credentials"""
        if self.opay_test_mode:
            raise UserError("Cannot validate Live credentials in Test Mode.")

        missing = []
        if not self.opay_client_auth_key: missing.append("Client Auth Key")
        if not self.opay_merchant_private_key: missing.append("Merchant Private Key")
        if not self.opay_public_key: missing.append("Opay Public Key")
        if not self.opay_merchant_id: missing.append("Merchant ID")
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

        try:
            # Encrypt the request payload using Opay's public key
            param_content = _encrypt_by_public_key(_json_dumps(biz_payload), self.opay_public_key)

            # Generate signature = SHA256(paramContent + timestamp)
            signature = _generate_sign(param_content, timestamp)

            # Build the final request body and headers
            request_body = {
                "paramContent": param_content,
                "sign": signature,
            }

            headers = {
                "clientAuthKey": self.opay_client_auth_key,
                "version": "V1.0.1",
                "bodyFormat": "JSON",
                "timestamp": timestamp,
            }

            api_url = "https://payapi.opayweb.com/api/v2/third/depositcode/generateStaticDepositCode"

            _logger.info("🔹 Validating Opay credentials...")
            response = requests.post(api_url, json=request_body, headers=headers, timeout=15)
            response.raise_for_status()
            response_json = response.json()

            _logger.info("✅ Opay API Response (raw): %s", json.dumps(response_json, indent=2))

            # Verify and decrypt the response
            decrypted_data = _analytic_response(response_json, self.opay_merchant_private_key, self.opay_public_key)
            decrypted_json = json.loads(decrypted_data)

            deposit_code = decrypted_json.get("depositCode", "N/A")
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
            _logger.error("❌ Connection error: %s", str(e))
            raise UserError(f"❌ Connection to Opay API failed: {str(e)}")
        except Exception as e:
            _logger.error("❌ Unexpected error: %s", str(e))
            raise UserError(f"❌ Unexpected error occurred: {str(e)}")
