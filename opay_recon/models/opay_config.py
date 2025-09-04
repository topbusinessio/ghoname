# -*- coding: utf-8 -*-
import random
import string
import logging
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

_logger = logging.getLogger(__name__)

# --- Opay RSA Utility Functions ---
MAX_DECRYPT_TYPE = 128
MAX_ENCRYPT_BYTE = 117

def _json_dumps(json_data):
    return json.dumps(json_data, sort_keys=True, separators=(',', ':'))

def _encrypt_by_public_key(input_str, public_key):
    rsa_key_bytes = base64.b64decode(public_key)
    key = RSA.import_key(rsa_key_bytes)
    cipher = PKCS1_v1_5.new(key)
    input_bytes = input_str.encode()
    offset = 0
    result_bytes = bytearray()
    while offset < len(input_bytes):
        chunk = input_bytes[offset:offset + MAX_ENCRYPT_BYTE]
        result_bytes.extend(cipher.encrypt(chunk))
        offset += MAX_ENCRYPT_BYTE
    return base64.b64encode(result_bytes).decode()

def _decrypt_by_private_key(text, private_key):
    key_bytes = base64.b64decode(private_key)
    key = RSA.import_key(key_bytes)
    cipher = PKCS1_v1_5.new(key)
    encrypted_data = base64.b64decode(text)
    out = bytearray()
    offset = 0
    while offset < len(encrypted_data):
        chunk = encrypted_data[offset:offset + MAX_DECRYPT_TYPE]
        out.extend(cipher.decrypt(chunk, None))
        offset += MAX_DECRYPT_TYPE
    return out.decode()

def _generate_sign(data, private_key=None, use_rsa=True):
    """
    Generates a signature.
    - If RSA enabled: sign with merchant private key.
    - If disabled: return SHA256 hexdigest (Opay hash mode).
    """
    if use_rsa:
        if not private_key:
            raise UserError("RSA signing requires a merchant private key.")
        key_bytes = base64.b64decode(private_key)
        rsa_key = RSA.import_key(key_bytes)
        signer = pkcs1_15.new(rsa_key)
        digest = SHA256.new(data.encode("utf-8"))
        signature = signer.sign(digest)
        return base64.b64encode(signature).decode("utf-8")
    else:
        return SHA256.new(data.encode("utf-8")).hexdigest()

def _verify_signature(data, signature, public_key):
    try:
        key_bytes = base64.b64decode(public_key)
        rsa_key = RSA.import_key(key_bytes)
        verifier = pkcs1_15.new(rsa_key)
        verifier.verify(SHA256.new(data.encode("utf-8")), base64.b64decode(signature))
        return True
    except Exception:
        return False

def _signature_content(response_content):
    res_data = {
        'code': response_content.get('code'),
        'message': response_content.get('message'),
        'data': response_content.get('data'),
        'timestamp': response_content.get('timestamp'),
    }
    parts = []
    for k in sorted(res_data.keys()):
        v = res_data[k]
        if k and v is not None and k != "sign":
            parts.append(f"{k}={v}")
    return "&".join(parts)

def _analytic_response(response_content, merchant_private_key, opay_public_key):
    if response_content.get('code') != '00000':
        raise UserError(f"Opay API error {response_content.get('code')}: {response_content.get('message')}")
    enc_text = response_content.get('data')
    if not enc_text:
        raise UserError("Opay API response data is missing.")
    # Verify signature
    sign_content = _signature_content(response_content)
    if not _verify_signature(sign_content, response_content.get('sign'), opay_public_key):
        raise UserError("Opay API signature verification failed.")
    # Decrypt and parse
    decrypted_text = _decrypt_by_private_key(enc_text, merchant_private_key)
    try:
        return json.loads(decrypted_text)
    except Exception:
        return {"raw": decrypted_text}

def generate_ref_id(length=15):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# --- Res Config Settings ---
class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    opay_client_auth_key = fields.Char(config_parameter='opay.client_auth_key', string="Opay Client Auth Key")
    opay_merchant_private_key = fields.Char(config_parameter='opay.merchant_private_key', string="Merchant Private Key")
    opay_public_key = fields.Char(config_parameter='opay.opay_public_key', string="Opay Public Key")
    opay_merchant_id = fields.Char(config_parameter='opay.opay_merchant_id', string="Opay Merchant ID")
    opay_account_prefix = fields.Char(config_parameter='opay.account_prefix', default='OPAY', string="Account Prefix")
    opay_test_mode = fields.Boolean(config_parameter='opay.is_test_mode', default=True, string="Test Mode")
    opay_use_rsa_signing = fields.Boolean(config_parameter='opay.use_rsa_signing', default=True, string="Use RSA Signing")

    def test_opay_connection(self):
        """Validate credentials by making a test API call."""
        if self.opay_test_mode:
            raise UserError("Cannot test Live credentials while Test Mode is enabled.")

        missing = [f for f in ["Client Auth Key","Merchant Private Key","Opay Public Key","Merchant ID"]
                   if not getattr(self, f"opay_{f.lower().replace(' ', '_')}")]
        if missing:
            raise UserError(f"Missing required fields: {', '.join(missing)}")

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
            param_content = _encrypt_by_public_key(_json_dumps(biz_payload), self.opay_public_key)
            signature = _generate_sign(param_content + timestamp, self.opay_merchant_private_key,
                                       use_rsa=self.opay_use_rsa_signing)
            request_body = {"paramContent": param_content, "sign": signature}
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
            decrypted = _analytic_response(response.json(), self.opay_merchant_private_key, self.opay_public_key)
            deposit_code = decrypted.get("depositCode", "N/A")
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': 'Success!',
                    'message': f'✅ Opay credentials validated!\nTest deposit code: {deposit_code}',
                    'type': 'success',
                    'sticky': False,
                }
            }
        except requests.exceptions.RequestException as e:
            raise UserError(f"Connection to Opay failed: {str(e)}")
        except Exception as e:
            raise UserError(f"Unexpected error: {str(e)}")
