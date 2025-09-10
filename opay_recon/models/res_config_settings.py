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

_logger = logging.getLogger(__name__)

# --- Opay RSA-related Helpers ---

def _json_dumps(json_data):
    """Dumps a dictionary to a sorted JSON string (stable for signing)."""
    return json.dumps(json_data, sort_keys=True, separators=(',', ':'))

def _import_rsa_key(key_str, key_type="private"):
    """
    Import RSA key from PEM or Base64 body.
    """
    if not key_str:
        raise UserError(f"Provided RSA {key_type} key is empty or invalid.")
    try:
        key_str = key_str.strip()

        # If PEM format, import directly
        if "BEGIN" in key_str:
            return RSA.import_key(key_str.encode())

        # Else assume Base64 body
        key_bytes = base64.b64decode(key_str)
        return RSA.import_key(key_bytes)

    except Exception as e:
        _logger.error("Failed to import RSA %s key. Details: %s", key_type, e)
        raise UserError(f"Invalid RSA {key_type} key format. Please provide PEM or Base64 key.")

def _get_rsa_chunk_sizes(rsa_key):
    key_bytes = rsa_key.size_in_bits() // 8
    max_decrypt = key_bytes
    max_encrypt = key_bytes - 11  # PKCS1 v1.5 padding overhead
    return max_encrypt, max_decrypt

# --- RSA encryption / decryption ---

def _encrypt_by_public_key(input_str, public_key):
    rsa_key = _import_rsa_key(public_key, key_type="public")
    cipher = PKCS1_v1_5.new(rsa_key)
    max_encrypt, _ = _get_rsa_chunk_sizes(rsa_key)

    input_bytes = input_str.encode()
    offset = 0
    result_bytes = bytearray()
    while offset < len(input_bytes):
        chunk = input_bytes[offset:offset + max_encrypt]
        result_bytes.extend(cipher.encrypt(chunk))
        offset += max_encrypt
    return base64.b64encode(result_bytes).decode()

def _decrypt_by_private_key(text, private_key):
    key = _import_rsa_key(private_key, key_type="private")
    cipher = PKCS1_v1_5.new(key)
    try:
        encrypted_data = base64.b64decode(text)
    except Exception as e:
        _logger.error("Decryption failed: input is not a valid base64 string. Details: %s", e)
        raise UserError(f"Encrypted response is not valid Base64: {e}")

    _, max_decrypt = _get_rsa_chunk_sizes(key)
    offset = 0
    out = bytearray()
    while offset < len(encrypted_data):
        chunk = encrypted_data[offset:offset + max_decrypt]
        decrypted = cipher.decrypt(chunk, None)
        if decrypted is None:
            _logger.error("RSA decryption failed – invalid block or key mismatch.")
            raise UserError("RSA decryption failed – invalid block or key mismatch.")
        out.extend(decrypted)
        offset += max_decrypt
    return out.decode()

# --- Signing / verification ---

def _generate_sign(data, private_key):
    if not private_key:
        _logger.error("RSA signing requested but no private key provided.")
        raise UserError("RSA signing requested but no private key provided.")
    
    key = _import_rsa_key(private_key, key_type="private")
    signer = pkcs1_15.new(key)
    digest = SHA256.new(data.encode("utf-8"))
    signature = signer.sign(digest)
    return base64.b64encode(signature).decode("utf-8")

def _verify_rsa_response_sign(resp, opay_public_key):
    """
    Verify Opay API response signature.
    Tries both signing rules:
      1. code + message + timestamp
      2. code + message + data + timestamp
    """
    sign = resp.get("sign")
    if not sign:
        _logger.warning("Opay API response missing signature. Skipping verification.")
        return True

    try:
        opay_key = _import_rsa_key(opay_public_key, key_type="public")
        verifier = pkcs1_15.new(opay_key)
        signature = base64.b64decode(sign)

        # --- Rule 1 ---
        string1 = f"code={resp.get('code')}&message={resp.get('message')}&timestamp={resp.get('timestamp')}"
        digest1 = SHA256.new(string1.encode("utf-8"))
        try:
            verifier.verify(digest1, signature)
            _logger.info("✅ Verified Opay response signature using rule 1 (no data). String: %s", string1)
            return True
        except Exception:
            _logger.info("❌ Rule 1 verification failed. Tried string: %s", string1)

        # --- Rule 2 ---
        string2 = f"code={resp.get('code')}&message={resp.get('message')}&data={resp.get('data')}&timestamp={resp.get('timestamp')}"
        digest2 = SHA256.new(string2.encode("utf-8"))
        verifier.verify(digest2, signature)
        _logger.info("✅ Verified Opay response signature using rule 2 (with data). String: %s", string2)
        return True

    except Exception as e:
        _logger.error("❌ RSA signature verification failed after both rules. Details: %s", e)
        raise UserError(f"Opay API response signature verification failed. Details: {e}")

# --- Response handler ---
def _analytic_response(response_content, merchant_private_key, opay_public_key):
    code = response_content.get('code')
    if code != '00000':
        error_msg = response_content.get('message', 'Unknown error from Opay.')
        raise UserError(f"Opay API call failed. Code: {code}, Message: {error_msg}")

    _verify_rsa_response_sign(response_content, opay_public_key)

    enc_or_plain = response_content.get('data')
    if enc_or_plain is None:
        return {}

    if isinstance(enc_or_plain, (dict, list)):
        return enc_or_plain

    decrypted_text = _decrypt_by_private_key(enc_or_plain, merchant_private_key)
    _logger.info("Decrypted response data: '%s'", decrypted_text)
    try:
        return json.loads(decrypted_text)
    except Exception as e:
        _logger.error("Decrypted data is not valid JSON. Details: %s", e)
        raise UserError("Opay API response data is not a valid JSON string.")

# --- Generate Ref ID ---
def generate_ref_id(length=15):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# --- Odoo Config ---
class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    opay_client_auth_key = fields.Char(config_parameter='opay.client_auth_key')
    opay_merchant_private_key = fields.Text(config_parameter='opay.merchant_private_key')
    opay_public_key = fields.Text(config_parameter='opay.opay_public_key')
    opay_merchant_id = fields.Char(config_parameter='opay.opay_merchant_id')
    opay_account_prefix = fields.Char(config_parameter='opay.account_prefix', default='OPAY')
    opay_test_mode = fields.Boolean(config_parameter='opay.is_test_mode', default=True)

    def test_opay_connection(self):
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
            param_content = _encrypt_by_public_key(_json_dumps(biz_payload), self.opay_public_key)

            # ✅ Correct signing: paramContent + timestamp
            string_to_sign = param_content + timestamp
            signature = _generate_sign(string_to_sign, self.opay_merchant_private_key)

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

            _logger.info("Attempting Opay API call to %s", api_url)
            _logger.info("Request Headers: %s", json.dumps(headers, indent=2))
            _logger.info("Request Body: %s", json.dumps(request_body, indent=2))
            
            response = requests.post(api_url, json=request_body, headers=headers, timeout=15)
            response.raise_for_status()
            response_json = response.json()

            _logger.info("Raw response from Opay API: %s", json.dumps(response_json, indent=2))

            decrypted_data = _analytic_response(response_json, self.opay_merchant_private_key, self.opay_public_key)

            deposit_code = decrypted_data.get("depositCode", "N/A")
            _logger.info("✅ Opay validated. Deposit code: %s", deposit_code)

            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': 'Success!',
                    'message': f'✅ Opay credentials validated successfully! Deposit code: {deposit_code}',
                    'type': 'success',
                    'sticky': False,
                }
            }

        except requests.exceptions.RequestException as e:
            raise UserError(f"❌ Connection to Opay API failed: {str(e)}")
        except Exception as e:
            raise UserError(f"❌ Unexpected error occurred: {str(e)}")
