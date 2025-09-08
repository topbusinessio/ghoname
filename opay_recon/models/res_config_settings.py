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
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

_logger = logging.getLogger(__name__)

# --- Helpers ---
def _json_dumps(json_data):
    return json.dumps(json_data, sort_keys=True, separators=(",", ":"))


def _import_rsa_key(key_str):
    """
    Import RSA key from PEM or base64 string.
    """
    if not key_str:
        raise UserError("RSA key is empty.")

    ks = key_str.strip()
    if ks.startswith("-----BEGIN"):
        return RSA.import_key(ks.encode())

    try:
        body = "".join(ks.split())
        der = base64.b64decode(body)
        return RSA.import_key(der)
    except Exception as e:
        raise UserError(f"Invalid RSA key format: {e}")


def _get_rsa_chunk_sizes(rsa_key):
    """
    Get max chunk sizes for encryption/decryption based on key size.
    """
    key_bytes = rsa_key.size_in_bits() // 8
    max_decrypt = key_bytes
    max_encrypt = key_bytes - 11  # PKCS1 v1.5 padding overhead
    return max_encrypt, max_decrypt


# --- RSA encryption/decryption ---
def _encrypt_by_public_key(input_str, public_key):
    rsa_key = _import_rsa_key(public_key)
    cipher = PKCS1_v1_5.new(rsa_key)
    max_encrypt, _ = _get_rsa_chunk_sizes(rsa_key)

    input_bytes = input_str.encode()
    input_length = len(input_bytes)
    offset = 0
    result_bytes = bytearray()
    while input_length - offset > 0:
        chunk = input_bytes[offset:offset + max_encrypt]
        cache = cipher.encrypt(chunk)
        result_bytes.extend(cache)
        offset += max_encrypt
    return base64.b64encode(result_bytes).decode()


def _decrypt_by_private_key(text, private_key):
    rsa_key = _import_rsa_key(private_key)
    cipher = PKCS1_v1_5.new(rsa_key)
    _, max_decrypt = _get_rsa_chunk_sizes(rsa_key)

    encrypted_data = base64.b64decode(text)
    input_len = len(encrypted_data)
    out = bytearray()
    offset = 0
    i = 0
    while input_len - offset > 0:
        chunk = encrypted_data[offset:offset + max_decrypt]
        cache = cipher.decrypt(chunk, None)
        out.extend(cache)
        i += 1
        offset = i * max_decrypt
    return out.decode()


# --- RSA Sign/Verify ---
def _generate_rsa_sign(input_string, merchant_private_key):
    rsa_key = _import_rsa_key(merchant_private_key)
    signer = pkcs1_15.new(rsa_key)
    digest = SHA256.new(input_string.encode("utf-8"))
    signature = signer.sign(digest)
    return base64.b64encode(signature).decode("utf-8")


def _verify_rsa_response_sign(resp, opay_public_key):
    """
    Verify the RSA signature of the Opay API response using Opay's public key.
    Correct version: encrypted data + timestamp is the string to verify.
    """
    try:
        sign = resp.get("sign")
        timestamp = resp.get("timestamp")
        data = resp.get("data")  # must be the encrypted string

        if not sign or not timestamp or not data:
            _logger.error("Opay response missing required fields for verification (sign/timestamp/data).")
            return False

        if isinstance(data, (dict, list)):
            _logger.error("Data is already decrypted; signature verification must use encrypted string.")
            return False

        string_to_verify = f"{data}{timestamp}"
        _logger.debug("String to verify: %s", string_to_verify)

        opay_key = _import_rsa_key(opay_public_key)
        verifier = pkcs1_15.new(opay_key)
        digest = SHA256.new(string_to_verify.encode("utf-8"))
        signature = base64.b64decode(sign)

        verifier.verify(digest, signature)
        _logger.info("✅ Opay API response signature verified successfully.")
        return True

    except (ValueError, TypeError) as e:
        _logger.error("❌ RSA signature verification failed: %s", e)
        raise UserError(f"Opay API response signature verification failed. Details: {e}")
    except Exception as e:
        _logger.error("❌ Unexpected error during signature verification: %s", e)
        raise UserError(f"Unexpected error during Opay API response signature verification: {e}")


# --- Response handler ---
def _analytic_response(response_content, merchant_private_key, opay_public_key):
    if response_content.get('code') != '00000':
        raise UserError(f"Opay API call failed. Code: {response_content.get('code')}, Message: {response_content.get('message')}")

    if not _verify_rsa_response_sign(response_content, opay_public_key):
        raise UserError("Opay API response signature verification failed.")

    enc_text = response_content.get('data')
    if not enc_text:
        raise UserError("Opay API response data is missing.")

    return _decrypt_by_private_key(enc_text, merchant_private_key)


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
            signature = _generate_rsa_sign(param_content + timestamp, self.opay_merchant_private_key)

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

            response = requests.post(api_url, json=request_body, headers=headers, timeout=15)
            response.raise_for_status()
            response_json = response.json()

            decrypted_data = _analytic_response(response_json, self.opay_merchant_private_key, self.opay_public_key)
            decrypted_json = json.loads(decrypted_data)

            deposit_code = decrypted_json.get("depositCode", "N/A")
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
