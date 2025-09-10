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

# --- Utilities ---

def _json_dumps(json_data):
    """Dumps a dictionary to a sorted JSON string (stable for signing)."""
    return json.dumps(json_data, sort_keys=True, separators=(',', ':'))

def _import_rsa_key(key_str, key_type="public"):
    """
    Imports an RSA key from a Base64-encoded string.
    This method mirrors the official Opay demo's key handling.
    
    Args:
        key_str (str): The Base64 encoded key string (without PEM headers/footers).
        key_type (str): "public" or "private", for logging.
    
    Returns:
        Crypto.PublicKey.RSA key object.
    
    Raises:
        UserError: If the key is invalid or fails to import.
    """
    if not key_str:
        raise UserError(f"Provided RSA {key_type} key is empty or invalid.")
    try:
        key_bytes = base64.b64decode(key_str)
        return RSA.import_key(key_bytes)
    except Exception as e:
        _logger.error("Failed to import Base64-encoded RSA %s key. Details: %s", key_type, e)
        raise UserError(f"Invalid RSA {key_type} key format. Please provide a Base64-encoded key body.")

# --- RSA encryption / decryption ---

def _encrypt_by_public_key(input_str, public_key):
    """Encrypt content with public key (RSA, auto-detect block size)."""
    key = _import_rsa_key(public_key, key_type="public")
    cipher = PKCS1_v1_5.new(key)
    key_bytes = key.size_in_bytes()
    max_encrypt = key_bytes - 11  # PKCS#1 v1.5 overhead
    input_bytes = input_str.encode()
    offset = 0
    result_bytes = bytearray()
    while offset < len(input_bytes):
        chunk = input_bytes[offset:offset + max_encrypt]
        result_bytes.extend(cipher.encrypt(chunk))
        offset += max_encrypt
    return base64.b64encode(result_bytes).decode()

def _decrypt_by_private_key(text, private_key):
    """Decrypt ciphertext with private key (RSA, auto-detect block size)."""
    key = _import_rsa_key(private_key, key_type="private")
    cipher = PKCS1_v1_5.new(key)
    try:
        encrypted_data = base64.b64decode(text)
    except Exception as e:
        _logger.error("Decryption failed: input is not a valid base64 string. Details: %s", e)
        raise UserError(f"Encrypted response is not valid Base64: {e}")

    key_bytes = key.size_in_bytes()
    offset = 0
    out = bytearray()
    while offset < len(encrypted_data):
        chunk = encrypted_data[offset:offset + key_bytes]
        decrypted = cipher.decrypt(chunk, None)
        if decrypted is None:
            _logger.error("RSA decryption failed – invalid block or key mismatch.")
            raise UserError("RSA decryption failed – invalid block or key mismatch.")
        out.extend(decrypted)
        offset += key_bytes
    return out.decode()

# --- Signing / verification ---

def _generate_sign(data, private_key):
    """Generates signature for requests (RSA)."""
    if not private_key:
        _logger.error("RSA signing requested but no private key provided.")
        raise UserError("RSA signing requested but no private key provided.")
    
    key = _import_rsa_key(private_key, key_type="private")
    signer = pkcs1_15.new(key)
    digest = SHA256.new(data.encode("utf-8"))
    signature = signer.sign(digest)
    return base64.b64encode(signature).decode("utf-8")

def _build_signature_string(response_content):
    """
    Builds the signature content string for verification.
    This logic is taken directly from the Opay demo script.
    """
    res_data = {
        'code': response_content.get('code'),
        'message': response_content.get('message'),
        'data': response_content.get('data'),
        'timestamp': response_content.get('timestamp'),
    }

    # The demo code sorts keys alphabetically for the string concatenation.
    sorted_params = dict(sorted(res_data.items()))
    content = []
    
    for key in sorted_params:
        value = sorted_params[key]
        if key is None or key == "" or key == "sign" or value is None:
            continue
        content.append(f"{key}={value}")
    
    return "&".join(content)

def _verify_rsa_response_sign(resp, opay_public_key):
    sign = resp.get("sign")
    if not sign:
        _logger.warning("Opay API response missing signature. Skipping verification.")
        return True

    candidate = _build_signature_string(resp)
    _logger.info("🔎 Signature string (to verify): %s", candidate)

    opay_key = _import_rsa_key(opay_public_key, key_type="public")
    verifier = pkcs1_15.new(opay_key)
    signature = base64.b64decode(sign)
    _logger.info("🔎 Signature (decoded hex): %s", signature.hex())

    try:
        digest = SHA256.new(candidate.encode("utf-8"))
        verifier.verify(digest, signature)
        _logger.info("✅ Signature verified successfully.")
        return True
    except Exception as e:
        _logger.error("❌ Signature verification failed. String=%s, Error=%s", candidate, e)
        raise UserError("Opay API response signature verification failed.")


def _analytic_response(response_content, merchant_private_key, opay_public_key):
    """Analyse Opay response: check code, verify sign, decrypt if needed."""
    code = response_content.get('code')
    if code != '00000':
        error_msg = response_content.get('message', 'Unknown error from Opay.')
        raise UserError(f"Opay API call failed. Code: {code}, Message: {error_msg}")

    # Verify Opay signature
    _verify_rsa_response_sign(response_content, opay_public_key)

    data = response_content.get('data')
    if data is None:
        return {}

    # If already dict/list, assume plaintext JSON
    if isinstance(data, (dict, list)):
        return data

    # If it's a string, try decryption
    try:
        decrypted_text = _decrypt_by_private_key(data, merchant_private_key)
        _logger.info("Decrypted response data: '%s'", decrypted_text)
        try:
            return json.loads(decrypted_text)
        except Exception:
            return {"raw": decrypted_text}
    except Exception:
        # Not decryptable, return raw string
        _logger.warning("Data not decryptable, returning as-is.")
        return data


# --- Opay Configuration ---
class OpayConfig(models.Model):
    _name = 'opay.config'
    _description = 'Opay Configuration'
    _inherit = 'res.config.settings'

    client_auth_key = fields.Char(string='Client Auth Key', required=True)
    merchant_private_key = fields.Text(string='Merchant Private Key', required=True,
                                       help="Paste your Base64 encoded RSA Merchant Private Key here.")
    opay_public_key = fields.Text(string='Opay Public Key', required=True,
                                  help="Paste Opay’s Base64 encoded RSA Public Key here.")
    opay_merchant_id = fields.Char(string='Opay Merchant ID', required=True)
    account_prefix = fields.Char(string='Account Prefix', default='OPAY')
    is_test_mode = fields.Boolean(string='Test Mode', default=False)
    use_rsa_signing = fields.Boolean(
        string="Use RSA Signing",
        default=True,
        help="Enable for RSA signatures with private key. Disable for SHA256 hash signing."
    )

    def set_values(self):
        super(OpayConfig, self).set_values()
        params = self.env['ir.config_parameter'].sudo()
        params.set_param('opay.client_auth_key', self.client_auth_key or '')
        params.set_param('opay.merchant_private_key', self.merchant_private_key or '')
        params.set_param('opay.opay_public_key', self.opay_public_key or '')
        params.set_param('opay.opay_merchant_id', self.opay_merchant_id or '')
        params.set_param('opay.account_prefix', self.account_prefix or 'OPAY')
        params.set_param('opay.is_test_mode', self.is_test_mode)
        params.set_param('opay.use_rsa_signing', self.use_rsa_signing)


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
    state = fields.Selection([('draft', 'Draft'), ('active', 'Active'), ('suspended', 'Suspended')],
                             default='draft', string='State')

    def _opay_api_request(self, endpoint, request_content):
        """Handles full Opay API lifecycle (encrypt, sign, call, decrypt, verify)."""
        params = self.env['ir.config_parameter'].sudo()
        client_auth_key = params.get_param('opay.client_auth_key', '')
        merchant_private_key = params.get_param('opay.merchant_private_key', '')
        opay_public_key = params.get_param('opay.opay_public_key', '')
        use_rsa = params.get_param('opay.use_rsa_signing') == 'True'

        missing = []
        if not client_auth_key: missing.append("Client Auth Key")
        if not merchant_private_key: missing.append("Merchant Private Key")
        if not opay_public_key: missing.append("Opay Public Key")
        if missing:
            raise UserError("Missing Opay configuration parameter(s): %s. "
                            "Configure under Settings > General Settings." % ", ".join(missing))

        timestamp = str(int(time.time() * 1000))

        # Encrypt business payload with Opay public key
        param_content = _encrypt_by_public_key(_json_dumps(request_content), opay_public_key)

        # Sign the request
        sign_string = param_content + timestamp
        signature = _generate_sign(sign_string, merchant_private_key)

        request_body = {"paramContent": param_content, "sign": signature}
        headers = {
            "clientAuthKey": client_auth_key,
            "version": "V1.0.1",
            "bodyFormat": "JSON",
            "timestamp": timestamp,
        }
        api_url = f"https://payapi.opayweb.com/api/v2/third/depositcode/{endpoint}"

        try:
            _logger.info("🔹 Opay Request URL: %s", api_url)
            _logger.info("🔹 Opay Request Headers: %s", json.dumps(headers, indent=2))
            _logger.info("🔹 Opay Request Body (paramContent): %s", request_body.get('paramContent'))
            _logger.info("🔹 Opay Request Body (sign): %s", request_body.get('sign'))

