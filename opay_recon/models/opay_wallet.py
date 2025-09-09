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
    """Encrypt content with public key (RSA), auto-detect block size."""
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
    """Decrypt ciphertext with private key (RSA), auto-detect block size."""
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
    """
    Verify the RSA signature of the Opay API response.
    This version includes debug logs to help diagnose the issue.
    """
    _logger.info("Starting Opay response signature verification...")
    _logger.info("Verifying signature using Opay Public Key: %s...", opay_public_key[:30] + '...')
    
    sign = resp.get("sign")
    if not sign:
        _logger.warning("Opay API response missing signature. Skipping verification.")
        return True # Or raise a different error if sign is mandatory

    # Use the new function to build the signature string
    string_to_verify = _build_signature_string(resp)
    
    _logger.info("Verification details:")
    _logger.info("  - String to verify: '%s'", string_to_verify)
    _logger.info("  - Received Signature: '%s'", sign)

    try:
        opay_key = _import_rsa_key(opay_public_key, key_type="public")
        verifier = pkcs1_15.new(opay_key)
        digest = SHA256.new(string_to_verify.encode("utf-8"))
        signature = base64.b64decode(sign)
        
        verifier.verify(digest, signature)
        _logger.info("✅ Opay API response signature verified successfully.")
        return True
    except Exception as e:
        _logger.error("❌ RSA signature verification failed: %s", e)
        raise UserError(f"Opay API response signature verification failed.\n"
                        f"Details: {e}\n\n"
                        f"Please compare the strings below:\n"
                        f"String to Verify: {string_to_verify}\n"
                        f"Received Signature: {sign}")


def _analytic_response(response_content, merchant_private_key, opay_public_key):
    """Analyse Opay response: check code, verify sign, decrypt if needed."""
    code = response_content.get('code')
    if code != '00000':
        error_msg = response_content.get('message', 'Unknown error from Opay.')
        raise UserError(f"Opay API call failed. Code: {code}, Message: {error_msg}")

    # Use the new RSA verification function
    _verify_rsa_response_sign(response_content, opay_public_key)

    enc_or_plain = response_content.get('data')
    if enc_or_plain is None:
        return {} # Handle case where data field is null

    # If already dict/list, assume plaintext JSON and return directly
    if isinstance(enc_or_plain, (dict, list)):
        return enc_or_plain

    # If it's a string, try to decrypt; if that yields JSON, parse it.
    decrypted_text = _decrypt_by_private_key(enc_or_plain, merchant_private_key)
    _logger.info("Decrypted response data: '%s'", decrypted_text)
    try:
        return json.loads(decrypted_text)
    except Exception:
        # Not JSON – return raw decrypted text as a string
        return {"raw": decrypted_text}


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
            
            response = requests.post(api_url, json=request_body, headers=headers, timeout=15)
            response.raise_for_status() # Raise an exception for bad status codes
            response_json = response.json()
            
            _logger.info("✅ Opay API Response (raw): %s", json.dumps(response_json, indent=2))

            # Analyze response: verify signature and decrypt data
            decrypted_data = _analytic_response(response_json, merchant_private_key, opay_public_key)
            _logger.info("✅ Opay API Response (parsed): %s", decrypted_data)
            return decrypted_data
        except requests.exceptions.RequestException as e:
            _logger.error("❌ Connection error to Opay: %s", str(e))
            raise UserError(f"Connection to Opay API failed: {str(e)}")
        except Exception as e:
            _logger.error("❌ Unexpected error during API call: %s", str(e))
            # This catches errors from _analytic_response and other unexpected issues
            raise UserError(f"Unexpected error occurred with Opay API: {str(e)}")

    @api.model
    def _create_virtual_account(self, customer):
        """Generates a virtual account number for the customer using Opay API."""
        params = self.env['ir.config_parameter'].sudo()
        merchant_id = params.get_param('opay.opay_merchant_id', '')
        is_test_mode = params.get_param('opay.is_test_mode') == 'True'

        if is_test_mode:
            account_prefix = params.get_param('opay.account_prefix', 'OPAY')
            random_number = str(random.randint(1000000000, 9999999999))
            return f"{account_prefix}-{random_number}"

        if not merchant_id:
            raise UserError("Missing Opay Merchant ID. Please configure it in Opay Settings.")

        # --- Enforce a phone number OR email address ---
        phone = customer.phone.replace(" ", "").replace("+", "") if customer.phone else ""
        email = customer.email.strip() if customer.email else ""
        
        # Opay API requires at least one of these.
        if not phone and not email:
            raise UserError(f"Customer '{customer.name}' must have a valid phone number or an email address to create an Opay wallet.")

        # If a phone number exists, ensure it's in the correct format.
        if phone:
            if not phone.isdigit():
                raise UserError(f"Invalid phone number format for '{customer.name}': {customer.phone}. Please use digits only.")
            if phone.startswith("0"):
                phone = "234" + phone[1:]
            if not phone.startswith("234") or len(phone) != 13:
                _logger.warning("Phone number '%s' for customer '%s' might not be in the expected Opay format (e.g., 234XXXXXXXXXX).", phone, customer.name)

        ref_id = ''.join(random.choices(string.ascii_letters + string.digits, k=15))
        biz_payload = {
            "opayMerchantId": merchant_id,
            "refId": ref_id,
            "name": customer.name,
            "accountType": "Merchant",
            "sendPassWordFlag": "N",
        }
        
        # Add phone OR email to the payload if they exist.
        if phone:
            biz_payload["phone"] = phone
        elif email:
            biz_payload["email"] = email

        response_data = self._opay_api_request('generateStaticDepositCode', biz_payload)
        if response_data.get('depositCode'):
            return response_data['depositCode']
        else:
            raise UserError("Opay API response missing 'depositCode'.")

    @api.model
    def create(self, vals):
        """Creates an Opay wallet for the partner and triggers API call."""
        wallet = super(OpayWallet, self).create(vals)
        if wallet.partner_id:
            try:
                account_number = wallet._create_virtual_account(wallet.partner_id)
                wallet.write({'account_number': account_number, 'state': 'active'})
            except UserError as e:
                wallet.write({'state': 'draft'}) # Reset state if creation fails
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
        """Handles payment creation, updating sale order state if successful."""
        payment = super(OpayPayment, self).create(vals)
        if payment.sale_order_id and payment.status == 'SUCCESS':
            # Assuming 'SUCCESS' is the status for a successful payment
            payment.sale_order_id.write({'state': 'paid'})
        return payment


# --- Extend res.partner ---
class ResPartner(models.Model):
    _inherit = 'res.partner'

    wallet_id = fields.Many2one('opay.wallet', string="Opay Wallet", ondelete="restrict")
    wallet_account_number = fields.Char(related='wallet_id.account_number', string="Wallet Deposit Code", readonly=True)
    wallet_balance = fields.Float(related='wallet_id.balance', string="Wallet Balance", readonly=True)

    def _sanitize_phone_for_opay(self, phone):
        """Sanitizes phone number for Opay, ensuring Nigerian format."""
        if not phone:
            return ""
        phone = phone.replace(" ", "").replace("+", "")
        # Ensure it starts with '234' for Nigerian numbers
        if phone.startswith("0"):
            phone = "234" + phone[1:]
        # Remove any non-digit characters
        phone = ''.join(filter(str.isdigit, phone))
        return phone

    @api.model
    def create(self, vals):
        """Sanitizes phone number and handles wallet creation upon partner creation."""
        if vals.get("phone"):
            vals["phone"] = self._sanitize_phone_for_opay(vals["phone"])
        partner = super(ResPartner, self).create(vals)

        # Automatically create wallet if partner is marked as a customer and no wallet exists
        if vals.get("customer_rank", 0) > 0 and not partner.wallet_id:
            # Check: enforce phone OR email for wallet creation
            if not partner.phone and not partner.email:
                raise UserError(f"Customer '{partner.name}' must have a valid phone number or an email address to create an Opay wallet.")

            wallet_vals = {
                'name': partner.name,
                'partner_id': partner.id,
                'currency_id': self.env.company.currency_id.id
            }
            try:
                wallet = self.env['opay.wallet'].create(wallet_vals)
                partner.write({'wallet_id': wallet.id}) # Link wallet to partner
            except UserError as e:
                # If wallet creation fails, propagate the error and ensure partner state is clean
                raise UserError(f"Failed to create Opay wallet for '{partner.name}'.\n{str(e)}")
        return partner

    def write(self, vals):
        """Sanitizes phone number on update."""
        if vals.get("phone"):
            vals["phone"] = self._sanitize_phone_for_opay(vals["phone"])
        return super(ResPartner, self).write(vals)
