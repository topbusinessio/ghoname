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


def _normalize_pem(key_str, is_private=True):
    """Normalize PEM key string with headers and 64-char wrapping."""
    key_str = (key_str or "").strip().replace("\r", "").replace("\n", "")
    if not key_str:
        return key_str

    if is_private:
        header = "-----BEGIN RSA PRIVATE KEY-----"
        footer = "-----END RSA PRIVATE KEY-----"
    else:
        header = "-----BEGIN PUBLIC KEY-----"
        footer = "-----END PUBLIC KEY-----"

    if key_str.startswith(header):
        key_str = key_str[len(header):]
    if key_str.endswith(footer):
        key_str = key_str[:-len(footer)]
    key_str = key_str.strip()

    lines = [key_str[i:i+64] for i in range(0, len(key_str), 64)]
    pem_key = "\n".join([header] + lines + [footer])
    return pem_key


# --- RSA helpers (adaptive to key size) ---

def _encrypt_by_public_key(input_str, public_key):
    """Encrypt content with public key (RSA), auto-detect block size."""
    public_key = _normalize_pem(public_key, is_private=False)
    try:
        key = RSA.import_key(public_key.encode())
    except Exception as e:
        _logger.error("Invalid Opay public key format: %s", e)
        raise UserError(f"Invalid Opay public key (PEM import failed): {e}")

    cipher = PKCS1_v1_5.new(key)

    key_bytes = key.size_in_bytes()
    max_encrypt = key_bytes - 11
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
    private_key = _normalize_pem(private_key, is_private=True)
    try:
        key = RSA.import_key(private_key.encode())
    except Exception as e:
        _logger.error("Invalid merchant private key format: %s", e)
        raise UserError(f"Invalid merchant private key (PEM import failed): {e}")

    cipher = PKCS1_v1_5.new(key)

    try:
        encrypted_data = base64.b64decode(text)
    except Exception:
        # Not base64 → treat as plaintext and return as-is
        return text

    key_bytes = key.size_in_bytes()
    offset = 0
    out = bytearray()

    while offset < len(encrypted_data):
        chunk = encrypted_data[offset:offset + key_bytes]
        decrypted = cipher.decrypt(chunk, None)
        if decrypted is None:
            raise UserError("RSA decryption failed – invalid block or key mismatch.")
        out.extend(decrypted)
        offset += key_bytes

    return out.decode()


# --- Signing / verification ---

def _generate_sign(data, private_key=None, use_rsa=True):
    """Generates signature for requests (RSA or SHA256)."""
    if use_rsa:
        if not private_key:
            raise UserError("RSA signing requested but no private key provided.")
        private_key = _normalize_pem(private_key, is_private=True)
        try:
            rsa_key = RSA.import_key(private_key.encode())
        except Exception as e:
            _logger.error("Invalid merchant private key format for signing: %s", e)
            raise UserError(f"Invalid merchant private key (PEM import failed): {e}")
        signer = pkcs1_15.new(rsa_key)
        digest = SHA256.new(data.encode("utf-8"))
        signature = signer.sign(digest)
        return base64.b64encode(signature).decode("utf-8")
    else:
        return SHA256.new(data.encode("utf-8")).hexdigest()


def _verify_rsa_response_sign(resp, opay_public_key):
    """
    Verify the RSA signature of the Opay API response using Opay's public key.
    """
    try:
        sign = resp.get("sign")
        timestamp = resp.get("timestamp")
        data = resp.get("data")

        if not sign or not timestamp:
            _logger.warning("Opay API response missing signature or timestamp. Skipping verification.")
            return True

        # Prepare the data string for verification
        if isinstance(data, (dict, list)):
            data_str = _json_dumps(data)
        elif data is None:
            data_str = ""
        else:
            data_str = str(data) # Ensure it's a string

        string_to_verify = f"{data_str}{timestamp}"

        # Normalize and import Opay's public key
        public_key_pem = _normalize_pem(opay_public_key, is_private=False)
        try:
            opay_key = RSA.import_key(public_key_pem.encode())
        except Exception as e:
            _logger.error("Invalid Opay public key format for verification: %s", e)
            raise UserError(f"Invalid Opay public key for verification (PEM import failed): {e}")

        # Create the verifier and hash object
        verifier = pkcs1_15.new(opay_key)
        digest = SHA256.new(string_to_verify.encode("utf-8"))

        # Decode the base64 signature from Opay
        signature = base64.b64decode(sign)

        # Perform verification
        verifier.verify(digest, signature)
        _logger.info("✅ Opay API response signature verified successfully.")
        return True

    except (ValueError, TypeError) as e:
        _logger.error("❌ RSA signature verification failed: %s", e)
        # Raise specific error for debugging
        raise UserError(f"Opay API response signature verification failed. Details: {e}")
    except Exception as e:
        _logger.error("❌ Unexpected error during signature verification: %s", e)
        raise UserError(f"Unexpected error during Opay API response signature verification: {e}")


def _analytic_response(response_content, merchant_private_key, opay_public_key):
    """Analyse Opay response: check code, verify sign, decrypt if needed."""
    code = response_content.get('code')
    if code != '00000':
        error_msg = response_content.get('message', 'Unknown error from Opay.')
        raise UserError(f"Opay API call failed. Code: {code}, Message: {error_msg}")

    # Use the new RSA verification function
    if not _verify_rsa_response_sign(response_content, opay_public_key):
        # This will now be raised if _verify_rsa_response_sign fails
        raise UserError("Opay API response signature verification failed.")

    enc_or_plain = response_content.get('data')
    if enc_or_plain is None:
        raise UserError("Opay API response data is missing.")

    # If already dict/list, assume plaintext JSON and return directly
    if isinstance(enc_or_plain, (dict, list)):
        return enc_or_plain

    # If it's a string, try to decrypt; if that yields JSON, parse it.
    decrypted_text = _decrypt_by_private_key(enc_or_plain, merchant_private_key)
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
                                       help="Paste your full RSA Merchant Private Key here.")
    opay_public_key = fields.Text(string='Opay Public Key', required=True,
                                  help="Paste Opay’s RSA Public Key here.")
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
        signature = _generate_sign(sign_string, merchant_private_key if use_rsa else None, use_rsa)

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
            _logger.debug("🔹 Opay Request Body (first 500 chars): %s", json.dumps(request_body)[:500])
            response = requests.post(api_url, json=request_body, headers=headers, timeout=15)
            response.raise_for_status() # Raise an exception for bad status codes
            response_json = response.json()
            _logger.info("✅ Opay API Response (raw, first 2000 chars): %s", json.dumps(response_json, indent=2)[:2000])

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