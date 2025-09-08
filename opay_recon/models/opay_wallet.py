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
MAX_DECRYPT_TYPE = 128  # typical for 1024-bit keys; we use key.size_in_bytes() dynamically
# Note: max encrypt bytes computed as key_bytes - 11 (PKCS1 v1.5 padding)

def _json_dumps(json_data):
    """Stable JSON serialization used for canonicalization."""
    return json.dumps(json_data, sort_keys=True, separators=(',', ':'))

def _import_rsa_key(key_str):
    """
    Accepts:
      - PEM with headers (-----BEGIN ...----- ... -----END ...-----)
      - raw base64 block (no headers) (we base64-decode and try import)
      - full PEM but without newlines (we still handle)
    Returns: Crypto.PublicKey.RSA key object or raises UserError.
    """
    if not key_str or not isinstance(key_str, str):
        raise UserError("RSA key is empty or invalid.")

    ks = key_str.strip()

    # If looks like PEM with headers, import directly
    try:
        return RSA.import_key(ks.encode() if isinstance(ks, str) else ks)
    except Exception:
        pass

    # Try to remove whitespace/newlines and treat as base64-encoded DER
    try:
        compact = "".join(ks.split())
        decoded = base64.b64decode(compact)
        return RSA.import_key(decoded)
    except Exception as e:
        _logger.error("Failed to import RSA key; tried PEM import and base64 decode. Details: %s", e)
        raise UserError("Invalid RSA key format. Please provide either a PEM (with headers) or base64-encoded key body.")

# --- RSA encryption / decryption (chunk-aware) ---

def _encrypt_by_public_key(input_str, public_key):
    """Encrypt an arbitrary-length string with RSA public key (PKCS#1 v1.5), chunking automatically."""
    key = _import_rsa_key(public_key)
    cipher = PKCS1_v1_5.new(key)
    key_bytes = key.size_in_bytes()
    max_encrypt = key_bytes - 11  # PKCS#1 v1.5 overhead
    input_bytes = input_str.encode("utf-8")
    offset = 0
    out = bytearray()
    while offset < len(input_bytes):
        chunk = input_bytes[offset:offset + max_encrypt]
        out.extend(cipher.encrypt(chunk))
        offset += max_encrypt
    return base64.b64encode(bytes(out)).decode("utf-8")

def _decrypt_by_private_key(text, private_key):
    """Decrypt base64-encoded RSA-encrypted data using private key (handles chunking)."""
    key = _import_rsa_key(private_key)
    cipher = PKCS1_v1_5.new(key)
    try:
        encrypted_data = base64.b64decode(text)
    except Exception as e:
        _logger.error("Decrypt input is not valid base64: %s", e)
        raise UserError("Encrypted response from Opay is not valid base64.")

    key_bytes = key.size_in_bytes()
    offset = 0
    out = bytearray()
    while offset < len(encrypted_data):
        chunk = encrypted_data[offset:offset + key_bytes]
        decrypted = cipher.decrypt(chunk, None)
        if decrypted is None:
            _logger.error("RSA decrypt returned None for a chunk (maybe wrong private key).")
            raise UserError("RSA decryption failed (invalid private key or corrupted data).")
        out.extend(decrypted)
        offset += key_bytes
    try:
        return out.decode("utf-8")
    except Exception:
        # If decoding fails, return raw bytes decoded with 'latin-1' to avoid crash (unlikely)
        return out.decode("latin-1")

# --- Signing (request) ---

def _generate_sign(data, private_key=None, use_rsa=True):
    """
    Generate signature for outgoing requests.
    If use_rsa True: sign `data` with RSA-SHA256 using merchant private key, return base64 signature.
    If use_rsa False: fallback to SHA256 hexdigest (not typically used for this flow).
    """
    if use_rsa:
        if not private_key:
            raise UserError("RSA signing requested but no private key provided.")
        rsa_key = _import_rsa_key(private_key)
        signer = pkcs1_15.new(rsa_key)
        digest = SHA256.new(data.encode("utf-8"))
        sig = signer.sign(digest)
        return base64.b64encode(sig).decode("utf-8")
    else:
        d = SHA256.new(data.encode("utf-8"))
        # Crypto `SHA256.new().hexdigest()` not directly available; use digest then hex:
        return d.digest().hex()

# --- Response signature verification (per Opay) ---

def _verify_rsa_response_sign(resp, opay_public_key):
    """
    Verify Opay response signature.
    According to Opay guidance, they sign the ENCRYPTED data string concatenated with timestamp:
        sign_string = encrypted_data + timestamp
    resp is the full JSON response dict. Returns True if signature valid, raises UserError if invalid.
    """
    _logger.debug("Verifying Opay response signature: %s", json.dumps(resp, indent=2))
    sign = (resp.get("sign") or "").strip()
    timestamp_raw = resp.get("timestamp")
    data_field = resp.get("data")

    if not sign:
        raise UserError("Opay response missing 'sign' value.")
    if timestamp_raw is None:
        raise UserError("Opay response missing 'timestamp' value.")
    timestamp = str(timestamp_raw).strip()
    if data_field is None:
        raise UserError("Opay response missing 'data' value for signature verification.")

    # If data_field is already a dict/list (plaintext), Opay normally signs encrypted string; raise.
    if isinstance(data_field, (dict, list)):
        raise UserError("Opay returned plaintext data; cannot verify signature which expects encrypted data string.")

    # Build string = encrypted_data + timestamp
    string_to_verify = f"{data_field}{timestamp}"
    _logger.debug("String to verify (encrypted_data+timestamp): %s", string_to_verify)

    opay_key = _import_rsa_key(opay_public_key)
    verifier = pkcs1_15.new(opay_key)
    digest = SHA256.new(string_to_verify.encode("utf-8"))
    try:
        verifier.verify(digest, base64.b64decode(sign))
        _logger.info("Opay signature verified successfully.")
        return True
    except (ValueError, TypeError) as e:
        _logger.error("Opay signature verification error: %s", e)
        raise UserError("Opay API response signature verification failed. Details: Invalid signature.")

# --- Response analysis (verify + decrypt) ---

def _analytic_response(response_content, merchant_private_key, opay_public_key):
    """
    1) Check response code
    2) Verify signature using encrypted data + timestamp (per Opay)
    3) Decrypt data with merchant private key (if data is encrypted string)
    4) Return parsed JSON or raw string wrapped as dict
    """
    code = response_content.get('code')
    if code != '00000':
        message = response_content.get('message', 'Unknown error from Opay.')
        raise UserError(f"Opay API call failed. Code: {code}, Message: {message}")

    # 1) verify signature
    _verify_rsa_response_sign(response_content, opay_public_key)

    # 2) handle data
    enc_or_plain = response_content.get('data')
    if enc_or_plain is None:
        return {}

    # If Opay returned a JSON object (rare), return as-is
    if isinstance(enc_or_plain, (dict, list)):
        return enc_or_plain

    # Otherwise decrypt the encrypted base64 string
    decrypted_text = _decrypt_by_private_key(enc_or_plain, merchant_private_key)
    try:
        return json.loads(decrypted_text)
    except Exception:
        return {"raw": decrypted_text}

# --- Odoo config model (store keys, auth key, merchant id) ---

class OpayConfig(models.Model):
    _name = 'opay.config'
    _description = 'Opay Configuration'
    _inherit = 'res.config.settings'

    client_auth_key = fields.Char(string='Client Auth Key', required=True)
    merchant_private_key = fields.Text(string='Merchant Private Key', required=True,
                                       help="Your RSA Merchant Private Key (PEM with headers, or base64 body).")
    opay_public_key = fields.Text(string='Opay Public Key', required=True,
                                  help="OPay RSA Public Key (PEM with headers, or base64 body).")
    opay_merchant_id = fields.Char(string='Opay Merchant ID', required=True)
    account_prefix = fields.Char(string='Account Prefix', default='OPAY')
    is_test_mode = fields.Boolean(string='Test Mode', default=False)
    use_rsa_signing = fields.Boolean(string="Use RSA Signing", default=True)

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

# --- Wallet model (creates deposit code via Opay) ---

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
        params = self.env['ir.config_parameter'].sudo()
        client_auth_key = params.get_param('opay.client_auth_key', '')
        merchant_private_key = params.get_param('opay.merchant_private_key', '')
        opay_public_key = params.get_param('opay.opay_public_key', '')
        use_rsa = params.get_param('opay.use_rsa_signing') in ('True', True, 'true')

        missing = []
        if not client_auth_key:
            missing.append("Client Auth Key")
        if not merchant_private_key:
            missing.append("Merchant Private Key")
        if not opay_public_key:
            missing.append("Opay Public Key")
        if missing:
            raise UserError("Missing Opay configuration parameter(s): %s." % ", ".join(missing))

        timestamp = str(int(time.time() * 1000))

        # Encrypt business payload
        param_content = _encrypt_by_public_key(_json_dumps(request_content), opay_public_key)

        # Sign the request (paramContent + timestamp) with merchant private key (RSA)
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
            _logger.debug("Opay request url: %s", api_url)
            _logger.debug("Opay request body keys: %s", list(request_body.keys()))
            resp = requests.post(api_url, json=request_body, headers=headers, timeout=15)
            resp.raise_for_status()
            response_json = resp.json()
            _logger.debug("Opay response: %s", json.dumps(response_json)[:2000])
            return _analytic_response(response_json, merchant_private_key, opay_public_key)
        except requests.exceptions.RequestException as e:
            _logger.error("Connection error to Opay: %s", e)
            raise UserError("Connection to Opay API failed: %s" % str(e))

    @api.model
    def _create_virtual_account(self, customer):
        params = self.env['ir.config_parameter'].sudo()
        merchant_id = params.get_param('opay.opay_merchant_id', '')
        is_test_mode = params.get_param('opay.is_test_mode') in ('True', True, 'true')

        if is_test_mode:
            account_prefix = params.get_param('opay.account_prefix', 'OPAY')
            random_number = str(random.randint(1000000000, 9999999999))
            return f"{account_prefix}-{random_number}"

        if not merchant_id:
            raise UserError("Missing Opay Merchant ID. Please configure it in Opay Settings.")

        phone = customer.phone.replace(" ", "").replace("+", "") if customer.phone else ""
        email = (customer.email or "").strip()

        if not phone and not email:
            raise UserError("Customer must have phone or email to create Opay wallet.")

        if phone:
            phone_digits = ''.join(filter(str.isdigit, phone))
            if phone_digits.startswith("0"):
                phone_digits = "234" + phone_digits[1:]
            elif not phone_digits.startswith("234"):
                phone_digits = "234" + phone_digits
            phone = phone_digits

        ref_id = ''.join(random.choices(string.ascii_letters + string.digits, k=15))
        biz_payload = {
            "opayMerchantId": merchant_id,
            "refId": ref_id,
            "name": customer.name,
            "accountType": "Merchant",
            "sendPassWordFlag": "N",
        }
        if phone:
            biz_payload["phone"] = phone
        else:
            biz_payload["email"] = email

        response_data = self._opay_api_request('generateStaticDepositCode', biz_payload)
        if response_data and response_data.get('depositCode'):
            return response_data.get('depositCode')
        raise UserError("Opay API response missing 'depositCode'.")

    @api.model
    def create(self, vals):
        wallet = super(OpayWallet, self).create(vals)
        if wallet.partner_id:
            try:
                deposit_code = wallet._create_virtual_account(wallet.partner_id)
                wallet.write({'account_number': deposit_code, 'state': 'active'})
            except UserError as e:
                wallet.write({'state': 'draft'})
                raise UserError("Wallet creation failed for %s. %s" % (wallet.partner_id.name, str(e)))
        return wallet

# --- Payment model (placeholder) ---

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
        return payment

# --- Extend res.partner to auto-create wallet ---

class ResPartner(models.Model):
    _inherit = 'res.partner'

    wallet_id = fields.Many2one('opay.wallet', string="Opay Wallet", ondelete="restrict")
    wallet_account_number = fields.Char(related='wallet_id.account_number', string="Wallet Deposit Code", readonly=True)
    wallet_balance = fields.Float(related='wallet_id.balance', string="Wallet Balance", readonly=True)

    def _sanitize_phone_for_opay(self, phone):
        if not phone:
            return ""
        phone_digits = ''.join(filter(str.isdigit, phone.replace(" ", "").replace("+", "")))
        if phone_digits.startswith("0"):
            phone_digits = "234" + phone_digits[1:]
        elif not phone_digits.startswith("234"):
            phone_digits = "234" + phone_digits
        return phone_digits

    @api.model
    def create(self, vals):
        if vals.get("phone"):
            vals["phone"] = self._sanitize_phone_for_opay(vals["phone"])
        partner = super(ResPartner, self).create(vals)
        # Auto-create wallet when customer_rank indicates customer
        if vals.get("customer_rank", 0) > 0 and not partner.wallet_id:
            if not partner.phone and not partner.email:
                raise UserError("Customer '%s' must have phone or email to create Opay wallet." % partner.name)
            wallet_vals = {'name': partner.name, 'partner_id': partner.id, 'currency_id': self.env.company.currency_id.id}
            try:
                wallet = self.env['opay.wallet'].create(wallet_vals)
                partner.write({'wallet_id': wallet.id})
            except UserError:
                raise
            except Exception as e:
                raise UserError("Failed to create Opay wallet: %s" % str(e))
        return partner

    def write(self, vals):
        if vals.get("phone"):
            vals["phone"] = self._sanitize_phone_for_opay(vals["phone"])
        return super(ResPartner, self).write(vals)
