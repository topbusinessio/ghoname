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

# --- Opay RSA Utility Functions (from Opay Python demo) ---

MAX_DECRYPT_TYPE = 128
MAX_ENCRYPT_BYTE = 117

def _json_dumps(json_data):
    """
    Dumps a dictionary to a sorted JSON string.
    """
    return json.dumps(json_data, sort_keys=True, separators=(',', ':'))

def _encrypt_by_public_key(input_str, public_key):
    """
    Encrypts content with a public key.
    :param input_str: Content to encrypt.
    :param public_key: Public key string (base64 encoded).
    :return: Encrypted ciphertext (base64 encoded string).
    """
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
    """
    Decrypts ciphertext with a private key.
    :param text: Ciphertext (base64 encoded).
    :param private_key: Private key string (base64 encoded).
    :return: Decrypted plaintext string.
    """
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

def _generate_sign(data, private_key):
    """
    Generates a signature for the given data using a private key.
    :param data: Data to sign.
    :param private_key: Private key string (base64 encoded).
    :return: Signature (base64 encoded string).
    """
    key_bytes = base64.b64decode(private_key)
    rsa_key = RSA.import_key(key_bytes)
    signer = pkcs1_15.new(rsa_key)
    digest = SHA256.new(data.encode('utf-8'))
    signature = signer.sign(digest)
    return base64.b64encode(signature).decode('utf-8')

def _verify_signature(data, signature, public_key):
    """
    Verifies a signature using a public key.
    :param data: Data to verify.
    :param signature: Signature to verify (base64 encoded).
    :param public_key: Public key string (base64 encoded).
    :return: True if the signature is valid, False otherwise.
    """
    try:
        key_bytes = base64.b64decode(public_key)
        rsa_key = RSA.import_key(key_bytes)
        verifier = pkcs1_15.new(rsa_key)
        hashed_data = SHA256.new(data.encode('utf-8'))
        verifier.verify(hashed_data, base64.b64decode(signature))
        return True
    except Exception:
        return False

def _signature_content(response_content):
    """
    Generates the signature content string from a response dictionary.
    """
    res_data = {
        'code': response_content['code'],
        'message': response_content['message'],
        'data': response_content['data'],
        'timestamp': response_content['timestamp'],
    }
    sorted_params = dict(sorted(res_data.items()))
    content = []
    keys = list(sorted_params.keys())
    keys.sort()
    for key in keys:
        value = sorted_params[key]
        if key is None or key == "" or key == "sign":
            continue
        if value is None:
            continue
        content.append(f"{key}={value}")
    return "&".join(content)

def _analytic_response(response_content, merchant_private_key, opay_public_key):
    """
    Analyses Opay's API response, verifies signature, and decrypts the data.
    :raises UserError: If the response code is not '00000' or signature verification fails.
    """
    if response_content.get('code') != '00000':
        error_msg = response_content.get('message', 'Unknown error from Opay.')
        error_code = response_content.get('code', 'N/A')
        raise UserError(f"Opay API call failed. Code: {error_code}, Message: {error_msg}")
    
    enc_text = response_content.get('data')
    if not enc_text:
        raise UserError("Opay API response data is missing.")
    
    # Verify signature
    sign_content = _signature_content(response_content)
    sign = response_content.get('sign')
    is_verified = _verify_signature(sign_content, sign, opay_public_key)
    if not is_verified:
        raise UserError("Opay API signature verification failed.")
    
    # Decrypt response data
    return _decrypt_by_private_key(enc_text, merchant_private_key)

# --- Opay Configuration ---
class OpayConfig(models.Model):
    _name = 'opay.config'
    _description = 'Opay Configuration'
    _inherit = 'res.config.settings'

    # Note: These fields replace the previous `opay_api_key` and `opay_secret_key`
    client_auth_key = fields.Char(string='Client Auth Key', required=True)
    merchant_private_key = fields.Char(string='Merchant Private Key', required=True,
                                        help="Your RSA private key, used for signing requests and decrypting responses.")
    opay_public_key = fields.Char(string='Opay Public Key', required=True,
                                    help="Opay's RSA public key, used for verifying their signatures and encrypting requests.")
    opay_merchant_id = fields.Char(string='Opay Merchant ID', required=True)
    account_prefix = fields.Char(string='Account Prefix', default='OPAY',
                                    help="Prefix for generated virtual accounts.")
    is_test_mode = fields.Boolean(string='Test Mode', default=False)
    
    def set_values(self):
        super(OpayConfig, self).set_values()
        self.env['ir.config_parameter'].sudo().set_param('opay.client_auth_key', self.client_auth_key)
        self.env['ir.config_parameter'].sudo().set_param('opay.merchant_private_key', self.merchant_private_key)
        self.env['ir.config_parameter'].sudo().set_param('opay.opay_public_key', self.opay_public_key)
        self.env['ir.config_parameter'].sudo().set_param('opay.opay_merchant_id', self.opay_merchant_id)
        self.env['ir.config_parameter'].sudo().set_param('opay.account_prefix', self.account_prefix)
        self.env['ir.config_parameter'].sudo().set_param('opay.is_test_mode', self.is_test_mode)

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
    state = fields.Selection([
        ('draft', 'Draft'),
        ('active', 'Active'),
        ('suspended', 'Suspended'),
    ], default='draft', string='State')

    def _opay_api_request(self, endpoint, request_content):
        """
        Generic helper to handle the full Opay API request lifecycle (encrypt, sign, call, decrypt, verify).
        """
        params = self.env['ir.config_parameter'].sudo()
        client_auth_key = params.get_param('opay.client_auth_key', default='')
        merchant_private_key = params.get_param('opay.merchant_private_key', default='')
        opay_public_key = params.get_param('opay.opay_public_key', default='')
        
        missing = []
        if not client_auth_key: missing.append("Client Auth Key")
        if not merchant_private_key: missing.append("Merchant Private Key")
        if not opay_public_key: missing.append("Opay Public Key")
        if missing:
            raise UserError(f"Missing Opay configuration parameter(s): {', '.join(missing)}. "
                            "Please configure them under `Settings > General Settings`.")

        timestamp = str(int(time.time() * 1000))
        
        # 1. Encrypt the request parameters using Opay's public key
        param_content = _encrypt_by_public_key(_json_dumps(request_content), opay_public_key)
        
        # 2. Sign the `paramContent` + `timestamp` string with your private key
        sign_string = param_content + timestamp
        signature = _generate_sign(sign_string, merchant_private_key)
        
        # 3. Build the final request body and headers
        request_body = {
            "paramContent": param_content,
            "sign": signature,
        }
        
        headers = {
            "clientAuthKey": client_auth_key,
            "version": "V1.0.1",
            "bodyFormat": "JSON",
            "timestamp": timestamp,
        }

        api_url = f"https://payapi.opayweb.com/api/v2/third/depositcode/{endpoint}"

        try:
            _logger.info("🔹 Opay Request URL: %s", api_url)
            _logger.info("🔹 Opay Request Headers: %s", headers)
            _logger.info("🔹 Opay Request Body: %s", request_body)
            
            response = requests.post(api_url, json=request_body, headers=headers, timeout=15)
            response.raise_for_status()
            response_json = response.json()
            
            _logger.info("✅ Opay API Response (raw): %s", json.dumps(response_json, indent=2))
            
            # 4. Analyze, verify, and decrypt the response
            decrypted_data = _analytic_response(response_json, merchant_private_key, opay_public_key)
            _logger.info("✅ Opay API Response (decrypted): %s", decrypted_data)
            
            return json.loads(decrypted_data)

        except requests.exceptions.RequestException as e:
            _logger.error("❌ Connection error to Opay: %s", str(e))
            raise UserError(f"Connection to Opay API failed: {str(e)}")
        except Exception as e:
            _logger.error("❌ Unexpected error during API call: %s", str(e))
            raise UserError(f"Unexpected error occurred with Opay API: {str(e)}")


    @api.model
    def _create_virtual_account(self, customer):
        """
        Creates a new Opay static deposit code for a customer using the API.
        """
        params = self.env['ir.config_parameter'].sudo()
        merchant_id = params.get_param('opay.opay_merchant_id', default='')
        is_test_mode = params.get_param('opay.is_test_mode') == 'True'
        
        if is_test_mode:
            account_prefix = params.get_param('opay.account_prefix', default='OPAY')
            random_number = str(random.randint(1000000000, 9999999999))
            generated_account = f"{account_prefix}-{random_number}"
            _logger.info("Test mode: generated dummy account %s", generated_account)
            return generated_account
            
        if not merchant_id:
            raise UserError("Missing Opay Merchant ID. Please configure it.")
        
        phone = customer.phone.replace(" ", "").replace("+", "") if customer.phone else ""
        if phone and not phone.isdigit():
            raise UserError(f"Invalid phone number format for {customer.name}: {customer.phone}")
            
        ref_id = ''.join(random.choices(string.ascii_letters + string.digits, k=15))

        biz_payload = {
            "opayMerchantId": merchant_id,
            "refId": ref_id,
            "name": customer.name,
            "accountType": "Merchant",
            "sendPassWordFlag": "N"
        }
        if phone:
            biz_payload["phone"] = phone
        if customer.email:
            biz_payload["email"] = customer.email
            
        # Call the new generic API request method
        response_data = self._opay_api_request('generateStaticDepositCode', biz_payload)
        
        if response_data.get('depositCode'):
            account_number = response_data['depositCode']
            _logger.info("✅ Opay deposit account successfully created: %s", account_number)
            return account_number
        else:
            raise UserError("API response was successful but missing 'depositCode'.")

    @api.model
    def create(self, vals):
        _logger.info("Creating wallet with vals: %s", vals)
        wallet = super(OpayWallet, self).create(vals)
        if wallet.partner_id:
            try:
                account_number = wallet._create_virtual_account(wallet.partner_id)
                wallet.write({'account_number': account_number, 'state': 'active'})
                _logger.info("Wallet updated with deposit account: %s", account_number)
            except UserError as e:
                wallet.write({'state': 'draft'})
                _logger.warning("Failed to create wallet for %s: %s", wallet.partner_id.name, str(e))
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
        payment = super(OpayPayment, self).create(vals)
        if payment.sale_order_id and payment.status == 'SUCCESS':
            payment.sale_order_id.write({'state': 'paid'})
            _logger.info("Sale Order %s marked as paid", payment.sale_order_id.name)
        return payment

# --- Extend res.partner ---
class ResPartner(models.Model):
    _inherit = 'res.partner'

    wallet_id = fields.Many2one('opay.wallet', string="Opay Wallet", ondelete="restrict")
    wallet_account_number = fields.Char(related='wallet_id.account_number', string="Wallet Deposit Code", readonly=True)
    wallet_balance = fields.Float(related='wallet_id.balance', string="Wallet Balance", readonly=True)

    def _sanitize_phone_for_opay(self, phone):
        if not phone:
            return ""
        phone = phone.replace(" ", "").replace("+", "")
        if phone.startswith("0"):
            phone = "234" + phone[1:]
        return ''.join(filter(str.isdigit, phone))

    @api.model
    def create(self, vals):
        if vals.get("phone"):
            vals["phone"] = self._sanitize_phone_for_opay(vals["phone"])

        partner = super(ResPartner, self).create(vals)

        if vals.get("customer_rank", 0) > 0 and not partner.wallet_id:
            _logger.info("Creating Opay wallet for new customer: %s", partner.name)
            wallet_vals = {
                'name': partner.name,
                'partner_id': partner.id,
                'currency_id': self.env.company.currency_id.id,
            }
            try:
                wallet = self.env['opay.wallet'].create(wallet_vals)
                partner.wallet_id = wallet.id
                _logger.info("Opay wallet created with deposit code: %s", wallet.account_number)
            except UserError as e:
                _logger.warning("Failed to create wallet for customer %s: %s", partner.name, str(e))
                raise UserError(f"Failed to create Opay wallet for {partner.name}.\n{str(e)}")

        return partner

    def write(self, vals):
        if vals.get("phone"):
            vals["phone"] = self._sanitize_phone_for_opay(vals["phone"])
        return super(ResPartner, self).write(vals)
