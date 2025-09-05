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
    return json.dumps(json_data, sort_keys=True, separators=(',', ':'))


def _normalize_pem(key_str, is_private=True):
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


# --- RSA helpers ---

def _encrypt_by_public_key(input_str, public_key):
    public_key = _normalize_pem(public_key, is_private=False)
    key = RSA.import_key(public_key.encode())
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
    private_key = _normalize_pem(private_key, is_private=True)
    key = RSA.import_key(private_key.encode())
    cipher = PKCS1_v1_5.new(key)

    try:
        encrypted_data = base64.b64decode(text)
    except Exception:
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
    if use_rsa:
        if not private_key:
            raise UserError("RSA signing requested but no private key provided.")
        private_key = _normalize_pem(private_key, is_private=True)
        rsa_key = RSA.import_key(private_key.encode())
        signer = pkcs1_15.new(rsa_key)
        digest = SHA256.new(data.encode("utf-8"))
        signature = signer.sign(digest)
        return base64.b64encode(signature).decode("utf-8")
    else:
        return SHA256.new(data.encode("utf-8")).hexdigest()


def _verify_simple_response_sign(resp):
    try:
        sign = resp.get("sign")
        timestamp = resp.get("timestamp")
        if not sign or not timestamp:
            return True
        data_str = resp.get("data")
        if isinstance(data_str, (dict, list)):
            data_str = _json_dumps(data_str)
        elif data_str is None:
            data_str = ""
        recomputed = SHA256.new(f"{data_str}{timestamp}".encode("utf-8")).hexdigest()
        return sign == recomputed
    except Exception as e:
        _logger.warning("Response sign verification skipped (error: %s).", e)
        return True


def _analytic_response(response_content, merchant_private_key, opay_public_key):
    code = response_content.get('code')
    if code != '00000':
        error_msg = response_content.get('message', 'Unknown error from Opay.')
        raise UserError(f"Opay API call failed. Code: {code}, Message: {error_msg}")

    if not _verify_simple_response_sign(response_content):
        raise UserError("Opay API response signature verification failed.")

    enc_or_plain = response_content.get('data')
    if enc_or_plain is None:
        raise UserError("Opay API response data is missing.")

    if isinstance(enc_or_plain, (dict, list)):
        return enc_or_plain

    decrypted_text = _decrypt_by_private_key(enc_or_plain, merchant_private_key)
    try:
        return json.loads(decrypted_text)
    except Exception:
        return {"raw": decrypted_text}


# --- Opay Configuration ---
class OpayConfig(models.Model):
    _name = 'opay.config'
    _description = 'Opay Configuration'
    _inherit = 'res.config.settings'

    client_auth_key = fields.Char(string='Client Auth Key', required=True)
    merchant_private_key = fields.Text(string='Merchant Private Key', required=True)
    opay_public_key = fields.Text(string='Opay Public Key', required=True)
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
            raise UserError("Missing Opay configuration parameter(s): %s." % ", ".join(missing))

        timestamp = str(int(time.time() * 1000))
        param_content = _encrypt_by_public_key(_json_dumps(request_content), opay_public_key)

        sign_string = param_content + timestamp
        _logger.info("🔑 Opay signing string: %s", sign_string[:200] + "..." if len(sign_string) > 200 else sign_string)

        signature = _generate_sign(sign_string, merchant_private_key if use_rsa else None, use_rsa)
        _logger.info("✍️ Generated signature: %s", signature)

        request_body = {"paramContent": param_content, "sign": signature}
        headers = {
            "clientAuthKey": client_auth_key,
            "version": "V1.0.1",
            "bodyFormat": "JSON",
            "timestamp": timestamp,
        }
        api_url = f"https://payapi.opayweb.com/api/v2/third/depositcode/{endpoint}"

        try:
            _logger.info("➡️ Sending request to %s with body: %s", api_url, request_body)
            response = requests.post(api_url, json=request_body, headers=headers, timeout=15)
            response.raise_for_status()
            response_json = response.json()
            _logger.info("⬅️ Response: %s", response_json)
            decrypted_data = _analytic_response(response_json, merchant_private_key, opay_public_key)
            return decrypted_data
        except requests.exceptions.RequestException as e:
            raise UserError(f"Connection to Opay API failed: {str(e)}")
        except Exception as e:
            raise UserError(f"Unexpected error occurred with Opay API: {str(e)}")

    @api.model
    def _create_virtual_account(self, customer):
        params = self.env['ir.config_parameter'].sudo()
        merchant_id = params.get_param('opay.opay_merchant_id', '')
        is_test_mode = params.get_param('opay.is_test_mode') == 'True'

        if is_test_mode:
            account_prefix = params.get_param('opay.account_prefix', 'OPAY')
            random_number = str(random.randint(1000000000, 9999999999))
            return f"{account_prefix}-{random_number}"

        if not merchant_id:
            raise UserError("Missing Opay Merchant ID. Please configure it.")

        phone = customer.phone.replace(" ", "").replace("+", "") if customer.phone else ""
        if not phone:
            raise UserError(f"Customer {customer.name} must have a valid phone number to create an Opay wallet.")
        if not phone.isdigit():
            raise UserError(f"Invalid phone number for {customer.name}: {customer.phone}")
        if phone.startswith("0"):
            phone = "234" + phone[1:]

        ref_id = ''.join(random.choices(string.ascii_letters + string.digits, k=15))
        biz_payload = {
            "opayMerchantId": merchant_id,
            "refId": ref_id,
            "name": customer.name,
            "accountType": "Merchant",
            "sendPassWordFlag": "N",
            "phone": phone,
        }

        response_data = self._opay_api_request('generateStaticDepositCode', biz_payload)
        if response_data.get('depositCode'):
            return response_data['depositCode']
        else:
            raise UserError("Opay API response missing 'depositCode'.")

    @api.model
    def create(self, vals):
        wallet = super(OpayWallet, self).create(vals)
        if wallet.partner_id:
            try:
                account_number = wallet._create_virtual_account(wallet.partner_id)
                wallet.write({'account_number': account_number, 'state': 'active'})
            except UserError as e:
                wallet.write({'state': 'draft'})
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
            if not partner.phone:
                raise UserError(f"Customer {partner.name} must have a valid phone number for Opay wallet.")
            wallet_vals = {
                'name': partner.name,
                'partner_id': partner.id,
                'currency_id': self.env.company.currency_id.id
            }
            try:
                wallet = self.env['opay.wallet'].create(wallet_vals)
                partner.wallet_id = wallet.id
            except UserError as e:
                raise UserError(f"Failed to create Opay wallet for {partner.name}.\n{str(e)}")
        return partner

    def write(self, vals):
        if vals.get("phone"):
            vals["phone"] = self._sanitize_phone_for_opay(vals["phone"])
        return super(ResPartner, self).write(vals)
