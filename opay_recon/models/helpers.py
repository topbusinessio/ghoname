# -*- coding: utf-8 -*-
import logging
import requests
import json
import time
import base64

from odoo.exceptions import UserError, ValidationError

from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

_logger = logging.getLogger(__name__)

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

def _analytic_response(response_content, opay_public_key, merchant_private_key):
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

def _build_request_headers(o_client_auth_key, timestamp):
    return {
        "clientAuthKey": o_client_auth_key,
        "version": "V1.0.1",
        "bodyFormat": "JSON",
        "timestamp": timestamp,
    }

def _build_request_body(request_content, opay_public_key, merchant_private_key, timestamp):
    """
    Build request body
    :param request_content: request content
    :return: request ciphertext
    """
    # encrypt
    enc_data = _encrypt_by_public_key(_json_dumps(request_content), opay_public_key)

    # generate sign
    sign = _generate_sign(enc_data + timestamp, merchant_private_key)

    return {"paramContent": enc_data, "sign": sign}

def create_opay_wallet(o_client_auth_key, o_merchant_private_key, o_public_key, o_merchant_id, partner):
        if (
            not o_client_auth_key
            or not o_merchant_private_key
            or not o_public_key
            or not o_merchant_id
        ):
            raise UserError(
                "Opay configuration is incomplete. Please check the settings."
            )
        # Request url
        url = "https://payapi.opayweb.com/api/v2/third/depositcode/generateStaticDepositCode"
        timestamp = str(int(time.time() * 1000))
        headers = _build_request_headers(o_client_auth_key, timestamp)
        # Request content
        request_contents = {
            "opayMerchantId": o_merchant_id,
            # ref_id is account prefix + partner id
            "refId": f"{partner.id:09d}",
            "name": partner.name,
            "email": partner.email,
            "accountType": "Merchant",
            "sendPassWordFlag": "N",
        }
        # Build request body
        request_body = _build_request_body(request_contents, o_public_key, o_merchant_private_key, timestamp)
        # print("request Opay service content: ", request_body)

        # Call to Opay's API
        response = requests.post(url, json=request_body, headers=headers)
        response_json = response.json()
        # print("response from Opay server: ", response_json)

        # Analytic response, raise Exception: Opay api call failed, response code is not 00000 or verify signature failed
        response_data = _analytic_response(response_json, o_public_key, o_merchant_private_key)
        # print("opay response data: ", response_data)

        # Sample successfuly response, unsuccessful if code is not 00000
        # {
        #     "code": "00000",
        #     "data": {
        #         "depositCode": "6122932762",
        #         "accountType": "Merchant",
        #         "emailOrPhone": "i.ewetoye@gmail.com",
        #         "name": "Ibrahim Ewetoye",
        #         "refId": "refer1200000850",
        #     },
        #     "message": "SUCCESSFUL",
        # }
        # Create wallet record when successful
        if response_data.get("code") != "00000":
            raise ValidationError(f"Opay wallet creation failed: {response_data.get('message', 'Unknown error')}")
        return response_data
        

def query_wallet_balance(deposit_code, o_client_auth_key, o_merchant_id, o_public_key, o_merchant_private_key):
    """Query Opay wallet balance by deposit code."""
    url = "https://payapi.opayweb.com/api/v2/third/depositcode/queryWalletBalance"
    timestamp = str(int(time.time() * 1000))
    headers = _build_request_headers(o_client_auth_key, timestamp)
    request_contents = {
        "opayMerchantId": o_merchant_id,
        "depositCode": deposit_code,
    }
    request_body = _build_request_body(request_contents, o_public_key, o_merchant_private_key, timestamp)
    print("Request headers to Opay service: ", headers)
    response = requests.post(url, json=request_body, headers=headers)
    print("First Response to Opay wallet balance query:", response)
    response_json = response.json()
    print("Response from Opay wallet balance query:", response_json)
    response_data = _analytic_response(response_json, o_public_key, o_merchant_private_key)
    # Sample Reponse Data
    # return {
    #     "code": "00000",
    #     "message": "SUCCESSFUL",
    #     "data": {
    #         "name": "Ewetoye Ibrahim",
    #         "refId": "refer1200000850",
    #         "amount": "234",
    #         "currency": "NGN",
    #         "queryTime": "2022-09-29 08:47:55"
    #     }
    print("Response data from Opay wallet balance query:", response_data)
     # Raise exception if code is not 0000
    if response_data.get("code") != "0000":
        raise ValidationError(f"Opay wallet balance failed: {response_data.get('message', 'Unknown error')}")
    return response_data.get("data", {})
