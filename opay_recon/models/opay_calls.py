"""
Opay encryption and decryption tool example

requirements: pycryptodome>=3.15.0
"""

__author__ = 'hao.zheng'

import base64
import json
import time

import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

MAX_DECRYPT_TYPE = 128
MAX_ENCRYPT_BYTE = 117


def encrypt_by_public_key(input_str, public_key):
    """
    Encrypt with public key
    :param input_str: Need to encrypt content
    :param public_key: public key
    :return: Ciphertext
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


def decrypt_by_private_key(text, private_key):
    """
    Decrypt with private key
    :param text: Ciphertext
    :param private_key: private key
    :return: Decrypted text
    """
    key_bytes = base64.b64decode(private_key)
    key = RSA.import_key(key_bytes)
    cipher = PKCS1_v1_5.new(key)
    encrypted_data = base64.b64decode(text)  # Base64 Decode
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


def generate_sign(data, private_key):
    """
    Generate a signature
    :param data: Signature data
    :param private_key: Private key
    :return: signature
    """
    key_bytes = base64.b64decode(private_key)
    rsa_key = RSA.import_key(key_bytes)

    signer = pkcs1_15.new(rsa_key)
    digest = SHA256.new(data.encode('utf-8'))

    signature = signer.sign(digest)
    signed_data = base64.b64encode(signature).decode('utf-8')

    return signed_data


def verify_signature(data, signature, public_key):
    """
    Verify the signature
    :param data: Verify the data
    :param signature: signature
    :param public_key: Public key
    :return: True or False
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


def json_dumps(json_data):
    return json.dumps(json_data, sort_keys=True, separators=(',', ':'))


def signature_content(response_content):
    """
    Generate Signature content
    :param response_content: opay response
    :return: Signature content
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
        if key is None or key == "":
            continue
        if value is None:
            continue
        if key == "sign":
            continue
        content.append(f"{key}={value}")
    return "&".join(content)


def build_request_body(request_content, timestamp):
    """
    Build request body
    :param request_content: request content
    :return: request ciphertext
    """
    # encrypt
    enc_data = encrypt_by_public_key(json_dumps(request_content), OPAY_PUBLIC_KEY)

    # generate sign
    sign = generate_sign(enc_data + timestamp, MERC_PRIVATE_KEY)

    return {"paramContent": enc_data, "sign": sign}


def analytic_response(response_content):
    """
    Analytic response
    :param response_content: opay api response
    :return: Decrypted text
    :raise Exception: Opay api call failed, response code is not 00000 or verify signature failed
    """
    if response_content['code'] != '00000':
        raise Exception(f"Opay api call failed, response code is not 00000, response: {response_content}")

    enc_text = response_content['data']

    # verify signature
    sign_content = signature_content(response_content)
    sign = response_content['sign']
    verift = verify_signature(sign_content, sign, OPAY_PUBLIC_KEY)
    if not verift:
        raise Exception(f"Opay api call error, verify signature failed, response: {response_content}")

    # decrypt
    return decrypt_by_private_key(enc_text, MERC_PRIVATE_KEY)


# =============== Demo Start ===============

# todo First of all, add your information, including key, auth key, request address, etc.

# Secret key
OPAY_PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCiAF0cpcyid9DULL51nb8sM+zHwh0wwnD7GUzGL6QWOU49fN1RB3wkmerzhb02O+VdnJr0jZCV8r8aGaVQc6ECwBgl/ea/ZKvd3jrNRruynmSESl7LByvcGiDTBVePM850+T0qTAseFdPvYCO7x1YZgGDutMHcD20ge2tu9fGCWwIDAQAB"
MERC_PRIVATE_KEY = "MIICXQIBAAKBgQCmQ/xD5YlsSxtUVQz7LBWxWTtUohL+BvS1UEi1aTl2Da5NLiIlClRn+kMmbKrmB/033MuAjUyuhC7gLHDxe/PyZH8jwafkmFnbqqHJ9Otdqdlb+GxF1Z+lpIL6/fz5ciEtBJloN+DEp6Lrv+xVu0JFYJgZKVzf6NJxXDy4LednaQIDAQABAoGAWHD/hmpZ8FX/YpufPRhVLbJmgf14ltHCZ5QeKQmg/DAI0JtCpGtbPLf98jmJqrUDOCzlvyrqaEZ93Ncm+P1TZHgK7VzEoZg6y947qGeUSRYb2sAvDA82uFMHmeBY5s6xC580rxbf9cDalyDF056BkV0MDHtOPZe4vmG6jI2HPTUCQQDTuVk7GvQd68VR/exjVnXGWo5BphjuXTObJeS/ECzQ15Uxnhk3lecnAWcPMDg3gPSz5XWaD9+SdnNi3mBCc48rAkEAyQkEddY/EaD4JldIiBigsseBN4sB59G79wUt3NrX7V/A18KQR8IvMT7nPJ7bKgYu1rxsgNnVsbd7vex+8Tf5uwJBAKRLqFqdR+IQG0bM7KsJZMtPaiS3Z5FQ8cLrXN6HBr/pCvU94gOoZ391LywyFu27PCh9Xwz2VF+rW07VkYz/b5ECQH1YL/3AzaYSNWbCeSjSIjAWEE0vUMrXjFjiU8wmbwdD8psUZp03R/FuhQLZEVFMdZvR890K9SBPhMnQUP3Zps0CQQCpkdq1Ul0jy9diZalIpyaR4Xqg+u2wndFIe3OTyHOd10f0DkiJTpXAyeViIpEgO4psujiWysRc9dex+ePArvZx"

auth_key = "5d394081fff24dc6a6b6952fcf6e4187"

# Request url
url = "https://payapi.opayweb.com/api/v2/third/depositcode/generateStaticDepositCode"

timestamp = str(int(time.time() * 1000))

headers = {
    "clientAuthKey": auth_key,
    "version": "V1.0.1",
    "bodyFormat": "JSON",
    "timestamp": timestamp
}

# Request content
request_contents = {
  "opayMerchantId":"256625041017171",
  "refId": "refer1200000850",
  "name": "Ibrahim Ewetoye",
  "email":"i.ewetoye@gmail.com",
  "phone":"2348076206772",
  "accountType":"Merchant",
  "sendPassWordFlag":"N"
}

# Build request body
request_body = build_request_body(request_contents, timestamp)
print("request Opay service content: ", request_body)

# Call to Opay's API
response = requests.post(url, json=request_body, headers=headers)
response_json = response.json()
print("response from Opay server: ", response_json)

# Analytic response, raise Exception: Opay api call failed, response code is not 00000 or verify signature failed
response_data = analytic_response(response_json)
print('opay response data: ', response_data)

# =============== Demo end ===============
