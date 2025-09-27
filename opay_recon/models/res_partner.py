from odoo import models, fields, api
from odoo.exceptions import UserError
import time
import requests
from . import opay_wallet


class Partner(models.Model):
    _inherit = 'res.partner'

    wallet_id = fields.Many2one("opay.wallet", "Opay Wallet", readonly=True, _compute="_create_opay_wallet")
    wallet_name = fields.Char("Opay Wallet Name", related="wallet_id.name", readonly=True)
    wallet_account_number = fields.Char("Opay Wallet Number", related="wallet_id.account_number", readonly=True)
    wallet_balance = fields.Float("Opay Wallet Balance", related="wallet_id.balance", readonly=True)

    @api.model
    def create(self, vals):
        # Create the partner record first
        partner = super(Partner, self).create(vals)
        # Then create the Opay wallet for the partner
        partner._create_opay_wallet()
        return partner
    
    def _create_opay_wallet(self):
        # Logic to create an Opay wallet for the partner
        # This is a placeholder for actual implementation
        if not self.wallet_id:
            # call Opay API to create wallet and get details
            # get opay keys from res_config_settings
            o_client_auth_key = (
                self.env["ir.config_parameter"]
                .sudo()
                .get_param("opay.client_auth_key", default=False)
            )
            o_merchant_private_key = (
                self.env["ir.config_parameter"]
                .sudo()
                .get_param("opay.merchant_private_key", default=False)
            )
            o_public_key = (
                self.env["ir.config_parameter"]
                .sudo()
                .get_param("opay.opay_public_key", default=False)
            )
            o_merchant_id = (
                self.env["ir.config_parameter"]
                .sudo()
                .get_param("opay.opay_merchant_id", default=False)
            )
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
            headers = {
                "clientAuthKey": o_client_auth_key,
                "version": "V1.0.1",
                "bodyFormat": "JSON",
                "timestamp": timestamp,
            }
            # Request content
            request_contents = {
                "opayMerchantId": o_merchant_id,
                # ref_id is account prefix + partner id
                "refId": f"{self.env['ir.config_parameter'].sudo().get_param('opay.account_prefix', 'OPAY')}{self.id:09d}",
                "name": self.name,
                "email": self.email,
                "accountType": "Merchant",
                "sendPassWordFlag": "N",
            }
            # Build request body
            request_body = opay_wallet.build_request_body(request_contents, o_public_key, o_merchant_private_key, timestamp)
            # print("request Opay service content: ", request_body)

            # Call to Opay's API
            response = requests.post(url, json=request_body, headers=headers)
            response_json = response.json()
            # print("response from Opay server: ", response_json)

            # Analytic response, raise Exception: Opay api call failed, response code is not 00000 or verify signature failed
            response_data = opay_wallet._analytic_response(response_json, o_public_key, o_merchant_private_key)
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
                raise UserError(
                    f"Opay wallet creation failed: {response_data.get('message', 'Unknown error')}"
                )
            wallet = self.env["opay.wallet"].create(
                {
                    "partner_id": self.id,
                    "name": self.name,
                    "reference": response_data['data']['refId'],
                    "account_number": response_data['data']['depositCode']
                }
            )
            self.wallet_id = wallet.id
            self.message_post(body="Opay wallet created successfully.")

