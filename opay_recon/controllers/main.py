# -*- coding: utf-8 -*-
import json
import logging
from odoo import http
from odoo.http import request

# Import the utility functions from the models file for signature verification
# from odoo.addons.opay_recon.models.opay_recon import _signature_content, _verify_signature
from odoo.addons.opay_recon.models.opay_config import _signature_content, _verify_signature
_logger = logging.getLogger(__name__)

class OpayWebhookController(http.Controller):

    @http.route('/opay/webhook', type='json', auth='public', methods=['POST'], csrf=False)
    def handle_opay_webhook(self, **kwargs):
        try:
            payload = kwargs
            _logger.info("Received OPay webhook payload: %s", json.dumps(payload, indent=2))

            # Fetch the signature from the request headers
            signature = request.httprequest.headers.get('X-Signature', '')
            
            # --- Signature Verification ---
            # Verify the webhook's authenticity using Opay's public key
            if not self._verify_opay_signature(payload, signature):
                _logger.error("Failed to verify OPay webhook signature.")
                return {'status': 'error', 'message': 'Invalid signature'}

            if 'data' not in payload or 'outOrderNo' not in payload['data']:
                _logger.error("Invalid OPay webhook payload.")
                return {'status': 'error', 'message': 'Invalid Payload'}

            payment_data = payload['data']
            transaction_status = payment_data.get('status')
            out_order_no = payment_data.get('outOrderNo')
            amount = float(payment_data.get('amount', 0.0))

            # Handle successful payment
            if transaction_status == 'SUCCESS':
                sale_order = http.request.env['sale.order'].sudo().search([('name', '=', out_order_no)], limit=1)

                if sale_order:
                    # Find the associated Opay Wallet and update the balance
                    wallet = http.request.env['opay.wallet'].sudo().search([('partner_id', '=', sale_order.partner_id.id)], limit=1)
                    
                    if wallet:
                        new_balance = wallet.balance + amount
                        wallet.write({'balance': new_balance})
                        _logger.info(
                            "Opay wallet balance for customer %s updated. New balance: %s",
                            sale_order.partner_id.name,
                            wallet.balance
                        )

                    # Update the sale order status to 'paid'
                    sale_order.sudo().write({'state': 'paid'})
                    _logger.info("Sale Order %s successfully reconciled via OPay webhook.", out_order_no)
                else:
                    _logger.warning("No matching sale order found for OPay reference: %s", out_order_no)
                    return {'status': 'error', 'message': 'No matching sale order'}

            elif transaction_status == 'FAILED':
                _logger.error("Payment failed for Order %s", out_order_no)
                return {'status': 'error', 'message': 'Payment Failed'}

            elif transaction_status == 'PENDING':
                _logger.info("Payment is pending for Order %s", out_order_no)
                return {'status': 'pending', 'message': 'Payment is pending'}

            else:
                _logger.warning("Unknown transaction status for Order %s", out_order_no)
                return {'status': 'error', 'message': 'Unknown transaction status'}

            # Return a success response to Opay as per their documentation
            return {'status': 'success', 'message': 'Webhook received successfully'}

        except Exception as e:
            _logger.error("Error processing OPay webhook: %s", str(e))
            return {'status': 'error', 'message': 'Internal Server Error'}

    def _verify_opay_signature(self, payload, signature):
        """
        Verifies the webhook signature from Opay using the Opay Public Key.

        Args:
            payload (dict): The parsed JSON payload sent by Opay.
            signature (str): The signature sent in the header of the webhook request.

        Returns:
            bool: True if the signature matches, False otherwise.
        """
        params = request.env['ir.config_parameter'].sudo()
        opay_public_key = params.get_param('opay.opay_public_key', default=False)
        
        if not opay_public_key:
            _logger.error("Opay public key is missing from configuration. Cannot verify webhook signature.")
            return False

        # The signature content for webhooks is the raw JSON body
        # excluding the 'sign' field if present.
        # This matches the `_signature_content` function's logic.
        sign_content = _signature_content(payload)
        
        return _verify_signature(sign_content, signature, opay_public_key)
