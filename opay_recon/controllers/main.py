from odoo import http
from odoo.http import request
import json
import logging
import hashlib
import hmac

_logger = logging.getLogger(__name__)

class OpayWebhookController(http.Controller):

    @http.route('/opay/webhook', type='json', auth='public', methods=['POST'], csrf=False)
    def handle_opay_webhook(self, **kwargs):
        try:
            payload = kwargs
            _logger.info("Received OPay webhook payload: %s", json.dumps(payload, indent=2))

            if 'data' not in payload or 'outOrderNo' not in payload['data']:
                _logger.error("Invalid OPay webhook payload.")
                return {'status': 'error', 'message': 'Invalid Payload'}

            payment_data = payload['data']
            transaction_status = payment_data.get('status')
            out_order_no = payment_data.get('outOrderNo')
            amount = float(payment_data.get('amount', 0.0))

            signature = request.httprequest.headers.get('X-Signature', '')
            if not self._verify_signature(payload, signature):
                return {'status': 'error', 'message': 'Invalid signature'}

            # ... rest of your payment handling code ...


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

    def _verify_signature(self, payload, signature):
        """
        Verifies the webhook signature from Opay to ensure the payload is legitimate.

        Args:
            payload (dict): The parsed JSON payload sent by Opay.
            signature (str): The signature sent in the header of the webhook request.

        Returns:
            bool: True if the signature matches, False otherwise.
        """
        # Fetch the secret key for signature verification
        opay_config = http.request.env['opay.config'].sudo().search([], limit=1)
        secret_key = opay_config.opay_secret_key if opay_config else None

        if not secret_key:
            _logger.error("Opay secret key is missing.")
            return False

        # Generate the signature from the payload
        payload_str = json.dumps(payload, separators=(',', ':'))
        calculated_signature = hmac.new(secret_key.encode(), payload_str.encode(), hashlib.sha256).hexdigest()

        # Compare the calculated signature with the provided signature
        return hmac.compare_digest(calculated_signature, signature)
