import json
import logging

from odoo import http, fields
from odoo.http import request, Response
from odoo.exceptions import ValidationError

from ..models import helpers

_logger = logging.getLogger(__name__)


class OPayWebhookController(http.Controller):

    @http.route(
        "/opay/webhook", type="json", auth="public", methods=["POST"], csrf=False
    )
    def opay_webhook_handler(self):
        try:
            json_data = request.httprequest.get_json(silent=True)
            # print("JSON Data:", json_data)
            response = helpers._decrypt_by_private_key(
                json_data.get("paramContent"), 
                request.env['ir.config_parameter'].sudo().get_param('opay.merchant_private_key'),
                )
            # Sample Response
            # '{"depositAmount":"50.00","senderAccount":"1003217490","orderNo":"250929060200455237613933","notes":"Transfer/ To GHONIM MOON LTD-Ewetoye Test/6124785974","fee":"0.15","formatDateTime":"2025-09-29 23:58:07","stampDutyPattern":"","depositFee":"0","depositTime":"1759186687000","transactionId":"202509291170295632021241856","merchantName":"GHONIM MOON LTD-Ewetoye Test","reference":"","senderName":"Ibrahim Ewetoye","payType":"COLLECTION","depositCode":"6124785974","merchantId":"256625041017171","stampDutyAmount":"0.00","currency":"NGN","refId":"000000056","senderBank":"VFD MFB","stampDutyChargeId":"","status":"SUCCESS"}'
            
            # response = helpers._analytic_response(
            #     json_data,
            #     request.env['ir.config_parameter'].sudo().get_param('opay.opay_public_key', default=False),
            #     request.env['ir.config_parameter'].sudo().get_param('opay.opay_merchant_id', default=False),
            #     )
            data = json.loads(response)
            config_merchant_id = (
                request.env["ir.config_parameter"]
                .sudo()
                .get_param("opay.opay_merchant_id")
            )
            if data.get("merchantId") != config_merchant_id:
                return self.build_response(
                    "Ignored",
                    "Merchant ID mismatch",
                    data,
                )
            if data.get("status") != "SUCCESS":
                return self.build_response("ignored", "Payment not successful", data)
            wallet = (
                request.env["opay.wallet"]
                .sudo()
                .search([("account_number", "=", data.get("depositCode"))], limit=1)
            )
            if not wallet:
                return self.build_response(
                    "Ignored", "Not an existing wallet account", data
                )
            # Check if payment already exists
            existing_payment = (
                request.env["account.payment"]
                .sudo()
                .search([("ref", "=", data.get("transactionId"))], limit=1)
            )
            if existing_payment:
                return self.handle_existing_payment(existing_payment, data)
            # Create new payment with sale order linking
            data["currency_id"] = request.env["res.currency"].sudo().search([
                    ("name", "=", data.get("currency", "NGN"))], limit=1).id
            payment = self.create_opay_payment(wallet.partner_id, data)
            return self.build_response("success", "Payment processed successfully",
                                       {"payment_id": payment.id})
        except Exception as e:
            return self.build_response("Exception", "Internal Server Error", {str(e)})

    def handle_existing_payment(self, payment, data):
        """Handle case where payment already exists"""
        # Update payment status or other fields if needed
        payment.write({"opay_status": data.get("status")})
        return self.build_response("Duplicate", "Payment already processed", data)

    def create_opay_payment(self, partner, data):
        """Create an account.payment from OPay webhook data with sale order linking"""
        # Find sale order based on outOrderNo or orderNo
        sale_order = self.find_sale_order(data)

        # Get OPay payment method
        opay_method = self.get_opay_payment_method()

        # Prepare payment values
        payment_vals = self.prepare_payment_vals(data, partner, opay_method, sale_order)

        # Create and post payment
        payment = request.env["account.payment"].sudo().create(payment_vals)
        payment.action_post()

        # Link to sale order if found
        if sale_order:
            self.link_payment_to_sale_order(payment, sale_order, data)

        _logger.info(
            f"Created OPay payment {payment.id} for order {data.get('orderNo')}"
        )
        return payment

    def find_sale_order(self, data):
        """Find sale order using outOrderNo or orderNo"""
        SaleOrder = request.env["sale.order"].sudo()
        # Try outOrderNo first (usually your internal reference)
        out_order_no = data.get("outOrderNo")
        if out_order_no:
            sale_order = SaleOrder.search([("name", "=", out_order_no)], limit=1)
            if sale_order:
                _logger.info(f"Found sale order by outOrderNo: {out_order_no}")
                return sale_order

        # Try orderNo (OPay's order reference)
        order_no = data.get("orderNo")
        if order_no:
            # Search in sale order references or custom field
            sale_order = SaleOrder.search(
                ["|", ("name", "=", order_no), ("client_order_ref", "=", order_no)],
                limit=1,
            )
            if sale_order:
                _logger.info(f"Found sale order by orderNo: {order_no}")
                return sale_order
        return None

    def get_opay_payment_method(self):
        """Get or create OPay payment method"""
        opay_method = (
            request.env["account.payment.method"]
            .sudo()
            .search([("is_opay", "=", True)], limit=1)
        )
        if not opay_method:
            opay_method = (
                request.env["account.payment.method"]
                .sudo()
                .create(
                    {
                        "name": "OPay",
                        "is_opay": True,
                        "code": "opay",
                        "payment_type": "inbound",
                    }
                )
            )
        return opay_method

    def prepare_payment_vals(self, data, partner, opay_method, sale_order):
        """Prepare payment values dictionary"""
        payment_vals = {
            "payment_type": "inbound" if data.get("payType") == "COLLECTION" else "outbound",
            "partner_id": partner.id,
            "amount": data["depositAmount"],
            "currency_id": data["currency_id"],
            "payment_method_id": opay_method.id,
            "ref": data["transactionId"],
            "opay_order_no": data.get("orderNo"),
            "opay_notes": data.get("notes"),
            "opay_merchant_id": data.get("merchantId"),
            "opay_status": data.get("status"),
            "opay_sender_name": data.get("senderName"),
            "opay_sender_account": data.get("senderAccount"),
            "opay_transaction_time": self.convert_timestamp(
                data.get("depositTime")
            ),
            "date": fields.Date.today(),
        }
        # If sale order found, set communication and link
        if sale_order:
            payment_vals["communication"] = sale_order.name
        return payment_vals

    def link_payment_to_sale_order(self, payment, sale_order, data):
        """Link payment to sale order and update order status"""
        try:
            # Add payment to sale order
            sale_order.write({"payment_ids": [(4, payment.id)]})
            _logger.info(f"Linked payment {payment.id} to sale order {sale_order.name}")
        except Exception as e:
            _logger.error(f"Error linking payment to sale order: {str(e)}")

    def convert_timestamp(self, timestamp_str):
        """Convert OPay timestamp to Odoo datetime"""
        if timestamp_str:
            from datetime import datetime

            try:
                timestamp = int(timestamp_str) / 1000
                return datetime.fromtimestamp(timestamp)
            except (ValueError, TypeError):
                pass
        return fields.Datetime.now()

    def build_response(self, status, message, data):
        _logger.info(f"OPay payment: {status}: {data}")
        return {"status": status, "message": message, "data": data}
