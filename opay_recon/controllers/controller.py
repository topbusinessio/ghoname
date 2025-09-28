import json
import logging

from odoo import http, fields
from odoo.http import request, Response
from odoo.exceptions import ValidationError

_logger = logging.getLogger(__name__)


class OPayWebhookController(http.Controller):

    @http.route(
        "/opay/webhook", type="json", auth="public", methods=["POST"], csrf=False
    )
    def opay_webhook_handler(self):
        # Sample Response
        # {
        #     "data": {
        #         "outOrderNo": "2334345345345211",
        #         "orderNo": "20220704741380171865833472",
        #         "payNo": "2334345345345245",
        #         "headMerchantId": "256622022480363",
        #         "merchantId": "256622022480364",
        #         "status": "SUCCESS",
        #         "errorMsg": "Not sufficient funds",
        #         "senderName": "LUJUN SUN",
        #         "senderBank": "ubaBank",
        #         "senderAccount": "2131****09",
        #         "recipientName": "LUJUN SUN",
        #         "receiptBank": "opay",
        #         "receiptAccount": "6119787331",
        #         "amount": "300.00",
        #         "fee": "1.50",
        #         "feePattern": "IN_DEDUCT",
        #         "payMethod": "BankCard",
        #         "settlementAmount": "100.00",
        #         "settlementFee": "10.00",
        #         "settlementFeePattern": "OUT_DEDUCT",
        #         "currency": "NGN",
        #         "isSplit": "Y",
        #         "splitInfo": [
        #             {"splitMerchantId": "25623232423432", "splitAmount": "20.00"}
        #         ],
        #         "productInfo": "",
        #         "sn": "XXXX",
        #         "remark": "static virtual account",
        #         "transactionTime": "1692773950143",
        #         "completedTime": "1692773950143",
        #         "additionalInformation": '{"pnr":"123","rrn":"310137872249"}',
        #     }
        # }

        try:
            # data = request.jsonrequest.get("data", {})
            json_data = request.httprequest.get_data().decode('utf-8')
            payload = json.loads(json_data)
            if not payload["data"]:
                return {"error": "Missing data"}, 400
            data = payload["data"]
            # Only process successful and known account payments
            wallet = (
                request.env["opay.wallet"]
                .sudo()
                .search([("account_number", "=", data.get("recipientAccount"))], limit=1)
            )
            if not wallet or data.get("status") != "SUCCESS":
                _logger.info(
                    f"OPay payment {data.get('orderNo')} status: {data.get('status')}"
                )
                return {"status": "ignored", "message": "Payment not successful", "data": data}
            # Check if payment already exists
            existing_payment = (
                request.env["account.payment"]
                .sudo()
                .search([("opay_order_no", "=", data.get("orderNo"))], limit=1)
            )

            if existing_payment:
                return self.handle_existing_payment(existing_payment, data)

            # Create new payment with sale order linking
            payment = self.create_opay_payment(wallet.partner_id, data)

            return {
                "status": "success",
                "payment_id": payment.id,
                "sale_order_linked": bool(payment.sale_order_id),
                "message": "Payment processed successfully",
            }

        except Exception as e:
            _logger.error(f"OPay webhook error: {str(e)}")
            return {"error": "Internal server error"}, 500

    def handle_existing_payment(self, payment, data):
        """Handle case where payment already exists"""
        # Update payment status or other fields if needed
        payment.write(
            {
                "opay_status": data.get("status"),
                "opay_additional_info": data.get("additionalInformation", ""),
            }
        )

        return {
            "status": "duplicate",
            "payment_id": payment.id,
            "message": "Payment already processed",
        }

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
                .create({"name": "OPay",
                        "is_opay": True,
                        "code": "opay",
                        "payment_type": "inbound",})
            )
        return opay_method

    def prepare_payment_vals(self, data, partner, opay_method, sale_order):
        """Prepare payment values dictionary"""
        amount = float(data.get("amount", 0))
        payment_vals = {
            "payment_type": "inbound",
            "partner_id": partner.id,
            "amount": amount,
            "currency_id": request.env.ref("base.NGN").id,
            "payment_method_id": opay_method.id,
            "ref": data.get("outOrderNo") or data.get("orderNo"),
            "opay_order_no": data.get("orderNo"),
            "opay_pay_no": data.get("payNo"),
            "opay_merchant_id": data.get("merchantId"),
            "opay_status": data.get("status"),
            "opay_sender_name": data.get("senderName"),
            "opay_sender_account": data.get("senderAccount"),
            "opay_settlement_amount": float(data.get("settlementAmount", 0)),
            "opay_transaction_time": self.convert_timestamp(data.get("transactionTime")),
            "opay_additional_info": data.get("additionalInformation", ""),
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
