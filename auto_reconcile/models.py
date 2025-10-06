from odoo import models, fields
import logging

_logger = logging.getLogger(__name__)


class AccountPayment(models.Model):
    _inherit = "account.payment"

    auto_assign_invoices = fields.Boolean(
        string="Auto Assign to Oldest Invoices",
        default=True,
        help="Automatically assign this payment to oldest unpaid invoices",
    )

    def action_post(self):
        """Override with error handling"""
        print("Auto Reconcile: action_post called")
        result = super().action_post()

        for payment in self:
            if (
                payment.auto_assign_invoices
                and payment.payment_type == "inbound"
                and not payment.reconciled_invoice_ids
            ):
                try:
                    print(
                        f"Auto Reconcile: Attempting to auto-assign invoices for payment {payment.name}"
                    )
                    payment._auto_assign_invoices()
                except Exception as e:
                    _logger.error(
                        f"Auto-assignment failed in action_post for {payment.name}: {str(e)}"
                    )
        return result

    def _auto_assign_invoices(self):
        """Auto-assign payment to oldest unpaid invoices using js_assign_outstanding_line"""
        for payment in self:
            if payment.payment_type != "inbound" or payment.state != "posted":
                continue

            try:
                unpaid_invoices = self._get_unpaid_invoices(payment)
                if not unpaid_invoices:
                    _logger.info(
                        f"No unpaid invoices found for {payment.partner_id.name}"
                    )
                    continue

                # In Odoo 17, use account_type instead of internal_type
                payment_line = payment.line_ids.filtered(
                    lambda line: line.account_id.account_type == "asset_receivable"
                    and not line.reconciled
                )

                if not payment_line:
                    _logger.warning(
                        f"No receivable line found for payment {payment.name}"
                    )
                    continue

                # Assign to invoices using Odoo's JS method
                assigned_count = 0
                for invoice in unpaid_invoices:
                    if payment_line.reconciled:
                        break
                    try:
                        invoice.js_assign_outstanding_line(payment_line.id)
                        assigned_count += 1
                        _logger.info(f"Assigned payment to invoice {invoice.name}")
                    except Exception as e:
                        _logger.warning(
                            f"Failed to assign invoice {invoice.name}: {str(e)}"
                        )
                        break

                _logger.info(
                    f"Successfully assigned payment {payment.name} to {assigned_count} invoices"
                )

            except Exception as e:
                _logger.error(
                    f"Auto-assignment failed for payment {payment.name}: {str(e)}"
                )

    def _get_unpaid_invoices(self, payment):
        """Get unpaid invoices for the partner, sorted by date (oldest first)"""
        return self.env["account.move"].search(
            [
                ("partner_id", "=", payment.partner_id.id),
                ("move_type", "=", "out_invoice"),
                ("state", "=", "posted"),
                ("payment_state", "in", ["not_paid", "partial"]),
                ("amount_residual", ">", 0),
            ],
            order="invoice_date asc, id asc",
        )
