from odoo import _, models, fields
import logging

_logger = logging.getLogger(__name__)

class AccountPayment(models.Model):
    _inherit = "account.payment"

    auto_assign_invoices = fields.Boolean(
        default=True,
        help="Automatically assign this payment to nearest due unpaid invoices",
    )

    def action_post(self):
        """Override action_post to auto-assign invoices after posting"""
        result = super().action_post()

        payments_to_assign = self.filtered(
            lambda p: (
                p.auto_assign_invoices
                and p.payment_type == "inbound"
                and not p.reconciled_invoice_ids
            )
        )

        for payment in payments_to_assign:
            try:
                payment._auto_assign_invoices()
            except Exception as e:
                _logger.error(
                    f"Auto-assignment failed for {payment.name}: {str(e)}"
                )

        return result

    def _auto_assign_invoices(self):
        """Auto-assign payment to oldest unpaid invoices"""
        unpaid_invoices = self._get_unpaid_invoices()
        if not unpaid_invoices:
            _logger.info(f"No unpaid invoices found for {self.partner_id.name}")
            return

        payment_line = self.line_ids.filtered(
            lambda line: (
                line.account_id.account_type == "asset_receivable" 
                and not line.reconciled
            )
        )

        if not payment_line:
            _logger.warning(f"No receivable line found for payment {self.name}")
            return

        assigned_count = 0
        assigned_invoices = []
        
        for invoice in unpaid_invoices:
            if payment_line.reconciled:
                break
            try:
                # Get amount before assignment for logging
                amount_before = invoice.amount_residual
                
                # Assign payment to invoice
                invoice.js_assign_outstanding_line(payment_line.id)
                assigned_count += 1
                assigned_invoices.append(invoice)
                
                # Get amount after assignment
                amount_after = invoice.amount_residual
                amount_applied = amount_before - amount_after
                
                # Log in invoice chatter
                invoice.message_post(
                    body=_("Payment %s was automatically assigned", self._get_html_link()),
                    subtype_xmlid="mail.mt_note",
                )
                
                _logger.info(f"Assigned {amount_applied} to invoice {invoice.name}")
                
            except Exception as e:
                _logger.warning(f"Failed to assign invoice {invoice.name}: {str(e)}")
                break

        # Log comprehensive summary in payment chatter
        if assigned_count > 0:
            invoice_links = []
            for invoice in assigned_invoices:
                invoice_links.append(invoice.name)
            
            invoice_list = ", ".join(invoice_links)
            remaining_amount = self.amount_residual
            
            self.message_post(
                body=f"""
                    Auto-assignment completed:\n
                    • Invoices assigned: {assigned_count}\n
                    • Assigned invoices: {invoice_list}\n
                    • Remaining amount: {remaining_amount:,.2f} {self.currency_id.name}\n
                    
                    The payment was automatically distributed to the nearest due unpaid invoices.
                    """,
                message_type="comment",
                subtype_xmlid="mail.mt_note"
            )
        _logger.info(f"Assigned payment {self.name} to {assigned_count} invoices")

    def _get_unpaid_invoices(self):
        """Get unpaid invoices for the partner, sorted by date (oldest first)"""
        return self.env["account.move"].search(
            [
                ("partner_id", "=", self.partner_id.id),
                ("move_type", "=", "out_invoice"),
                ("state", "=", "posted"),
                ("payment_state", "in", ["not_paid", "partial"]),
                ("amount_residual", ">", 0),
            ],
            order="invoice_date_due asc, id asc",
        )