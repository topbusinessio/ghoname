# models/account_move.py

from odoo import models, api

class AccountMove(models.Model):
    _inherit = 'account.move'

    def _update_installment_payment_status(self):
        """Auto-update installment and sale order payment status when invoices change."""
        for move in self:
            # Find linked installment (if any)
            plan = self.env['sale.installment.plan'].search([('invoice_id', '=', move.id)], limit=1)
            if plan:
                # 🔁 Recompute installment payment tracking fields
                plan._compute_invoice_payment()
                plan._compute_payment_status()

                # 🔁 Trigger recompute on the related Sale Order
                if plan.sale_order_id:
                    plan.sale_order_id._compute_payment_summary()

            # Also check if this invoice belongs to a sale order (e.g., down payment)
            elif move.invoice_origin:
                order = self.env['sale.order'].search([('name', '=', move.invoice_origin)], limit=1)
                if order:
                    order._compute_payment_summary()

    def write(self, vals):
        """Intercept invoice updates to auto-refresh payment linkage."""
        res = super().write(vals)
        if 'payment_state' in vals or 'amount_residual' in vals:
            self._update_installment_payment_status()
        return res
