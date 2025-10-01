# -*- coding: utf-8 -*-
import logging

from odoo import _, models, fields, api
from odoo.exceptions import UserError


from . import helpers

_logger = logging.getLogger(__name__)

class OpayWallet(models.Model):
    _name = 'opay.wallet'
    _description = 'Opay Wallet'

    name = fields.Char(required=True, readonly=True,)
    reference = fields.Char(readonly=True, copy=False)
    partner_id = fields.Many2one('res.partner', string='Customer', required=True, ondelete='cascade', readonly=True)
    account_number = fields.Char(readonly=True)
    payments = fields.One2many('account.payment', 'opay_wallet_id')
    payment_count = fields.Integer(compute='_compute_payment_count')

    @api.depends('payments')
    def _compute_payment_count(self):
        for wallet in self:
            wallet.payment_count = self.env['account.payment'].sudo().search_count([('opay_wallet_id', '=', wallet.id)])

    def action_payments(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': 'Payments',
            'view_mode': 'tree',
            'res_model': 'account.payment',
            'domain': [('opay_wallet_id', '=', self.id)],
        }
