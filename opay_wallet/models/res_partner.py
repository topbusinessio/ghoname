from odoo import _, api, fields, models
from odoo.exceptions import UserError, ValidationError
from . import helpers


class Partner(models.Model):
    _inherit = "res.partner"

    wallet_id = fields.Many2one(
        "opay.wallet", "Opay Wallet", readonly=True, _compute="_create_opay_wallet"
    )
    wallet_name = fields.Char(
        "Opay Wallet Name", related="wallet_id.name", readonly=True
    )
    wallet_account_number = fields.Char(
        "Opay Wallet Number", related="wallet_id.account_number", readonly=True
    )
    create_opay = fields.Boolean(
        default=False, help="Check this to create Opay Wallet for this partner"
    )

    @api.constrains("email")
    def _check_email_required(self):
        for partner in self:
            if not partner.email:
                raise ValidationError(_("Email address is required for partners."))

    @api.constrains("create_opay")
    def _on_create_opay_change(self):
        for partner in self:
            if partner.create_opay and not partner.wallet_id:
                if not partner.email:
                    raise ValidationError(
                        _("Email address is required to create an Opay wallet.")
                    )
                partner._create_opay_wallet()
        return partner

    def _create_opay_wallet(self):
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
        response_data = helpers.create_opay_wallet(o_client_auth_key, o_merchant_private_key, o_public_key, o_merchant_id, self)
        wallet = self.env["opay.wallet"].create(
            {
                "partner_id": self.id,
                "name": self.name,
                "reference": response_data["data"]["refId"],
                "account_number": response_data["data"]["depositCode"],
            }
        )
        self.wallet_id = wallet.id
        self.message_post(body="Opay wallet created successfully.")
