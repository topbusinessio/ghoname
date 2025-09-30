# -*- coding: utf-8 -*-
{
    'name': 'Opay Wallet',
    'version': '1.0',
    'category': 'Accounting',
    'summary': 'Opay Wallet Integration for Odoo | Automatically assign wallet account and record payments to Opay Wallet',
    'author': 'Ewetoye Ibrahim',
    'depends': ['sale_management'],
    'data': [
        'data/opay_wallet_data.xml',
        'views/account_payment.xml',
        'views/wallet_view.xml',
        'views/res_config_settings_views.xml',
        'views/res_partner_views.xml',
        'views/res_partner_form.xml',               # 👈 NEW: full-width email & phone
        'views/sale_order_inherit_opay.xml',       # show wallet in quotation/delivery address
        'security/ir.model.access.csv',
    ],
    'qweb': [],
    'installable': True,
    'application': True,
    'license': 'OPL-1',
    'external_dependencies': {
        'python': ['pycryptodome'],
    },
}
