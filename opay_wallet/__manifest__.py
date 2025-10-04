# -*- coding: utf-8 -*-
{
    'name': 'Opay Wallet',
    'version': '1.0',
    'category': 'Accounting',
    'summary': 'Opay Wallet Integration for Odoo | Automatically assign wallet account and record payments to Opay Wallet',
    'author': 'Ewetoye Ibrahim',
    'depends': ['sale_management', 'account_payment'],
    'data': [
        'views/account_payment.xml',
        'views/res_config_settings_views.xml',
        'views/res_partner_views.xml',
        'views/sale_order_views.xml',
    ],
    'qweb': [],
    'installable': True,
    'application': True,
    'license': 'OPL-1',
    'external_dependencies': {
        'python': ['pycryptodome'],
    },
}
