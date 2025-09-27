# -*- coding: utf-8 -*-
{
    'name': 'Opay Wallet Generation',
    'version': '1.0',
    'category': 'Accounting',
    'summary': 'Automates Opay wallet generation, payments, and reconciliation',
    'description': """
Opay Wallet System:
- Automates wallet generation for customers
- Supports payments and reconciliation
- Dynamic configuration management (test/live)
    """,
    'author': 'EWetoye Ibrahim, Stephen',
    'depends': ['sale_management'],
    'data': [
        'data/opay_wallet_data.xml',
        # 'views/wallet_view.xml',
        'views/res_config_settings_views.xml',
        'views/res_partner_views.xml',
        'views/res_partner_form.xml',               # 👈 NEW: full-width email & phone
        'views/sale_order_inherit_opay.xml',       # show wallet in quotation/delivery address
        'security/ir.model.access.csv',
    ],
    'qweb': [],
    'installable': True,
    'application': True,
    'external_dependencies': {
        'python': ['pycryptodome'],
    },
}
