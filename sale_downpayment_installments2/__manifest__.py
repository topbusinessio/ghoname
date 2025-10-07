{
    'name': 'Sale Down Payment & Installments2',
    'version': '1.0',
    'summary': 'Enables down payments and flexible installment plans on sale orders',
    'category': 'Sales',
    'depends': [
        'sale_management',
        'account',
        'mail',
    ],
    'author': 'Ghonim Moon Ltd',
    'data': [
        'security/ir.model.access.csv',
        'views/sale_order_view.xml',
    ],
    'installable': True,
    'application': True,
    'auto_install': False,
    'license': 'LGPL-3',
}
