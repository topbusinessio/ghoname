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
        #'data/customer_code_sequence.xml',  # ✅ Add this line
        'views/sale_order_view.xml',
        #'views/partner_views.xml',          # ✅ (If you have view code for res.partner, add it too)
    ],
    'installable': True,
    'application': True,
    'auto_install': False,
    'license': 'LGPL-3',
}
