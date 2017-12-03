# -*- coding: utf-8 -*-

TEST_CONFIGURATION = {
    'auth': {
        'ldap_url': 'ldap://',
        'ldap_base': 'ou=xxx,dc=xxx,dc=xx',
        'ldap_attribute': 'uid',
        'ldap_filter': '(objectClass=person)',
        'ldap_binddn': 'cn=xxx,dc=xxx,dc=xx',
        'ldap_password': '',
        'ldap_scope': 'LEVEL'
    }
}

VALID_USER = 'xxx'
VALID_PASS = 'xxx'
