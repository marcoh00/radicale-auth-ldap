# -*- coding: utf-8 -*-

import unittest

import radicale_auth_ldap


class References(unittest.TestCase):
    def test_invalid_credentials_exception_exists(self):
        successful_test = False

        try:
            import ldap3.core.exceptions
        except ImportError:
            self.fail('ldap3 module was not found at all!')
        try:
            raise ldap3.core.exceptions.LDAPInvalidCredentialsResult()
        except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
            successful_test = True

        self.assertTrue(successful_test)