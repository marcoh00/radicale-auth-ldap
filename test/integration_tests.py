# -*- coding: utf-8 -*-

import logging
import unittest

import radicale_auth_ldap
from test.configuration import TEST_CONFIGURATION, VALID_USER, VALID_PASS
from test.util import ConfigMock


class Authentication(unittest.TestCase):
    configuration = None
    logger = None

    @classmethod
    def setUpClass(cls):
        cls.configuration = ConfigMock(TEST_CONFIGURATION)
        cls.logger = logging.getLogger(__name__)

    def test_authentication_works(self):
        auth = radicale_auth_ldap.Auth(self.__class__.configuration, self.__class__.logger)
        self.assertTrue(auth.is_authenticated(VALID_USER, VALID_PASS))


if __name__ == '__main__':
    unittest.main()
