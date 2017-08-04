# -*- coding: utf-8 -*-

import logging

import radicale_auth_ldap
from test.configuration import TEST_CONFIGURATION, VALID_USER, VALID_PASS
from test.util import ConfigMock


def main():
    configuration = ConfigMock(TEST_CONFIGURATION)
    logger = logging.getLogger(__name__)
    auth = radicale_auth_ldap.Auth(configuration, logger)
    assert auth.is_authenticated(VALID_USER, VALID_PASS)

if __name__ == '__main__':
    main()
