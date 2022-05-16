#!/usr/bin/env python3

from distutils.core import setup

setup(
    name="radicale-auth-ldap",
    version="0.3",
    description="LDAP Authentication Plugin for Radicale 3",
    author="Raoul Thill",
    license="GNU GPL v3",
    install_requires=["radicale >= 3.0", "ldap3 >= 2.3"],
    packages=["radicale_auth_ldap"])
