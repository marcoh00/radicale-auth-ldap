#!/usr/bin/env python3

from setuptools import setup

setup(
    name="radicale-auth-ldap",
    version="0.1",
    description="LDAP Authentication Plugin for Radicale 2",
    author="Raoul Thill",
    license="GNU GPL v3",
    install_requires=["radicale >= 2.0", "ldap3 >= 2.3"],
    packages=["radicale_auth_ldap"])
