# -*- coding: utf-8 -*-
#
# This file is part of Radicale Server - Calendar Server
# Copyright © 2011 Corentin Le Bail
# Copyright © 2011-2013 Guillaume Ayoub
# Copyright © 2015 Raoul Thill
# Copyright © 2017 Marco Huenseler
# Copyright © 2020 Johannes Zellner
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Radicale.  If not, see <http://www.gnu.org/licenses/>.

"""
LDAP authentication.
Authentication based on the ``ldap3`` module
(https://github.com/cannatag/ldap3/).
"""

import ldap3

from radicale.auth import BaseAuth
from radicale.log import logger

PLUGIN_CONFIG_SCHEMA = {
    "auth": {
        "password": {
            "value": "",
            "type": str
        },
        "ldap_url": {
            "value": "ldap://localhost:389",
            "help": "LDAP server URL, with protocol and port",
            "type": str
        },
        "ldap_base": {
            "value": "ou=users,dc=example",
            "help": "LDAP base DN for users",
            "type": str
        },
        "ldap_filter": {
            "value": "(&(objectclass=user)(username=%username))",
            "help": "LDAP search filter to find login user",
            "type": str
        },
        "ldap_attribute": {
            "value": "username",
            "help": "LDAP attribute to uniquely identify the user",
            "type": str
        },
        "ldap_binddn": {
            "value": "",
            "help": "LDAP dn used if server does not allow anonymous search",
            "type": str
        },
        "ldap_password": {
            "value": "",
            "help": "LDAP password used with ldap_binddn",
            "type": str
        }
    }
}


class Auth(BaseAuth):
    ldap_url = ""
    ldap_base = ""
    ldap_filter = ""
    ldap_attribute = ""
    ldap_binddn = ""
    ldap_password = ""

    def __init__(self, configuration):
        super().__init__(configuration.copy(PLUGIN_CONFIG_SCHEMA))

        options = configuration.options("auth")

        if "ldap_url" not in options: raise RuntimeError("The ldap_url configuration for ldap auth is required.")
        if "ldap_base" not in options: raise RuntimeError("The ldap_base configuration for ldap auth is required.")
        if "ldap_filter" not in options: raise RuntimeError("The ldap_filter configuration for ldap auth is required.")
        if "ldap_attribute" not in options: raise RuntimeError("The ldap_attribute configuration for ldap auth is required.")
        if "ldap_binddn" not in options: raise RuntimeError("The ldap_binddn configuration for ldap auth is required.")
        if "ldap_password" not in options: raise RuntimeError("The ldap_password configuration for ldap auth is required.")

        # also get rid of trailing slashes which are typical for uris
        self.ldap_url = configuration.get("auth", "ldap_url").rstrip("/")
        self.ldap_base = configuration.get("auth", "ldap_base")
        self.ldap_filter = configuration.get("auth", "ldap_filter")
        self.ldap_attribute = configuration.get("auth", "ldap_attribute")
        self.ldap_binddn = configuration.get("auth", "ldap_binddn")
        self.ldap_password = configuration.get("auth", "ldap_password")

        logger.info("LDAP auth configuration:")
        logger.info("  %r is %r", "ldap_url", self.ldap_url)
        logger.info("  %r is %r", "ldap_base", self.ldap_base)
        logger.info("  %r is %r", "ldap_filter", self.ldap_filter)
        logger.info("  %r is %r", "ldap_attribute", self.ldap_attribute)
        logger.info("  %r is %r", "ldap_binddn", self.ldap_binddn)
        logger.info("  %r is %r", "ldap_password", self.ldap_password)

    def login(self, login, password):
        if login == "" or password == "":
            return ""

        server = ldap3.Server(self.ldap_url, get_info=ldap3.ALL)
        conn = ldap3.Connection(server=server, user=self.ldap_binddn,
                                password=self.ldap_password, check_names=True,
                                lazy=False, raise_exceptions=False)
        conn.open()
        conn.bind()

        if conn.result["result"] != 0:
            logger.error(conn.result)
            return ""

        final_search_filter = self.ldap_filter.replace("%username", login)
        conn.search(search_base=self.ldap_base,
                    search_filter=final_search_filter,
                    attributes=ldap3.ALL_ATTRIBUTES)

        if conn.result["result"] != 0:
            logger.error(conn.result)
            return ""

        if len(conn.response) == 0:
            return ""

        final_user_dn = conn.response[0]["dn"]
        conn.unbind()

        # new connection to check the password as we cannot rebind here
        conn = ldap3.Connection(server=server, user=final_user_dn,
                                password=password, check_names=True,
                                lazy=False, raise_exceptions=False)
        conn.open()
        conn.bind()

        if conn.result["result"] != 0:
            logger.error(conn.result)
            return ""

        return login
