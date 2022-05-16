# -*- coding: utf-8 -*-
#
# This file is part of Radicale Server - Calendar Server
# Copyright © 2011 Corentin Le Bail
# Copyright © 2011-2013 Guillaume Ayoub
# Copyright © 2015 Raoul Thill
# Copyright © 2017 Marco Huenseler
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
import ldap3.core.exceptions

from radicale.auth import BaseAuth
from radicale.log import logger

import radicale_auth_ldap.ldap3imports


PLUGIN_CONFIG_SCHEMA = {
    "auth": {
        "ldap_url": {
            "value": "ldap://localhost:389",
            "help": "LDAP server URL, with protocol and port (multiple servers can be separated by spaces)",
            "type": str
        },
        "ldap_base": {
            "value": "ou=users,dc=example,dc=com",
            "help": "LDAP base path when searching for users",
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
        },
        "ldap_scope": {
            "value": "LEVEL",
            "help": "scope of the search, either BASE, LEVEL or SUBTREE",
            "type": str
        },
        "ldap_support_extended": {
            "value": True,
            "help": "",
            "type": bool
        }
    }
}


class Auth(BaseAuth):

    ldap_url = ""
    ldap_base = ""
    ldap_filter = ""
    ldap_attribute = "user"
    ldap_binddn = ""
    ldap_password = ""
    ldap_scope = "LEVEL"
    ldap_support_extended = True

    def __init__(self, configuration):
        super().__init__(configuration.copy(PLUGIN_CONFIG_SCHEMA))

        options = configuration.options("auth")

        if "ldap_url" not in options: raise RuntimeError("The ldap_url configuration for ldap auth is required.")
        if "ldap_base" not in options: raise RuntimeError("The ldap_base configuration for ldap auth is required.")

        # also get rid of trailing slashes which are typical for uris
        self.ldap_url = configuration.get("auth", "ldap_url").rstrip("/")
        self.ldap_base = configuration.get("auth", "ldap_base")
        try:
            self.ldap_filter = configuration.get("auth", "ldap_filter")
        except KeyError:
                pass
        try:
            self.ldap_attribute = configuration.get("auth", "ldap_attribute")
        except KeyError:
                pass
        try:
            self.ldap_binddn = configuration.get("auth", "ldap_binddn")
        except KeyError:
                pass
        try:
            self.ldap_password = configuration.get("auth", "ldap_password")
        except KeyError:
                pass
        try:
            self.ldap_scope = configuration.get("auth", "ldap_scope")
        except KeyError:
                pass
        try:
            self.ldap_support_extended = configuration.get("auth", "ldap_support_extended")
        except KeyError:
                pass

        logger.info("LDAP auth configuration:")
        logger.info("  %r is %r", "ldap_url", self.ldap_url)
        logger.info("  %r is %r", "ldap_base", self.ldap_base)
        logger.info("  %r is %r", "ldap_filter", self.ldap_filter)
        logger.info("  %r is %r", "ldap_attribute", self.ldap_attribute)
        logger.info("  %r is %r", "ldap_binddn", self.ldap_binddn)
        logger.info("  %r is %r", "ldap_password", self.ldap_password)
        logger.info("  %r is %r", "ldap_scope", self.ldap_scope)
        logger.info("  %r is %r", "ldap_support_extended", self.ldap_support_extended)

    def login(self, login, password):
        """Check if ``login``/``password`` couple is valid."""
        servers = self.configuration.get("auth", "ldap_url")
        if ' ' in servers:  # Handle for multiple LDAP server defined in ldap_url with space separation
            servers = servers.split(' ')
            logger.debug("Multiple servers: %s" % servers)
            SERVER = ldap3.ServerPool(None)
            for s in servers:
                SERVER.add(ldap3.Server(s))
        else:  # only one server is defined
            logger.debug("Single server: %s" % servers)
            SERVER = ldap3.Server(servers)
        if self.ldap_binddn and self.ldap_password:
            conn = ldap3.Connection(SERVER, self.ldap_binddn, self.ldap_password)
        else:
            conn = ldap3.Connection(SERVER)
        conn.bind()

        try:
            logger.debug("LDAP whoami: %s" % conn.extend.standard.who_am_i())
        except Exception as err:
            logger.error("LDAP error: %s" % err)

        distinguished_name = "%s=%s" % (self.ldap_attribute, ldap3imports.escape_attribute_value(login))
        logger.debug("LDAP bind for %s in base %s" % (distinguished_name, self.ldap_base))

        if self.ldap_filter:
            filter_string = "(&(%s)%s)" % (distinguished_name, self.ldap_filter)
        else:
            filter_string = distinguished_name
        logger.debug("LDAP filter: %s" % filter_string)

        conn.search(search_base=self.ldap_base,
                    search_scope=self.ldap_scope,
                    search_filter=filter_string,
                    attributes=[self.ldap_attribute])

        users = conn.response
        conn.unbind()

        if users:
            user_dn = users[0]['dn']
            uid = users[0]['attributes'][self.ldap_attribute]
            logger.info("LDAP user %s (%s) found" % (uid, user_dn))
            try:
                conn = ldap3.Connection(SERVER, user_dn, password)
                conn.bind()
                logger.debug(conn.result)
                if self.ldap_support_extended:
                    whoami = conn.extend.standard.who_am_i()
                    logger.debug("LDAP whoami: %s" % whoami)
                else:
                    logger.debug("LDAP skip extended: call whoami")
                    whoami = conn.result['result'] == 0
                conn.unbind()
                if whoami:
                    logger.info("LDAP bind OK")
                    return login
                else:
                    logger.error("LDAP bind failed")
                    return ""
            except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
                logger.error("LDAP invalid credentials")
            except Exception as err:
                logger.error("LDAP error %s" % err)
            return ""
        else:
            logger.error("LDAP user %s not found" % user)
            return ""
