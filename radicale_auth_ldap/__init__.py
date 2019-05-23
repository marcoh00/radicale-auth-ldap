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

import radicale_auth_ldap.ldap3imports


class Auth(BaseAuth):
    def is_authenticated(self, user, password):
        """Check if ``user``/``password`` couple is valid."""
        SERVER = ldap3.Server(self.configuration.get("auth", "ldap_url"))
        BASE = self.configuration.get("auth", "ldap_base")
        ATTRIBUTE = self.configuration.get("auth", "ldap_attribute")
        FILTER = self.configuration.get("auth", "ldap_filter")
        BINDDN = self.configuration.get("auth", "ldap_binddn")
        PASSWORD = self.configuration.get("auth", "ldap_password")
        SCOPE = self.configuration.get("auth", "ldap_scope")
        SUPPORT_EXTENDED = self.configuration.getboolean("auth", "ldap_support_extended", fallback=True)
        
        if BINDDN and PASSWORD:
            conn = ldap3.Connection(SERVER, BINDDN, PASSWORD)
        else:
            conn = ldap3.Connection(SERVER)
        conn.bind()

        try:
            self.logger.debug("LDAP whoami: %s" % conn.extend.standard.who_am_i())
        except Exception as err:
            self.logger.debug("LDAP error: %s" % err)

        distinguished_name = "%s=%s" % (ATTRIBUTE, ldap3imports.escape_attribute_value(user))
        self.logger.debug("LDAP bind for %s in base %s" % (distinguished_name, BASE))

        if FILTER:
            filter_string = "(&(%s)%s)" % (distinguished_name, FILTER)
        else:
            filter_string = distinguished_name
        self.logger.debug("LDAP filter: %s" % filter_string)

        conn.search(search_base=BASE,
                    search_scope=SCOPE,
                    search_filter=filter_string,
                    attributes=[ATTRIBUTE])

        users = conn.response

        if users:
            user_dn = users[0]['dn']
            uid = users[0]['attributes'][ATTRIBUTE]
            self.logger.debug("LDAP user %s (%s) found" % (uid, user_dn))
            try:
                conn = ldap3.Connection(SERVER, user_dn, password)
                conn.bind()
                self.logger.debug(conn.result)
                if SUPPORT_EXTENDED:
                    whoami = conn.extend.standard.who_am_i()
                    self.logger.debug("LDAP whoami: %s" % whoami)
                else:
                    self.logger.debug("LDAP skip extended: call whoami")
                    whoami = conn.result['result'] == 0
                if whoami:
                    self.logger.debug("LDAP bind OK")
                    return True
                else:
                    self.logger.debug("LDAP bind failed")
                    return False
            except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
                self.logger.debug("LDAP invalid credentials")
            except Exception as err:
                self.logger.debug("LDAP error %s" % err)
            return False
        else:
            self.logger.debug("LDAP user %s not found" % user)
            return False
