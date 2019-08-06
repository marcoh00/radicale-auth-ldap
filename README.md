# What is this?
This is an authentication plugin for Radicale 2. It adds an LDAP authentication backend which can be used for authenticating users against an LDAP server.

# How to configure
You will need to set a few options inside your radicale config file. Example:

```
[auth]
type = radicale_auth_ldap

# LDAP server URL, with protocol and port
ldap_url = ldap://ldap:389

# LDAP base path
ldap_base = ou=Users,dc=TESTDOMAIN

# LDAP login attribute
ldap_attribute = uid

# LDAP filter string
# placed as X in a query of the form (&(...)X)
# example: (objectCategory=Person)(objectClass=User)(memberOf=cn=calenderusers,ou=users,dc=example,dc=org)
ldap_filter = (objectClass=person)

# LDAP dn for initial login, used if LDAP server does not allow anonymous searches
# Leave empty if searches are anonymous
ldap_binddn = cn=admin,dc=TESTDOMAIN

# LDAP password for initial login, used with ldap_binddn
ldap_password = verysecurepassword

# LDAP scope of the search
ldap_scope = LEVEL

# LDAP extended option
# If the server is samba, ldap_support_extended is should be no
ldap_support_extended = yes
```
