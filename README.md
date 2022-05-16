# What is this?
This is an authentication plugin for Radicale 3. It adds an LDAP authentication backend which can be used for authenticating users against an LDAP server.

Use the `2-final` git tag for Radicale 2 support.

# How to configure
You will need to set a few options inside your radicale config file. Example:

```
[auth]
type = radicale_auth_ldap

# LDAP server URL, with protocol and port (multiple servers can be separated by spaces)
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
# If the server is samba, ldap_support_extended should be no
ldap_support_extended = yes
```

## SELinux considerations
If you use SELinux, you will need to add a few rules. To install `radicale-auth-ldap.te`, use these commands.

    sudo checkmodule -M -m -o radicale-auth-ldap.mod radicale-auth-ldap.te && sudo semodule_package -o radicale-auth-ldap.pp -m radicale-auth-ldap.mod && sudo semodule -i radicale-auth-ldap.pp

You will need packages to run the above commands:

* checkpolicy
* policycoreutils-python (CentOS 7)
* policycoreutils (CentOS 7, AlmaLinux 8, Fedora)
