# VULNERABLE: InjectLdap — LDAP filter built with string concatenation of user input
# Rule: InjectLdapTemplate | CWE-90 | Severity: HIGH

import ldap
from flask import Flask, request, jsonify

app = Flask(__name__)

LDAP_SERVER = 'ldap://ldap.example.com'
LDAP_BASE_DN = 'dc=example,dc=com'


@app.route('/api/users/search', methods=['GET'])
def search_user():
    """Search for a user in the LDAP directory."""
    username = request.args.get('username', '')

    conn = ldap.initialize(LDAP_SERVER)
    conn.simple_bind_s('cn=admin,dc=example,dc=com', 'adminpassword')

    # <-- VULNERABLE: username concatenated directly into LDAP filter string
    # An attacker can pass: *)(uid=*))(|(uid=* to bypass authentication or dump all users
    ldap_filter = '(uid=' + username + ')'

    results = conn.search_s(LDAP_BASE_DN, ldap.SCOPE_SUBTREE, ldap_filter, ['cn', 'mail'])
    conn.unbind_s()

    users = [{'dn': dn, 'cn': attrs.get('cn', [b''])[0].decode()} for dn, attrs in results]
    return jsonify({'users': users})


if __name__ == '__main__':
    app.run()
