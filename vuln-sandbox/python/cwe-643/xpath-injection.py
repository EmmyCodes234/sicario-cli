# VULNERABLE: InjectXpath — XPath query built with f-string containing user input
# Rule: InjectXpathTemplate | CWE-643 | Severity: HIGH

from lxml import etree
from flask import Flask, request, jsonify

app = Flask(__name__)

# Sample XML document (in production this would be loaded from a file or DB)
XML_DATA = b"""
<users>
  <user id="1"><name>Alice</name><role>admin</role></user>
  <user id="2"><name>Bob</name><role>user</role></user>
  <user id="3"><name>Charlie</name><role>user</role></user>
</users>
"""


@app.route('/api/users/find', methods=['GET'])
def find_user():
    """Find a user by name using XPath."""
    name = request.args.get('name', '')

    tree = etree.fromstring(XML_DATA)

    # <-- VULNERABLE: user input embedded in XPath expression via f-string
    # An attacker can pass: ' or '1'='1 to match all users and bypass access controls
    xpath_query = f"//user[name='{name}']"
    results = tree.xpath(xpath_query)

    users = [{'id': node.get('id'), 'name': node.findtext('name'), 'role': node.findtext('role')}
             for node in results]
    return jsonify({'users': users})


if __name__ == '__main__':
    app.run()
