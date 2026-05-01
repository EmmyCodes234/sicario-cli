# VULNERABLE: SsrfHttpGetUserInput — requests.get() called with a user-controlled URL
# Rule: SsrfHttpGetUserInputTemplate | CWE-918 | Severity: HIGH

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route('/api/fetch', methods=['POST'])
def fetch_url():
    """Fetch content from a URL provided by the user."""
    data = request.get_json()
    user_url = data.get('url', '')

    # <-- VULNERABLE: user_url passed directly to requests.get without validation
    # An attacker can pass: http://169.254.169.254/latest/meta-data/ to access AWS metadata
    # or http://internal-service:8080/admin to reach internal network services
    response = requests.get(user_url, timeout=5)

    return jsonify({
        'status_code': response.status_code,
        'content_type': response.headers.get('Content-Type'),
        'body': response.text[:1000],
    })


if __name__ == '__main__':
    app.run()
