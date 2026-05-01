# VULNERABLE: PyRequestsVerifyFalse — SSL certificate verification disabled in requests call
# Rule: PyRequestsVerifyFalseTemplate | CWE-295 | Severity: HIGH

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

PAYMENT_API = 'https://payments.internal.example.com'


@app.route('/api/payment/charge', methods=['POST'])
def charge():
    """Forward a charge request to the internal payment service."""
    data = request.get_json()

    # <-- VULNERABLE: verify=False disables TLS certificate validation
    # Enables man-in-the-middle attacks — attacker can intercept payment data
    response = requests.post(
        f'{PAYMENT_API}/v1/charge',
        json=data,
        verify=False,  # <-- VULNERABLE
        timeout=10,
    )

    return jsonify(response.json()), response.status_code


if __name__ == '__main__':
    app.run()
