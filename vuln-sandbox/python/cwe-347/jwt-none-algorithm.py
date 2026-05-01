# VULNERABLE: CryptoJwtNoneAlgorithm — JWT decoded with verify_signature=False and algorithm='none'
# Rule: CryptoJwtNoneAlgorithmTemplate | CWE-347 | Severity: CRITICAL

import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route('/api/auth/verify', methods=['POST'])
def verify_token():
    """Verify a JWT and return the decoded claims."""
    data = request.get_json()
    token = data.get('token', '')

    # <-- VULNERABLE: signature verification disabled — any token is accepted as valid
    # An attacker can craft a token with algorithm='none' and arbitrary claims (e.g., admin: true)
    # and it will be accepted without any cryptographic check
    decoded = jwt.decode(
        token,
        options={"verify_signature": False},
        algorithms=['none'],
    )

    return jsonify({
        'user_id': decoded.get('sub'),
        'role': decoded.get('role'),
        'valid': True,
    })


if __name__ == '__main__':
    app.run()
