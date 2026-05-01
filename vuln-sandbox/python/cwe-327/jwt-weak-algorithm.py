# VULNERABLE: CryptoJwtWeakAlgorithm — JWT signed with weak algorithm 'HS1'
# Rule: CryptoJwtWeakAlgorithmTemplate | CWE-327 | Severity: HIGH

import jwt
import os
from flask import Flask, request, jsonify

app = Flask(__name__)
SECRET = os.environ.get('JWT_SECRET', 'dev-secret')


@app.route('/api/auth/token', methods=['POST'])
def issue_token():
    """Issue a JWT for an authenticated user."""
    data = request.get_json()
    user_id = data.get('user_id')
    role = data.get('role', 'user')

    payload = {'sub': user_id, 'role': role}

    # <-- VULNERABLE: HS1 (HMAC-SHA1) is cryptographically weak
    # SHA-1 is broken; use HS256 (HMAC-SHA256) or RS256 at minimum
    token = jwt.encode(payload, SECRET, algorithm='HS1')

    return jsonify({'token': token})


@app.route('/api/auth/decode', methods=['POST'])
def decode_token():
    data = request.get_json()
    token = data.get('token', '')
    decoded = jwt.decode(token, SECRET, algorithms=['HS1'])  # <-- VULNERABLE
    return jsonify(decoded)


if __name__ == '__main__':
    app.run()
