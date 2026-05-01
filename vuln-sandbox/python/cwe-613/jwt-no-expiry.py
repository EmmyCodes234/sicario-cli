# VULNERABLE: AuthJwtNoExpiry — JWT payload issued without an 'exp' (expiration) claim
# Rule: AuthJwtNoExpiryTemplate | CWE-613 | Severity: HIGH

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

    # <-- VULNERABLE: no 'exp' claim means this token is valid forever
    # A stolen token can never be invalidated without rotating the signing secret
    payload = {
        'sub': str(user_id),
        'role': role,
        # Missing: 'exp': datetime.utcnow() + timedelta(hours=1)
    }

    token = jwt.encode(payload, SECRET, algorithm='HS256')
    return jsonify({'token': token})


@app.route('/api/profile', methods=['GET'])
def get_profile():
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '')
    decoded = jwt.decode(token, SECRET, algorithms=['HS256'])
    return jsonify({'user_id': decoded.get('sub'), 'role': decoded.get('role')})


if __name__ == '__main__':
    app.run()
