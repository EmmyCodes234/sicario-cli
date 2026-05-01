# VULNERABLE: CryptoPbkdf2LowIterations — PBKDF2 called with only 1000 iterations (far below minimum)
# Rule: CryptoPbkdf2LowIterationsTemplate | CWE-916 | Severity: HIGH

import hashlib
import os
from flask import Flask, request, jsonify

app = Flask(__name__)


def hash_password(password: str) -> dict:
    """Hash a password using PBKDF2-HMAC-SHA256."""
    salt = os.urandom(16)

    # <-- VULNERABLE: 1000 iterations is ~310x below the OWASP 2023 minimum of 310,000
    # A modern GPU can crack this in seconds using offline dictionary attacks
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 1000)

    return {
        'salt': salt.hex(),
        'hash': dk.hex(),
        'iterations': 1000,
    }


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    password = data.get('password', '')
    hashed = hash_password(password)
    # Store hashed['salt'] and hashed['hash'] in the database...
    return jsonify({'status': 'registered', 'iterations': hashed['iterations']})


if __name__ == '__main__':
    app.run()
