# VULNERABLE: CryptoHardcodedSalt — bcrypt called with a hardcoded literal salt
# Rule: CryptoHardcodedSaltTemplate | CWE-760 | Severity: HIGH

import bcrypt
from flask import Flask, request, jsonify

app = Flask(__name__)

# <-- VULNERABLE: hardcoded salt means all passwords share the same salt
# Identical passwords produce identical hashes, enabling precomputed table attacks
# A real salt must be randomly generated per-password via bcrypt.gensalt()
HARDCODED_SALT = b"$2b$12$hardcodedsaltXXXXXXXXXX"


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    password = data.get('password', '').encode()

    # <-- VULNERABLE: using a static salt defeats the purpose of salting
    hashed = bcrypt.hashpw(password, HARDCODED_SALT)

    # Store hashed in database...
    return jsonify({'status': 'registered', 'hash': hashed.decode()})


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    password = data.get('password', '').encode()
    stored_hash = data.get('stored_hash', '').encode()

    if bcrypt.checkpw(password, stored_hash):
        return jsonify({'status': 'authenticated'})
    return jsonify({'error': 'Invalid credentials'}), 401


if __name__ == '__main__':
    app.run()
