# VULNERABLE: CryptoMd5PasswordHash — MD5 used to hash passwords (broken, no salt, fast to crack)
# Rule: CryptoMd5PasswordHashTemplate | CWE-916 | Severity: CRITICAL

import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)

# Simulated user store
USERS = {}


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')

    # <-- VULNERABLE: MD5 is cryptographically broken and unsuitable for password hashing
    # No salt means identical passwords produce identical hashes (rainbow table attacks)
    # MD5 can be computed at ~10 billion hashes/second on a GPU
    password_hash = hashlib.md5(password.encode()).hexdigest()

    USERS[username] = password_hash
    return jsonify({'status': 'registered'})


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')

    stored_hash = USERS.get(username)
    if stored_hash and stored_hash == hashlib.md5(password.encode()).hexdigest():
        return jsonify({'status': 'authenticated'})
    return jsonify({'error': 'Invalid credentials'}), 401


if __name__ == '__main__':
    app.run()
