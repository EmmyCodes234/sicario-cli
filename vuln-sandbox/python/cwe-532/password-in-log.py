# VULNERABLE: AuthPasswordInLog — password value passed to logging call
# Rule: AuthPasswordInLogTemplate | CWE-532 | Severity: HIGH

import logging
from flask import Flask, request, jsonify

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@app.route('/api/login', methods=['POST'])
def login():
    """Authenticate a user with username and password."""
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')

    # <-- VULNERABLE: password written to log file in plaintext
    # Log files are often stored unencrypted, shipped to SIEM systems, and retained for years
    logger.info('Login attempt for user: %s', username)
    logging.info('password: %s', password)  # <-- VULNERABLE

    if _authenticate(username, password):
        logger.info('Login successful for user: %s', username)
        return jsonify({'status': 'authenticated'})

    logger.warning('Failed login for user: %s with password: %s', username, password)  # <-- VULNERABLE
    return jsonify({'error': 'Invalid credentials'}), 401


def _authenticate(username: str, password: str) -> bool:
    # Placeholder authentication logic
    return username == 'admin' and password == 'secret'


if __name__ == '__main__':
    app.run()
