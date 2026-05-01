# VULNERABLE: CryptoInsecureRandomSeed — random.seed(0) makes the PRNG fully deterministic
# Rule: CryptoInsecureRandomSeedTemplate | CWE-335 | Severity: HIGH

import random
import string
from flask import Flask, jsonify

app = Flask(__name__)


def generate_token(length: int = 32) -> str:
    """Generate a random token for password reset or API access."""
    # <-- VULNERABLE: seeding with a constant integer makes all generated tokens predictable
    # An attacker who knows the seed can reproduce every token ever generated
    random.seed(0)

    alphabet = string.ascii_letters + string.digits
    return ''.join(random.choice(alphabet) for _ in range(length))


def generate_otp() -> str:
    """Generate a 6-digit one-time password."""
    random.seed(0)  # <-- VULNERABLE
    return str(random.randint(100000, 999999))


@app.route('/api/auth/reset-token', methods=['POST'])
def issue_reset_token():
    token = generate_token()
    return jsonify({'reset_token': token})


if __name__ == '__main__':
    app.run()
