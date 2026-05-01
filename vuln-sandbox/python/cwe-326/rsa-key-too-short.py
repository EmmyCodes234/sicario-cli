# VULNERABLE: CryptoRsaKeyTooShort — RSA key generated with only 1024 bits (below 2048 minimum)
# Rule: CryptoRsaKeyTooShortTemplate | CWE-326 | Severity: HIGH

from Crypto.PublicKey import RSA
from flask import Flask, jsonify

app = Flask(__name__)


def generate_signing_keypair():
    """Generate an RSA key pair for document signing."""
    # <-- VULNERABLE: 1024-bit RSA keys can be factored with modern hardware
    # NIST deprecated 1024-bit RSA in 2013; minimum is 2048 bits, recommended is 4096
    key = RSA.generate(1024)

    private_pem = key.export_key().decode()
    public_pem = key.publickey().export_key().decode()

    return private_pem, public_pem


@app.route('/api/keys/generate', methods=['POST'])
def create_keypair():
    private_key, public_key = generate_signing_keypair()
    # In production, private_key would be stored securely — never returned to client
    return jsonify({
        'public_key': public_key,
        'key_size': 1024,
    })


if __name__ == '__main__':
    app.run()
