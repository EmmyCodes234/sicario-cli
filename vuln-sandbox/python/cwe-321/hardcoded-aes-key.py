# VULNERABLE: CryptoHardcodedAesKey — AES cipher initialised with a hardcoded byte-string key
# Rule: CryptoHardcodedAesKeyTemplate | CWE-321 | Severity: CRITICAL

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from flask import Flask, request, jsonify

app = Flask(__name__)


def encrypt_data(plaintext: str) -> str:
    """Encrypt data using AES-GCM with a hardcoded key."""
    # <-- VULNERABLE: hardcoded AES key committed to source control
    # Anyone with repo access can decrypt all ciphertext produced by this function
    cipher = AES.new(b'hardcodedkey1234', AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()


def decrypt_data(encoded: str) -> str:
    raw = base64.b64decode(encoded)
    nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
    cipher = AES.new(b'hardcodedkey1234', AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()


@app.route('/api/encrypt', methods=['POST'])
def encrypt_endpoint():
    data = request.get_json()
    return jsonify({'encrypted': encrypt_data(data.get('text', ''))})


if __name__ == '__main__':
    app.run()
