# VULNERABLE: FlaskDebugTrue — app.run(debug=True) enables the Werkzeug debugger in production
# Rule: FlaskDebugTrueTemplate | CWE-215 | Severity: HIGH

from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route('/api/users', methods=['GET'])
def list_users():
    """Return a list of users."""
    return jsonify({'users': ['alice', 'bob', 'charlie']})


@app.route('/api/echo', methods=['POST'])
def echo():
    """Echo back the request body."""
    data = request.get_json()
    return jsonify(data)


if __name__ == '__main__':
    # <-- VULNERABLE: debug=True exposes an interactive debugger with arbitrary code execution
    # The Werkzeug debugger PIN can be brute-forced, giving full RCE on the server.
    app.run(debug=True, host='0.0.0.0', port=5000)
