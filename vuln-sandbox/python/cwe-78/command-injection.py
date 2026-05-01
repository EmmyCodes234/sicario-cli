# VULNERABLE: InjectPythonSubprocessShell — user input passed to subprocess with shell=True
# Rule: InjectPythonSubprocessShellTemplate | CWE-78 | Severity: CRITICAL

import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route('/api/ping', methods=['POST'])
def ping_host():
    """Ping a host provided by the user."""
    data = request.get_json()
    host = data.get('host', '')

    # <-- VULNERABLE: shell=True with user-controlled cmd enables arbitrary command execution
    # An attacker can pass: "8.8.8.8; rm -rf /" to run arbitrary shell commands
    cmd = f"ping -c 1 {host}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    return jsonify({
        'stdout': result.stdout,
        'stderr': result.stderr,
        'returncode': result.returncode,
    })


if __name__ == '__main__':
    app.run()
