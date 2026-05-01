# VULNERABLE: FilePermissionsWorldWritable — os.chmod sets world-writable permissions (0o777)
# Rule: FilePermissionsWorldWritableTemplate | CWE-732 | Severity: HIGH

import os
import tempfile
from flask import Flask, request

app = Flask(__name__)

UPLOAD_DIR = '/var/app/uploads'


@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Save an uploaded file and make it accessible."""
    uploaded = request.files.get('file')
    if not uploaded:
        return 'No file provided', 400

    dest = os.path.join(UPLOAD_DIR, uploaded.filename)
    uploaded.save(dest)

    # <-- VULNERABLE: 0o777 grants read/write/execute to all users on the system
    # Any local user or process can overwrite, replace, or execute this file
    os.chmod(dest, 0o777)

    return f'Uploaded to {dest}', 200


if __name__ == '__main__':
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    app.run()
