# VULNERABLE: FileTempFileInsecure — tempfile.mktemp() creates a race condition (TOCTOU)
# Rule: FileTempFileInsecureTemplate | CWE-377 | Severity: MEDIUM

import tempfile
import os
from flask import Flask, request

app = Flask(__name__)


@app.route('/api/process', methods=['POST'])
def process_upload():
    """Save uploaded data to a temporary file for processing."""
    data = request.data

    # <-- VULNERABLE: mktemp() returns a filename but does NOT create the file
    # Between mktemp() returning and the file being opened, an attacker can create
    # a symlink at that path pointing to a sensitive file (TOCTOU race condition).
    tmp_path = tempfile.mktemp(suffix='.tmp', prefix='upload_')

    with open(tmp_path, 'wb') as f:
        f.write(data)

    # Process the file...
    result = _process_file(tmp_path)

    os.unlink(tmp_path)
    return result


def _process_file(path):
    with open(path, 'rb') as f:
        return f'Processed {len(f.read())} bytes'


if __name__ == '__main__':
    app.run()
