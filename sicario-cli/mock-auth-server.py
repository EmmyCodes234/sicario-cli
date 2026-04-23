#!/usr/bin/env python3
"""
Minimal mock OAuth 2.0 Device Flow auth server for testing `sicario login`.

Usage:
    python mock-auth-server.py

Then in another terminal:
    $env:SICARIO_CLOUD_AUTH_URL="http://localhost:9876"
    $env:SICARIO_CLOUD_URL="http://localhost:9876"
    cargo run --bin sicario -- login
"""

import json
import secrets
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

# In-memory state
pending_codes = {}  # device_code -> { user_code, verified, created_at, code_verifier_challenge }

class MockAuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # GET /approve?code=XXXX-YYYY  — simulate user approving in browser
        if self.path.startswith("/approve"):
            qs = parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            user_code = qs.get("code", [None])[0]
            if not user_code:
                self._json(400, {"error": "missing ?code= parameter"})
                return
            # Find and approve the matching device code
            for dc, info in pending_codes.items():
                if info["user_code"] == user_code:
                    info["verified"] = True
                    self._json(200, {"status": "approved", "user_code": user_code})
                    print(f"  [mock] Approved device code for user_code={user_code}")
                    return
            self._json(404, {"error": f"unknown user_code: {user_code}"})
            return

        # GET /api/v1/whoami — return mock user info
        if self.path == "/api/v1/whoami":
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                self._json(401, {"error": "unauthorized"})
                return
            self._json(200, {
                "username": "test-user",
                "email": "test@usesicario.xyz",
                "organization": "sicario-dev",
                "plan_tier": "Team",
            })
            return

        self._json(404, {"error": "not found"})

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode()
        params = parse_qs(body)

        # POST /oauth/device/code — initiate device flow
        if self.path == "/oauth/device/code":
            device_code = secrets.token_hex(20)
            user_code = f"{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}"
            pending_codes[device_code] = {
                "user_code": user_code,
                "verified": False,
                "created_at": time.time(),
            }
            resp = {
                "device_code": device_code,
                "user_code": user_code,
                "verification_uri": f"http://localhost:9876/approve?code={user_code}",
                "interval": 2,
                "expires_in": 300,
            }
            print(f"  [mock] Device flow started: user_code={user_code}")
            print(f"  [mock] Approve at: http://localhost:9876/approve?code={user_code}")
            self._json(200, resp)
            return

        # POST /oauth/token — poll for token
        if self.path == "/oauth/token":
            device_code = params.get("device_code", [None])[0]
            if not device_code or device_code not in pending_codes:
                self._json(400, {"error": "invalid_grant", "error_description": "unknown device_code"})
                return
            info = pending_codes[device_code]
            if not info["verified"]:
                self._json(200, {"error": "authorization_pending"})
                return
            # User approved — issue tokens
            access_token = f"mock_access_{secrets.token_hex(16)}"
            resp = {
                "access_token": access_token,
                "refresh_token": f"mock_refresh_{secrets.token_hex(16)}",
                "expires_in": 3600,
            }
            del pending_codes[device_code]
            print(f"  [mock] Token issued for user_code={info['user_code']}")
            self._json(200, resp)
            return

        self._json(404, {"error": "not found"})

    def _json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        print(f"  [mock] {args[0]}")

if __name__ == "__main__":
    port = 9876
    server = HTTPServer(("127.0.0.1", port), MockAuthHandler)
    print(f"Mock Sicario auth server running on http://localhost:{port}")
    print(f"")
    print(f"In another terminal, run:")
    print(f'  $env:SICARIO_CLOUD_AUTH_URL="http://localhost:{port}"')
    print(f'  $env:SICARIO_CLOUD_URL="http://localhost:{port}"')
    print(f"  cargo run --bin sicario -- login")
    print(f"")
    print(f"Then approve the code by visiting the URL shown in the CLI output.")
    print(f"Press Ctrl+C to stop.")
    print()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down mock server.")
