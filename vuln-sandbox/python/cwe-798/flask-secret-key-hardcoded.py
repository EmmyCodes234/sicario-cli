# VULNERABLE: FlaskSecretKeyHardcoded — app.secret_key is a hardcoded string literal
# Rule: FlaskSecretKeyHardcodedTemplate | CWE-798 | Severity: CRITICAL

from flask import Flask, session, request, redirect, url_for

app = Flask(__name__)

# <-- VULNERABLE: hardcoded secret key committed to version control
# Allows attackers to forge session cookies and impersonate any user.
app.secret_key = 'hardcoded-secret'


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    if username == 'admin' and password == 'password':
        session['user'] = username
        return redirect(url_for('dashboard'))
    return 'Invalid credentials', 401


@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return f"Welcome, {session['user']}!"


if __name__ == '__main__':
    app.run()
