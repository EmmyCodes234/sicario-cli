# VULNERABLE: SqlStringConcat — user input concatenated directly into SQL query string
# Rule: SqlStringConcatTemplate | CWE-89 | Severity: CRITICAL

import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)
DB_PATH = 'users.db'


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route('/api/users/<user_id>', methods=['GET'])
def get_user(user_id):
    """Fetch a user by ID."""
    conn = get_db()
    cursor = conn.cursor()

    # <-- VULNERABLE: user_id is concatenated directly into the SQL string
    # An attacker can pass: 1 OR 1=1 -- to dump all users
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)

    row = cursor.fetchone()
    conn.close()

    if row is None:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'id': row[0], 'username': row[1], 'email': row[2]})


if __name__ == '__main__':
    app.run()
