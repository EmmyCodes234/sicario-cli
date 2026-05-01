# VULNERABLE: FlaskSqlAlchemyUriHardcoded — database credentials embedded in URI literal
# Rule: FlaskSqlAlchemyUriHardcodedTemplate | CWE-798 | Severity: CRITICAL

from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# <-- VULNERABLE: database credentials hardcoded in source — visible in version control and logs
SQLALCHEMY_DATABASE_URI = 'postgresql://user:password@host/db'
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()
