# VULNERABLE: DjangoSecretKeyHardcoded — SECRET_KEY is a hardcoded literal in source code
# Rule: DjangoSecretKeyHardcodedTemplate | CWE-798 | Severity: CRITICAL

import os

# Django settings file — secret key committed to version control
# Anyone with repo access can forge session cookies, CSRF tokens, and signed data.

DEBUG = os.environ.get('DJANGO_DEBUG', 'False') == 'True'

SECRET_KEY = 'hardcoded-secret-key-value'  # <-- VULNERABLE: never commit real secret keys

ALLOWED_HOSTS = ['localhost', '127.0.0.1']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(os.path.dirname(__file__), 'db.sqlite3'),
    }
}
