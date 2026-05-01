# VULNERABLE: DjangoDebugTrue — DEBUG = True exposes stack traces and internal config to attackers
# Rule: DjangoDebugTrueTemplate | CWE-215 | Severity: HIGH

import os

# Django settings file — DEBUG left on in production
# This exposes full stack traces, local variables, and settings to any visitor on error pages.

SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'fallback-key')

DEBUG = True  # <-- VULNERABLE: must be False in production

ALLOWED_HOSTS = ['localhost', '127.0.0.1']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'myapp',
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(os.path.dirname(__file__), 'db.sqlite3'),
    }
}
