# VULNERABLE: DjangoAllowedHostsWildcard — ALLOWED_HOSTS = ['*'] accepts requests from any host
# Rule: DjangoAllowedHostsWildcardTemplate | CWE-183 | Severity: HIGH

import os

# Django settings file — wildcard in ALLOWED_HOSTS disables host header validation
# Enables HTTP Host header injection attacks and DNS rebinding.

SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
DEBUG = False

ALLOWED_HOSTS = ['*']  # <-- VULNERABLE: accepts any Host header value

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
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DB_NAME', 'mydb'),
        'USER': os.environ.get('DB_USER', 'postgres'),
        'HOST': os.environ.get('DB_HOST', 'localhost'),
        'PORT': '5432',
    }
}
