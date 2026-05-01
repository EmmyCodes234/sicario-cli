# Test fixture: Django debug and secret key patterns
# Expected: TruePositive for DEBUG=True and hardcoded SECRET_KEY

# TP: DEBUG=True
DEBUG = True

# TN: DEBUG=False
# DEBUG = False

# TP: hardcoded SECRET_KEY
SECRET_KEY = "django-insecure-abc123xyz456"

# TN: SECRET_KEY from environment
# SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]

# TP: ALLOWED_HOSTS wildcard
ALLOWED_HOSTS = ["*"]

# TN: specific hosts
# ALLOWED_HOSTS = ["example.com"]
