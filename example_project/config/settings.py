"""Settings for the SampleStore demo relying party.

A minimal but real Django 6 project that proves the whole point of
``sso_portal_client``: an RP installs the app, wires ~5 lines, and every
portal login automatically maps the ``groups`` OIDC claim onto standard
Django groups — no sync code lives here.

Runs on ``localhost:9002`` (the Flask reference RP owns 9001; a distinct
host:port keeps the two demos' session cookies from colliding on one box).
"""

import os
from pathlib import Path

from sso_portal_client import provider_config

BASE_DIR = Path(__file__).resolve().parent.parent

# Dev-only literal secret — never do this in production; a real RP reads it
# from the environment. Safe here because DEBUG runs only on localhost.
SECRET_KEY = 'django-insecure-samplestore-demo-key-do-not-use-in-production'

DEBUG = True

ALLOWED_HOSTS = ['localhost', '127.0.0.1']

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.openid_connect',
    'sso_portal_client',
    'store',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'allauth.account.middleware.AccountMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    }
]

WSGI_APPLICATION = 'config.wsgi.application'

# DB-backed sessions (Django's default backend) are REQUIRED: back-channel
# logout works by deleting django_session rows, which a signed-cookie session
# cannot support.
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

AUTH_PASSWORD_VALIDATORS: list[dict] = []

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

SITE_ID = 1

AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
]

# --- allauth: portal is the ONLY login path ---------------------------------
# SOCIALACCOUNT_ONLY disables local (username/password) login and signup UI
# entirely — the sole way in is the SSO portal. It also flips email
# verification to "none" by default, which is what we want for a demo.
SOCIALACCOUNT_ONLY = True
# First portal login auto-creates the local user from the OIDC claims with no
# intermediate signup form (the portal already supplies username/email).
SOCIALACCOUNT_AUTO_SIGNUP = True
# Don't require an email at signup; the portal may issue tokens without one.
SOCIALACCOUNT_EMAIL_REQUIRED = False
ACCOUNT_EMAIL_VERIFICATION = 'none'
# Skip allauth's intermediate "Continue to SSO Portal" confirmation page so
# the login link jumps straight to the provider — smoother for a demo.
# Tradeoff: with LOGIN_ON_GET a plain GET starts the OAuth flow, so the link
# is not login-CSRF protected (an attacker could pre-initiate a login). That
# is acceptable for a localhost demo; a hardened RP would leave this False (or
# guard the link behind a POST) so login begins only from a CSRF-checked form.
SOCIALACCOUNT_LOGIN_ON_GET = True

LOGIN_REDIRECT_URL = '/'
ACCOUNT_LOGOUT_REDIRECT_URL = '/'
# Log out in one click (no interstitial confirmation) for the demo.
ACCOUNT_LOGOUT_ON_GET = False

# --- sso_portal_client: the whole integration -------------------------------
# CLIENT_SECRET comes from the environment (printed by the portal-side
# registration snippet in the README); the rest have dev defaults.
SSO_PORTAL_CLIENT = {
    'SERVER_URL': os.environ.get('SSO_SERVER_URL', 'http://127.0.0.1:8000/o'),
    'CLIENT_ID': os.environ.get('SSO_CLIENT_ID', 'samplestore-django'),
    'CLIENT_SECRET': os.environ.get('SSO_CLIENT_SECRET', ''),
    'GROUP_PREFIX': None,
    'STAFF_GROUPS': ['samplestore-admin'],
    # RP-initiated logout ("Log out everywhere"): the absolute URL the portal
    # sends the browser back to after ending its session. Must be registered as
    # a post_logout_redirect_uri on this app's portal OAuth2 Application (DOT
    # validates it). Also the local fallback if the portal is unreachable.
    'POST_LOGOUT_REDIRECT_URL': 'http://localhost:9002/',
}

SOCIALACCOUNT_PROVIDERS = {'openid_connect': provider_config()}
