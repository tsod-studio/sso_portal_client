"""Minimal Django settings for the test suite (sqlite, in-memory)."""

from pathlib import Path

from sso_portal_client.conf import provider_config

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'test-only-secret-key'
DEBUG = False
USE_TZ = True
TIME_ZONE = 'UTC'
ROOT_URLCONF = 'tests.urls'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.openid_connect',
    'sso_portal_client',
]

MIDDLEWARE = [
    # SecurityMiddleware is included (rather than left out like most of this
    # minimal test settings module) specifically so
    # tests/test_middleware.py can exercise the real COOP-header precedence
    # rule documented in sso_portal_client/middleware.py — PortalSwitchMiddleware
    # is placed AFTER it, per that module's docstring.
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    'sso_portal_client.middleware.PortalSwitchMiddleware',
]

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'tests' / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.contrib.auth.context_processors.auth',
                'django.template.context_processors.request',
                'sso_portal_client.context_processors.portal_user',
            ],
        },
    }
]

AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
]

SSO_PORTAL_CLIENT = {
    'SERVER_URL': 'http://127.0.0.1:8000/o',
    'CLIENT_ID': 'test-client-id',
    'CLIENT_SECRET': 'test-client-secret',
}

# Needed for the {% portal_switch_widget %} tag's server-side loginUrl
# (allauth's get_provider()/get_login_url()) — see test_templatetags.py.
SOCIALACCOUNT_PROVIDERS = {'openid_connect': provider_config()}
