"""SocialAccountAdapter.populate_user: stable, collision-free RP usernames.

Constructs an unsaved SocialLogin the same way allauth's
``Provider.sociallogin_from_response`` does (account.uid/provider already
set before populate_user() runs) and calls the override directly — no OAuth
flow, no database, matching the `data` shape (extract_common_fields()'s
output) documented in adapters.py.
"""

import pytest
from allauth.socialaccount.models import SocialAccount, SocialLogin
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.test import RequestFactory, override_settings

from sso_portal_client.adapters import SocialAccountAdapter

User = get_user_model()

SUB = '3f7a9c2e-1c2b-4b7a-9d3e-9a1b2c3d4e5f'
COMMON_FIELDS = {
    'username': 'alice',
    'email': 'alice@example.com',
    'name': 'Alice Lin',
    'first_name': None,
    'last_name': None,
}


def make_sociallogin(provider='sso_portal', uid=SUB):
    user = User()
    account = SocialAccount(provider=provider, uid=uid)
    return SocialLogin(user=user, account=account)


def populate(sociallogin, data=None):
    request = RequestFactory().get('/')
    return SocialAccountAdapter().populate_user(request, sociallogin, dict(data or COMMON_FIELDS))


def test_portal_login_gets_sub_at_issuer_username():
    user = populate(make_sociallogin())
    assert user.username == f'{SUB}@127.0.0.1'


def test_super_still_maps_name_and_email():
    # Verifies DefaultSocialAccountAdapter.populate_user still runs first:
    # email and first/last name (split from `name`, since given_name/
    # family_name are absent here) are populated exactly as stock allauth
    # would, untouched by this override.
    user = populate(make_sociallogin())
    assert user.email == 'alice@example.com'
    assert user.first_name == 'Alice'
    assert user.last_name == 'Lin'


def test_given_family_name_win_over_splitting_name():
    data = {**COMMON_FIELDS, 'first_name': 'Alicia', 'last_name': 'L.'}
    user = populate(make_sociallogin(), data)
    assert user.first_name == 'Alicia'
    assert user.last_name == 'L.'


@override_settings(
    SSO_PORTAL_CLIENT={
        'SERVER_URL': 'http://127.0.0.1:8000/o',
        'CLIENT_ID': 'test-client-id',
        'USERNAME_STRATEGY': 'preferred_username',
    }
)
def test_legacy_strategy_keeps_preferred_username():
    user = populate(make_sociallogin())
    assert user.username == 'alice'


def test_non_portal_provider_untouched():
    user = populate(make_sociallogin(provider='google'))
    assert user.username == 'alice'


@override_settings(
    SSO_PORTAL_CLIENT={
        'SERVER_URL': 'http://127.0.0.1:8000/o',
        'CLIENT_ID': 'test-client-id',
        'USERNAME_STRATEGY': 'bogus',
    }
)
def test_unknown_strategy_raises():
    with pytest.raises(ImproperlyConfigured, match='USERNAME_STRATEGY'):
        populate(make_sociallogin())


@override_settings(
    SSO_PORTAL_CLIENT={
        'SERVER_URL': f'http://{"a" * 200}.example.com:8000/o',
        'CLIENT_ID': 'test-client-id',
    }
)
def test_over_max_length_raises_instead_of_truncating():
    with pytest.raises(ImproperlyConfigured, match='over the'):
        populate(make_sociallogin())


@override_settings(SSO_PORTAL_CLIENT={'SERVER_URL': 'not-a-url', 'CLIENT_ID': 'test-client-id'})
def test_unparseable_server_url_raises():
    # No scheme/netloc to derive a hostname from - fail loudly rather than
    # mint a broken/empty issuer suffix.
    with pytest.raises(ImproperlyConfigured, match='issuer host'):
        populate(make_sociallogin())
