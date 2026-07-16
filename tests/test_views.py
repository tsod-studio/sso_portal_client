"""Back-channel logout token verification + session-ping contract tests.

Logout tokens are signed with a test RSA keypair; the jwks fetch and the
discovery fetch are monkeypatched so the real verification code path runs
without any network access.
"""

import json
import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from allauth.socialaccount.models import SocialAccount
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.models import Session
from django.test import override_settings

from sso_portal_client import views
from sso_portal_client.conf import SESSION_ID_TOKEN_KEY
from sso_portal_client.models import PortalSession

pytestmark = pytest.mark.django_db

ISSUER = 'http://127.0.0.1:8000/o'
CLIENT_ID = 'test-client-id'  # matches tests/settings.py
KID = 'test-key-1'
LOGOUT_URL = '/sso/backchannel-logout/'
PING_URL = '/sso/session-ping/'
END_SESSION = 'http://127.0.0.1:8000/o/logout/'
GLOBAL_LOGOUT_URL = '/sso/logout/'


@pytest.fixture(scope='module')
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(autouse=True)
def portal_endpoints(monkeypatch, rsa_key):
    """Serve discovery + jwks from fixtures instead of the network."""
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(rsa_key.public_key()))
    jwk.update({'kid': KID, 'alg': 'RS256', 'use': 'sig'})
    monkeypatch.setattr(
        views,
        '_discovery',
        lambda: {'issuer': ISSUER, 'jwks_uri': 'http://portal.test/o/jwks', 'end_session_endpoint': END_SESSION},
    )
    monkeypatch.setattr(jwt.PyJWKClient, 'fetch_data', lambda self: {'keys': [jwk]})


def make_logout_token(rsa_key, **overrides):
    now = int(time.time())
    claims = {
        'iss': ISSUER,
        'aud': CLIENT_ID,
        'iat': now,
        'exp': now + 120,
        'jti': 'logout-jti-1',
        'sub': '42',
        'sid': 'portal-sid-1',
        'events': {views.BACKCHANNEL_LOGOUT_EVENT: {}},
    }
    claims.update(overrides)
    claims = {key: value for key, value in claims.items() if value is not None}
    return jwt.encode(claims, rsa_key, algorithm='RS256', headers={'kid': KID})


def make_session():
    store = SessionStore()
    store['seen'] = True
    store.create()
    return store.session_key


def track(user, sid, session_key):
    return PortalSession.objects.create(user=user, sid=sid, session_key=session_key)


# --- backchannel_logout --------------------------------------------------------


def test_valid_logout_token_kills_matching_sessions_only(client, user, rsa_key):
    key_a, key_b, key_other = make_session(), make_session(), make_session()
    track(user, 'portal-sid-1', key_a)
    track(user, 'portal-sid-1', key_b)
    track(user, 'other-sid', key_other)

    response = client.post(LOGOUT_URL, {'logout_token': make_logout_token(rsa_key)})

    assert response.status_code == 200
    remaining = set(Session.objects.values_list('session_key', flat=True))
    assert key_a not in remaining
    assert key_b not in remaining
    assert key_other in remaining
    assert set(PortalSession.objects.values_list('sid', flat=True)) == {'other-sid'}


def test_valid_token_with_no_tracked_sessions_still_200(client, rsa_key):
    response = client.post(LOGOUT_URL, {'logout_token': make_logout_token(rsa_key)})
    assert response.status_code == 200


@pytest.mark.parametrize(
    'overrides',
    [
        {'aud': 'some-other-client'},
        {'iss': 'https://evil.example'},
        {'events': None},
        {'events': {'urn:example:unrelated-event': {}}},
        {'nonce': 'must-not-be-here'},
        {'sid': None},
        {'exp': int(time.time()) - 3600},
    ],
    ids=['wrong-aud', 'wrong-iss', 'missing-events', 'wrong-event', 'nonce-present', 'missing-sid', 'expired'],
)
def test_invalid_logout_tokens_rejected(client, user, rsa_key, overrides):
    session_key = make_session()
    track(user, 'portal-sid-1', session_key)

    response = client.post(LOGOUT_URL, {'logout_token': make_logout_token(rsa_key, **overrides)})

    assert response.status_code == 400
    # Nothing was deleted.
    assert Session.objects.filter(session_key=session_key).exists()
    assert PortalSession.objects.filter(session_key=session_key).exists()


def test_token_signed_by_unknown_key_rejected(client, rsa_key):
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(
        {'iss': ISSUER, 'aud': CLIENT_ID, 'sid': 's', 'events': {views.BACKCHANNEL_LOGOUT_EVENT: {}}},
        other_key,
        algorithm='RS256',
        headers={'kid': KID},
    )
    assert client.post(LOGOUT_URL, {'logout_token': token}).status_code == 400


def test_garbage_token_rejected(client):
    assert client.post(LOGOUT_URL, {'logout_token': 'not-a-jwt'}).status_code == 400


def test_missing_logout_token_rejected(client):
    assert client.post(LOGOUT_URL, {}).status_code == 400


def test_get_not_allowed(client):
    assert client.get(LOGOUT_URL).status_code == 405


# --- session_ping ---------------------------------------------------------------


def test_ping_anonymous_401(client):
    response = client.get(PING_URL)
    assert response.status_code == 401
    assert response.json() == {'detail': 'no active session'}


def test_ping_live_session_returns_sub_and_sid(client, user):
    SocialAccount.objects.create(user=user, provider='sso_portal', uid='42', extra_data={})
    client.force_login(user)
    track(user, 'portal-sid-1', client.session.session_key)

    response = client.get(PING_URL)

    assert response.status_code == 200
    assert response.json() == {'sub': '42', 'sid': 'portal-sid-1'}


def test_ping_without_tracking_rows_still_200(client, user):
    client.force_login(user)
    response = client.get(PING_URL)
    assert response.status_code == 200
    assert response.json() == {'sub': None, 'sid': None}


def test_ping_does_not_refresh_session(client, user):
    """The MUST-NOT-refresh contract (Flask sample's /session-ping): polling
    this endpoint must not extend the session's lifetime, or the widget's
    heartbeat would make the RP session self-renewing forever."""
    client.force_login(user)
    session_key = client.session.session_key
    expiry_before = Session.objects.get(session_key=session_key).expire_date

    client.get(PING_URL)

    expiry_after = Session.objects.get(session_key=session_key).expire_date
    assert expiry_after == expiry_before


def test_ping_post_not_allowed(client, user):
    client.force_login(user)
    assert client.post(PING_URL).status_code == 405


# --- global_logout (RP-initiated "log out everywhere") --------------------------


def redirect_target(response):
    location = response.headers['Location']
    parsed = urlparse(location)
    base = f'{parsed.scheme}://{parsed.netloc}{parsed.path}'
    return base, parse_qs(parsed.query)


def test_global_logout_get_not_allowed(client):
    assert client.get(GLOBAL_LOGOUT_URL).status_code == 405


def test_global_logout_no_hint_clears_session_and_redirects(client, user):
    client.force_login(user)
    assert '_auth_user_id' in client.session

    response = client.post(GLOBAL_LOGOUT_URL)

    assert response.status_code == 302
    # No hint stashed -> bare end_session_endpoint, no post_logout_redirect_uri.
    base, params = redirect_target(response)
    assert base == END_SESSION
    assert params == {}
    # Local logout always happened.
    assert '_auth_user_id' not in client.session


@override_settings(
    SSO_PORTAL_CLIENT={
        'SERVER_URL': ISSUER,
        'CLIENT_ID': CLIENT_ID,
        'POST_LOGOUT_REDIRECT_URL': 'http://localhost:9002/',
    }
)
def test_global_logout_with_hint_sends_hint_and_post_logout_uri(client, user):
    client.force_login(user)
    session = client.session
    session[SESSION_ID_TOKEN_KEY] = 'raw.jwt.token'
    session.save()

    response = client.post(GLOBAL_LOGOUT_URL)

    assert response.status_code == 302
    base, params = redirect_target(response)
    assert base == END_SESSION
    assert params['id_token_hint'] == ['raw.jwt.token']
    assert params['post_logout_redirect_uri'] == ['http://localhost:9002/']
    assert '_auth_user_id' not in client.session


def test_global_logout_with_hint_but_no_post_logout_setting_omits_uri(client, user):
    # tests/settings.py sets no POST_LOGOUT_REDIRECT_URL (default None).
    client.force_login(user)
    session = client.session
    session[SESSION_ID_TOKEN_KEY] = 'raw.jwt.token'
    session.save()

    response = client.post(GLOBAL_LOGOUT_URL)

    base, params = redirect_target(response)
    assert base == END_SESSION
    assert params['id_token_hint'] == ['raw.jwt.token']
    assert 'post_logout_redirect_uri' not in params


@override_settings(
    SSO_PORTAL_CLIENT={
        'SERVER_URL': ISSUER,
        'CLIENT_ID': CLIENT_ID,
        'POST_LOGOUT_REDIRECT_URL': 'http://localhost:9002/',
    }
)
def test_global_logout_discovery_failure_logs_out_locally_and_uses_fallback(client, user, monkeypatch):
    def boom():
        raise RuntimeError

    monkeypatch.setattr(views, '_discovery', boom)
    client.force_login(user)

    response = client.post(GLOBAL_LOGOUT_URL)

    assert response.status_code == 302
    assert response.headers['Location'] == 'http://localhost:9002/'
    # Local logout still happened even though the portal was unreachable.
    assert '_auth_user_id' not in client.session


def test_global_logout_anonymous_still_redirects(client):
    response = client.post(GLOBAL_LOGOUT_URL)
    assert response.status_code == 302
    base, params = redirect_target(response)
    assert base == END_SESSION
    assert params == {}
