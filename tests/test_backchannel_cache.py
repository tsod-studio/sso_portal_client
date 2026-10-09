"""Back-channel caching, key rotation, upstream errors, and request metrics."""

import io
import json
import logging
from typing import Any
from urllib.error import URLError

import jwt
import pytest
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import Client

from sso_portal_client import views
from sso_portal_client.models import PortalSession
from tests.test_discovery import DISCOVERY, FakeResponse
from tests.test_views import CLIENT_ID, ISSUER, KID, LOGOUT_URL, make_logout_token, make_session

pytestmark = pytest.mark.django_db


@pytest.fixture
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def jwk(rsa_key: rsa.RSAPrivateKey) -> dict[str, Any]:
    key: dict[str, Any] = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(rsa_key.public_key()))
    return {**key, 'kid': KID, 'alg': 'RS256', 'use': 'sig'}


@pytest.fixture
def upstream(monkeypatch: pytest.MonkeyPatch, jwk: dict[str, Any]) -> list[object]:
    replies: list[object] = [json.dumps({'keys': [jwk]}).encode()]
    monkeypatch.setattr(views.requests, 'get', lambda *args, **kwargs: FakeResponse(200, DISCOVERY))

    class Opener:
        def open(self, request: Any, *, timeout: float) -> io.BytesIO:
            reply = replies.pop(0)
            if isinstance(reply, Exception):
                raise reply
            assert isinstance(reply, bytes)
            return io.BytesIO(reply)

    monkeypatch.setattr('urllib.request.build_opener', lambda *args: Opener())
    return replies


def test_jwk_client_reused_with_ttl_cache(
    client: Client, rsa_key: rsa.RSAPrivateKey, upstream: list[object], monkeypatch: pytest.MonkeyPatch
) -> None:
    instances: list[jwt.PyJWKClient] = []
    original_init = jwt.PyJWKClient.__init__

    def init(self: jwt.PyJWKClient, *args: Any, **kwargs: Any) -> None:
        assert kwargs['cache_keys'] is False
        assert kwargs['cache_jwk_set'] is True
        assert 'lifespan' not in kwargs
        instances.append(self)
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(jwt.PyJWKClient, '__init__', init)
    token = make_logout_token(rsa_key)
    assert client.post(LOGOUT_URL, {'logout_token': token}).status_code == 200
    assert client.post(LOGOUT_URL, {'logout_token': token}).status_code == 200
    assert len(instances) == 1
    assert upstream == []


def test_unknown_kid_refetches_cached_jwks_after_cooldown(
    client: Client,
    rsa_key: rsa.RSAPrivateKey,
    upstream: list[object],
    jwk: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [100.0]
    monkeypatch.setattr('time.monotonic', lambda: clock[0])
    assert client.post(LOGOUT_URL, {'logout_token': make_logout_token(rsa_key)}).status_code == 200
    rotated = {**jwk, 'kid': 'rotated-key'}
    upstream.append(json.dumps({'keys': [rotated]}).encode())
    token = jwt.encode(
        {'iss': ISSUER, 'aud': CLIENT_ID, 'sid': 'rotated-sid', 'events': {views.BACKCHANNEL_LOGOUT_EVENT: {}}},
        rsa_key,
        algorithm='RS256',
        headers={'kid': 'rotated-key'},
    )
    clock[0] = 131.0
    assert client.post(LOGOUT_URL, {'logout_token': token}).status_code == 200
    assert upstream == []
    # A removed key must not survive in a per-key LRU cache.
    upstream.append(json.dumps({'keys': [rotated]}).encode())
    clock[0] = 162.0
    assert client.post(LOGOUT_URL, {'logout_token': make_logout_token(rsa_key)}).status_code == 400
    assert upstream == []


def test_unknown_kid_within_cooldown_does_not_refetch(
    client: Client,
    rsa_key: rsa.RSAPrivateKey,
    upstream: list[object],
    jwk: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [100.0]
    monkeypatch.setattr('time.monotonic', lambda: clock[0])
    assert client.post(LOGOUT_URL, {'logout_token': make_logout_token(rsa_key)}).status_code == 200
    unused = json.dumps({'keys': [{**jwk, 'kid': 'random-kid'}]}).encode()
    upstream.append(unused)
    forged = jwt.encode(
        {'iss': ISSUER, 'aud': CLIENT_ID, 'sid': 'forged', 'events': {views.BACKCHANNEL_LOGOUT_EVENT: {}}},
        rsa_key,
        algorithm='RS256',
        headers={'kid': 'random-kid'},
    )
    clock[0] = 110.0
    assert client.post(LOGOUT_URL, {'logout_token': forged}).status_code == 400
    # Tokens with unknown kids inside the cooldown must not reach the portal.
    assert upstream == [unused]


def test_discovery_jwks_uri_change_switches_clients(
    client: Client,
    rsa_key: rsa.RSAPrivateKey,
    upstream: list[object],
    jwk: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert client.post(LOGOUT_URL, {'logout_token': make_logout_token(rsa_key)}).status_code == 200
    monkeypatch.setattr(views, '_discovery', lambda: {**DISCOVERY, 'jwks_uri': 'https://portal.test/new-jwks'})
    upstream.append(json.dumps({'keys': [jwk]}).encode())
    assert client.post(LOGOUT_URL, {'logout_token': make_logout_token(rsa_key)}).status_code == 200
    assert upstream == []


@pytest.mark.parametrize('error', [requests.Timeout(), requests.ConnectionError(), requests.HTTPError(), ValueError()])
def test_discovery_failure_is_503(
    client: Client,
    rsa_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    error: Exception,
) -> None:
    def fail(*args: Any, **kwargs: Any) -> FakeResponse:
        raise error

    monkeypatch.setattr(views.requests, 'get', fail)
    assert client.post(LOGOUT_URL, {'logout_token': make_logout_token(rsa_key)}).status_code == 503
    assert 'upstream' in caplog.text


@pytest.mark.parametrize(
    'payload',
    [
        [],
        {},
        {'issuer': ISSUER},
        {'issuer': None, 'jwks_uri': 'https://portal.test/jwks'},
        {'issuer': ISSUER, 'jwks_uri': ''},
    ],
)
def test_malformed_discovery_is_503(
    client: Client, rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch, payload: Any
) -> None:
    monkeypatch.setattr(views.requests, 'get', lambda *args, **kwargs: FakeResponse(200, payload))
    assert client.post(LOGOUT_URL, {'logout_token': make_logout_token(rsa_key)}).status_code == 503


@pytest.mark.parametrize('reply', [URLError('offline'), TimeoutError(), b'bad json', b'[]', b'{"keys": []}'])
def test_jwks_failure_is_503(
    client: Client,
    rsa_key: rsa.RSAPrivateKey,
    upstream: list[object],
    caplog: pytest.LogCaptureFixture,
    reply: object,
) -> None:
    upstream[:] = [reply]
    assert client.post(LOGOUT_URL, {'logout_token': make_logout_token(rsa_key)}).status_code == 503
    assert 'upstream' in caplog.text


@pytest.mark.parametrize('outcome', ['success', 'invalid', 'missing', 'upstream'])
def test_one_info_line_reports_duration_and_deleted_sessions(
    client: Client,
    user: Any,
    rsa_key: rsa.RSAPrivateKey,
    upstream: list[object],
    caplog: pytest.LogCaptureFixture,
    outcome: str,
) -> None:
    key = make_session()
    PortalSession.objects.create(user=user, sid='portal-sid-1', session_key=key)
    token = make_logout_token(rsa_key)
    data = {'logout_token': token}
    if outcome == 'invalid':
        data = {'logout_token': 'invalid-token'}
    elif outcome == 'missing':
        data = {}
    elif outcome == 'upstream':
        upstream[:] = [URLError('offline')]
    with caplog.at_level(logging.INFO, logger=views.__name__):
        response = client.post(LOGOUT_URL, data)
    records = [record for record in caplog.records if record.name == views.__name__ and record.levelno == logging.INFO]
    assert len(records) == 1
    record = records[0]
    assert record.duration_ms >= 0
    assert record.sessions_deleted == (1 if outcome == 'success' else 0)
    assert record.status_code == response.status_code
    assert 'duration_ms=' in record.getMessage()
    assert 'sessions_deleted=' in record.getMessage()
    assert token not in caplog.text
    assert 'portal-sid-1' not in caplog.text


def test_invalid_discovery_jwks_uri_is_upstream_failure(
    client: Client, rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        views.requests, 'get', lambda *args, **kwargs: FakeResponse(200, {**DISCOVERY, 'jwks_uri': 'invalid'})
    )
    assert client.post(LOGOUT_URL, {'logout_token': make_logout_token(rsa_key)}).status_code == 503


def test_jwks_cache_expiry_refetches_and_revokes_removed_key(
    client: Client,
    rsa_key: rsa.RSAPrivateKey,
    upstream: list[object],
    jwk: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [100.0]
    monkeypatch.setattr('time.monotonic', lambda: clock[0])
    token = make_logout_token(rsa_key)
    assert client.post(LOGOUT_URL, {'logout_token': token}).status_code == 200
    clock[0] = 399.0
    assert client.post(LOGOUT_URL, {'logout_token': token}).status_code == 200
    rotated = json.dumps({'keys': [{**jwk, 'kid': 'rotated-key'}]}).encode()
    upstream.append(rotated)
    clock[0] = 401.0
    assert client.post(LOGOUT_URL, {'logout_token': token}).status_code == 400
    # One fetch on expiry; the removed kid does not force a second fetch inside the cooldown.
    assert upstream == []
