"""The un-mocked OIDC discovery fetch in ``sso_portal_client.oidc``.

``tests/test_views.py`` replaces ``oidc.discovery`` wholesale; this module
exercises the real function against a stubbed ``requests.get``.
"""

import time
from typing import Any

import pytest
import requests

from sso_portal_client import oidc

DISCOVERY = {'issuer': 'http://127.0.0.1:8000/o', 'jwks_uri': 'http://127.0.0.1:8000/o/jwks/'}


class FakeResponse:
    def __init__(self, status_code: int, payload: dict[str, Any]) -> None:
        self.status_code = status_code
        self.payload = payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError

    def json(self) -> dict[str, Any]:
        return self.payload


def test_discovery_fetches_well_known_document_with_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_get(url: str, **kwargs: Any) -> FakeResponse:
        calls.append((url, kwargs))
        return FakeResponse(200, DISCOVERY)

    monkeypatch.setattr(oidc.requests, 'get', fake_get)

    assert oidc.discovery() == DISCOVERY
    assert calls == [
        ('http://127.0.0.1:8000/o/.well-known/openid-configuration', {'timeout': oidc.HTTP_TIMEOUT_SECONDS}),
    ]


def test_discovery_raises_on_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(oidc.requests, 'get', lambda url, **kwargs: FakeResponse(503, {}))

    with pytest.raises(oidc.UpstreamFetchError):
        oidc.discovery()


def test_discovery_cache_hit_and_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [100.0]
    calls: list[str] = []

    def fake_get(url: str, **kwargs: Any) -> FakeResponse:
        calls.append(url)
        return FakeResponse(200, DISCOVERY)

    monkeypatch.setattr(oidc.requests, 'get', fake_get)
    monkeypatch.setattr(time, 'monotonic', lambda: clock[0])
    assert oidc.discovery() == DISCOVERY
    clock[0] = 399.0
    assert oidc.discovery() == DISCOVERY
    assert len(calls) == 1
    clock[0] = 400.0
    assert oidc.discovery() == DISCOVERY
    assert len(calls) == 2


def test_discovery_cache_is_per_url(monkeypatch: pytest.MonkeyPatch, settings: Any) -> None:
    calls: list[str] = []

    def fake_get(url: str, **kwargs: Any) -> FakeResponse:
        calls.append(url)
        return FakeResponse(200, {**DISCOVERY, 'issuer': url})

    monkeypatch.setattr(oidc.requests, 'get', fake_get)
    first = oidc.discovery()
    original = settings.SSO_PORTAL_CLIENT
    settings.SSO_PORTAL_CLIENT = {**original, 'SERVER_URL': 'https://other.portal/o'}
    assert oidc.discovery() != first
    settings.SSO_PORTAL_CLIENT = original
    assert oidc.discovery() == first
    assert len(calls) == 2


@pytest.mark.parametrize('ttl', [0, 10])
def test_discovery_cache_configurable_ttl(monkeypatch: pytest.MonkeyPatch, settings: Any, ttl: int) -> None:
    settings.SSO_PORTAL_CLIENT = {**settings.SSO_PORTAL_CLIENT, 'DISCOVERY_CACHE_SECONDS': ttl}
    calls: list[str] = []
    clock = [100.0]

    def fake_get(url: str, **kwargs: Any) -> FakeResponse:
        calls.append(url)
        return FakeResponse(200, DISCOVERY)

    monkeypatch.setattr(oidc.requests, 'get', fake_get)
    monkeypatch.setattr(time, 'monotonic', lambda: clock[0])
    oidc.discovery()
    oidc.discovery()
    assert len(calls) == (2 if ttl == 0 else 1)
    clock[0] += ttl
    oidc.discovery()
    assert len(calls) == (3 if ttl == 0 else 2)
