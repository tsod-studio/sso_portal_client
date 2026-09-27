"""The un-mocked OIDC discovery fetch in ``sso_portal_client.views``.

``tests/test_views.py`` replaces ``views._discovery`` wholesale; this module
exercises the real function against a stubbed ``requests.get``.
"""

from typing import Any

import pytest
import requests

from sso_portal_client import views

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

    monkeypatch.setattr(views.requests, 'get', fake_get)

    assert views._discovery() == DISCOVERY
    assert calls == [
        ('http://127.0.0.1:8000/o/.well-known/openid-configuration', {'timeout': views.HTTP_TIMEOUT_SECONDS}),
    ]


def test_discovery_raises_on_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(views.requests, 'get', lambda url, **kwargs: FakeResponse(503, {}))

    with pytest.raises(requests.HTTPError):
        views._discovery()
