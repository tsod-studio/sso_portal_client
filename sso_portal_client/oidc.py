"""The portal's OIDC discovery document and signing keys, fetched and cached
per process.

Shared by everything in this package that verifies a portal-signed JWT: the
back-channel logout endpoint (``views``) and the authorize-only client
(``authorize_only``). Each failure to reach the portal, or a reply that is not
a usable document or key set, is an :class:`UpstreamFetchError`, kept apart
from a token that does not verify (``jwt.PyJWTError``).
"""

import time
from threading import Lock
from typing import Any

import jwt
import requests
from jwt import PyJWKClient

from sso_portal_client.conf import discovery_url, get_settings

#: Seconds a call to the portal may take to connect and to answer.
HTTP_TIMEOUT_SECONDS = 5


class UpstreamFetchError(Exception):
    """Discovery or JWKS could not be fetched or parsed."""


class _UpstreamJWKClient(PyJWKClient):
    def fetch_data(self) -> Any:
        """Keep upstream parsing errors distinct from token validation errors."""
        try:
            return super().fetch_data()
        except (jwt.PyJWTError, ValueError, TypeError, KeyError) as exc:
            msg = 'JWKS fetch failed'
            raise UpstreamFetchError(msg) from exc


_discovery_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_jwk_clients: dict[tuple[str, bool], PyJWKClient] = {}
_cache_lock = Lock()


def reset_caches() -> None:
    """Clear process-local discovery documents and JWK clients (for tests)."""
    with _cache_lock:
        _discovery_cache.clear()
        _jwk_clients.clear()


def discovery() -> dict[str, Any]:
    """The portal's discovery document, cached per URL for ``DISCOVERY_CACHE_SECONDS``.

    Guarantees non-empty string ``issuer`` and ``jwks_uri``; any other key a
    caller needs, it checks itself.
    """
    url = discovery_url()
    ttl = get_settings()['DISCOVERY_CACHE_SECONDS']
    with _cache_lock:
        cached = _discovery_cache.get(url)
        if ttl and cached and time.monotonic() < cached[0]:
            return cached[1]
        try:
            response = requests.get(url, timeout=HTTP_TIMEOUT_SECONDS)
            response.raise_for_status()
            result = response.json()
        except (requests.RequestException, ValueError) as exc:
            msg = 'Discovery fetch failed'
            raise UpstreamFetchError(msg) from exc
        if not isinstance(result, dict) or any(
            not isinstance(result.get(key), str) or not result[key] for key in ('issuer', 'jwks_uri')
        ):
            msg = 'Invalid discovery document'
            raise UpstreamFetchError(msg)
        _discovery_cache[url] = (time.monotonic() + ttl, result)
        return result


def jwk_client(uri: str, *, refetch_cooldown: bool = True) -> PyJWKClient:
    """The JWK client for ``uri``, reused across calls: its JWK-set TTL cache, never a per-key LRU, so a removed key
    is not retained.

    ``refetch_cooldown`` keeps PyJWT's cooldown between forced refetches for unknown ``kid`` s. Keep it on wherever
    the token arrives from the internet (a back-channel logout endpoint), so tokens with random ``kid`` s never turn
    into one JWKS fetch each. Turn it off only where the token came straight from the portal's own token endpoint
    over TLS: there an unknown ``kid`` means the portal just rotated its key, and it must be found at once.
    """
    with _cache_lock:
        key = (uri, refetch_cooldown)
        if key not in _jwk_clients:
            options: dict[str, Any] = {} if refetch_cooldown else {'cooldown_duration': 0}
            try:
                _jwk_clients[key] = _UpstreamJWKClient(
                    uri,
                    timeout=HTTP_TIMEOUT_SECONDS,
                    cache_jwk_set=True,
                    cache_keys=False,
                    **options,
                )
            except jwt.PyJWKClientError as exc:
                msg = 'Invalid discovery JWKS URI'
                raise UpstreamFetchError(msg) from exc
        return _jwk_clients[key]
