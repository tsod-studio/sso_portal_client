"""Back-channel logout + session-ping endpoints.

Both endpoints mirror sso_portal's Flask reference RP
(``examples/sample_rp/app.py`` in the sso_portal repo) — the logout_token
verification implements the same OIDC Back-Channel Logout 1.0 §2.6 checks,
and session-ping carries the same MUST-NOT-refresh contract.

Requires Django's database session backend
(``django.contrib.sessions.backends.db``, the default): back-channel logout
works by unilaterally deleting ``django_session`` rows. A signed-cookie
session cannot be revoked server-side.
"""

import logging
import time
from threading import Lock
from typing import Any
from urllib.parse import urlencode

import jwt
import requests
from allauth.socialaccount.models import SocialAccount
from django.conf import settings as django_settings
from django.contrib.auth import logout as auth_logout
from django.contrib.sessions.models import Session
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.views.decorators.http import require_GET, require_POST
from jwt import PyJWKClient

from sso_portal_client.conf import (
    PROVIDER_ID,
    SESSION_ID_TOKEN_KEY,
    discovery_url,
    get_settings,
)
from sso_portal_client.models import PortalSession

logger = logging.getLogger(__name__)

# OIDC Back-Channel Logout 1.0 §2.4's event claim key.
BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout'
HTTP_TIMEOUT_SECONDS = 5


class UpstreamFetchError(Exception):
    """Discovery or JWKS could not be fetched or parsed."""


class _LogoutJWKClient(PyJWKClient):
    def fetch_data(self) -> Any:
        """Keep upstream parsing errors distinct from token validation errors."""
        try:
            return super().fetch_data()
        except (jwt.PyJWTError, ValueError, TypeError, KeyError) as exc:
            msg = 'JWKS fetch failed'
            raise UpstreamFetchError(msg) from exc


_discovery_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_jwk_clients: dict[str, PyJWKClient] = {}
_cache_lock = Lock()


def _reset_logout_caches() -> None:
    """Clear process-local discovery documents and JWK clients for tests."""
    with _cache_lock:
        _discovery_cache.clear()
        _jwk_clients.clear()


def _discovery() -> dict[str, Any]:
    """Fetch and cache discovery per URL for the configured TTL."""
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


def _jwk_client(uri: str) -> PyJWKClient:
    """Reuse the JWK-set TTL cache; never retain removed keys in a key LRU."""
    with _cache_lock:
        if uri not in _jwk_clients:
            try:
                _jwk_clients[uri] = _LogoutJWKClient(
                    uri,
                    timeout=HTTP_TIMEOUT_SECONDS,
                    cache_jwk_set=True,
                    # PyJWT's default refetch cooldown stays on: the endpoint is reachable from the
                    # internet, and tokens with random kids must not turn into one JWKS fetch each.
                    cache_keys=False,
                )
            except jwt.PyJWKClientError as exc:
                msg = 'Invalid discovery JWKS URI'
                raise UpstreamFetchError(msg) from exc
        return _jwk_clients[uri]


def _decode_logout_token(token: str, *, discovery: dict[str, Any], client_id: str) -> dict[str, Any]:
    """Verify a logout_token per OIDC Back-Channel Logout 1.0 §2.6.

    Checks (same set as the Flask sample's ``_decode_logout_token``):
    RS256 signature against the portal's jwks, iss, aud, presence of the
    backchannel-logout event, absence of a nonce claim, presence of sid
    (this RP only tracks sid, not sub-wide logout).
    """
    signing_key = _jwk_client(discovery['jwks_uri']).get_signing_key_from_jwt(token)
    claims: dict[str, Any] = jwt.decode(
        token,
        signing_key.key,
        algorithms=['RS256'],
        audience=client_id,
        issuer=discovery['issuer'],
    )
    if 'nonce' in claims:
        msg = 'logout token must not contain a nonce claim'
        raise ValueError(msg)
    events = claims.get('events')
    if not isinstance(events, dict) or BACKCHANNEL_LOGOUT_EVENT not in events:
        msg = 'logout token missing the backchannel-logout events claim'
        raise ValueError(msg)
    if not claims.get('sid'):
        msg = 'logout token missing sid'
        raise ValueError(msg)
    return claims


@csrf_exempt
@require_POST
def backchannel_logout(request: HttpRequest) -> HttpResponse:
    """OIDC Back-Channel Logout endpoint (portal -> RP, server to server).

    csrf_exempt is correct here: the caller is the portal's backend, not a
    browser — there is no session cookie to ride, and the logout_token's
    signature is the authentication.
    """
    started = time.monotonic()
    status = 400
    deleted = 0
    try:
        token = request.POST.get('logout_token', '')
        if not token:
            return HttpResponse('missing logout_token', status=status)

        client_id = get_settings()['CLIENT_ID']
        try:
            claims = _decode_logout_token(token, discovery=_discovery(), client_id=client_id)
        except UpstreamFetchError:
            status = 503
            logger.warning('back-channel logout: upstream discovery/JWKS fetch failed')
            return HttpResponse('logout upstream unavailable', status=status)
        except (jwt.PyJWTError, ValueError):
            logger.warning('back-channel logout: rejected invalid logout_token')
            return HttpResponse('invalid logout token', status=status)

        portal_sessions = PortalSession.objects.filter(sid=claims['sid'])
        session_keys = list(portal_sessions.values_list('session_key', flat=True))
        deleted, _ = Session.objects.filter(session_key__in=session_keys).delete()
        portal_sessions.delete()
        status = 200
        return HttpResponse(status=status)
    finally:
        duration_ms = (time.monotonic() - started) * 1000
        logger.info(
            'back-channel logout: status=%s duration_ms=%.2f sessions_deleted=%s',
            status,
            duration_ms,
            deleted,
            extra={'status_code': status, 'duration_ms': duration_ms, 'sessions_deleted': deleted},
        )


@require_GET
def session_ping(request: HttpRequest) -> JsonResponse:
    """Read-only session-liveness check for the portal's switch widget.

    MUST NOT extend the session's lifetime — no session write, nothing that
    sets ``request.session.modified``. The widget polls this endpoint on a
    timer while its tab is visible; if this handler refreshed the session on
    each hit, that background heartbeat alone would make the RP's session
    self-renewing forever, silently defeating whatever idle timeout the RP
    relies on (see the Flask sample's ``/session-ping`` docstring in
    sso_portal's ``examples/sample_rp/app.py`` for the full rationale).

    Corollary for integrators: with ``SESSION_SAVE_EVERY_REQUEST = True``
    Django's session middleware re-saves the session on *every* request,
    including this one — that setting is incompatible with the no-refresh
    contract, so leave it at its default (``False``).
    """
    if not request.user.is_authenticated:
        return JsonResponse({'detail': 'no active session'}, status=401)

    session_key = request.session.session_key
    portal_session = PortalSession.objects.filter(session_key=session_key).first() if session_key else None
    account = SocialAccount.objects.filter(user=request.user, provider=PROVIDER_ID).only('uid').first()
    return JsonResponse(
        {
            'sub': account.uid if account else None,
            'sid': portal_session.sid if portal_session else None,
        }
    )


@require_POST
@csrf_protect
def local_logout(request: HttpRequest) -> HttpResponse:
    """End only this RP session after a widget logout, without a redirect."""
    session_key = request.session.session_key
    auth_logout(request)
    if session_key:
        PortalSession.objects.filter(session_key=session_key).delete()
    return HttpResponse(status=204)


def _local_fallback_url() -> str:
    """Where to send the browser when the portal's end_session_endpoint can't
    be resolved (discovery unreachable/malformed). Local logout already
    happened, so this only affects where the user lands — never a 500.

    Configurable, in priority order: SSO_PORTAL_CLIENT['POST_LOGOUT_REDIRECT_URL']
    (the same landing page the portal is asked to return to), then Django's
    stock ``LOGOUT_REDIRECT_URL``, then ``'/'``.
    """
    return get_settings()['POST_LOGOUT_REDIRECT_URL'] or getattr(django_settings, 'LOGOUT_REDIRECT_URL', None) or '/'


@require_POST
def global_logout(request: HttpRequest) -> HttpResponse:
    """RP-initiated ("log out everywhere") logout for browser sessions.

    POST-only (logout is state-changing; GET yields 405, mirroring how Django
    and allauth treat logout). The flow:

    1. Capture the stashed raw id_token (``SESSION_ID_TOKEN_KEY``) BEFORE
       clearing the session — see that constant's docstring: this package does
       not populate it (no supported allauth hook exposes the raw JWT), so in
       practice the hint is absent and we take the no-hint path below.
    2. ``auth.logout(request)`` ALWAYS runs — local logout is unconditional and
       never depends on the portal being reachable.
    3. Redirect (302) to the portal's ``end_session_endpoint`` from the
       discovery document. If discovery fails, still redirect — to the local
       fallback — instead of 500ing.

    Query params on the portal redirect:

    - ``id_token_hint`` only when a raw id_token was stashed. With a valid hint
      the portal (``ALWAYS_PROMPT=False``) skips its logout-confirmation page.
    - ``post_logout_redirect_uri`` only alongside a hint (the OIDC RP-Initiated
      Logout spec ties the two, and the portal validates the URI against the
      Application's registered ``post_logout_redirect_uris``). Value comes from
      ``POST_LOGOUT_REDIRECT_URL``; omitted when unset.

    Without a hint the portal shows its confirmation prompt — the documented
    degraded-but-functional UX.
    """
    id_token = request.session.get(SESSION_ID_TOKEN_KEY)

    # Local logout is unconditional and happens first (flushes the session).
    auth_logout(request)

    try:
        end_session_endpoint = _discovery().get('end_session_endpoint')
    except Exception:
        logger.warning('global logout: discovery fetch failed; redirecting to local fallback')
        end_session_endpoint = None
    if not end_session_endpoint:
        return HttpResponseRedirect(_local_fallback_url())

    params: dict[str, str] = {}
    if id_token:
        params['id_token_hint'] = id_token
        post_logout_redirect_uri = get_settings()['POST_LOGOUT_REDIRECT_URL']
        if post_logout_redirect_uri:
            params['post_logout_redirect_uri'] = post_logout_redirect_uri

    url = f'{end_session_endpoint}?{urlencode(params)}' if params else end_session_endpoint
    return HttpResponseRedirect(url)
