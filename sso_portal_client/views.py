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
from typing import Any

import jwt
import requests
from allauth.socialaccount.models import SocialAccount
from django.contrib.sessions.models import Session
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST
from jwt import PyJWKClient

from sso_portal_client.conf import PROVIDER_ID, discovery_url, get_settings
from sso_portal_client.models import PortalSession

logger = logging.getLogger(__name__)

# OIDC Back-Channel Logout 1.0 §2.4's event claim key.
BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout'
HTTP_TIMEOUT_SECONDS = 5


def _discovery() -> dict[str, Any]:
    """Fetch the portal's OIDC discovery document (not cached: logout is
    rare, and always reflecting the portal's current jwks_uri/issuer is
    worth more than the round trip)."""
    response = requests.get(discovery_url(), timeout=HTTP_TIMEOUT_SECONDS)
    response.raise_for_status()
    result: dict[str, Any] = response.json()
    return result


def _decode_logout_token(token: str, *, discovery: dict[str, Any], client_id: str) -> dict[str, Any]:
    """Verify a logout_token per OIDC Back-Channel Logout 1.0 §2.6.

    Checks (same set as the Flask sample's ``_decode_logout_token``):
    RS256 signature against the portal's jwks, iss, aud, presence of the
    backchannel-logout event, absence of a nonce claim, presence of sid
    (this RP only tracks sid, not sub-wide logout).
    """
    signing_key = PyJWKClient(discovery['jwks_uri'], timeout=HTTP_TIMEOUT_SECONDS).get_signing_key_from_jwt(token)
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
    token = request.POST.get('logout_token', '')
    if not token:
        return HttpResponse('missing logout_token', status=400)

    client_id = get_settings()['CLIENT_ID']
    try:
        claims = _decode_logout_token(token, discovery=_discovery(), client_id=client_id)
    except Exception:
        logger.warning('back-channel logout: rejected invalid logout_token')
        return HttpResponse('invalid logout token', status=400)

    sid = claims['sid']
    portal_sessions = PortalSession.objects.filter(sid=sid)
    session_keys = list(portal_sessions.values_list('session_key', flat=True))
    Session.objects.filter(session_key__in=session_keys).delete()
    portal_sessions.delete()
    return HttpResponse(status=200)


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
