"""Authorize only: one person's approval without signing anyone in.

The portal's ``GET /switch/authorize/`` (its app integration guide, section 9)
is a standard OIDC authorization-code endpoint that identifies a person (store
PIN, QR on their phone, email and password, or LINE) and sends the browser
back with a code for that person, leaving every session as it was. An RP uses
it when an action at one terminal needs a second person's approval.

Use a separate portal Application for it (its own client id and secret), so an
authorize-only id_token can never be mistaken for a sign-in. One approval runs:

1. :class:`AuthorizeOnlyRequest` makes the request's secrets (``state``,
   ``nonce``, the PKCE ``code_verifier``) for one approval; keep what
   :func:`failed_check` and :meth:`AuthorizeOnlyClient.redeem` need later
   server-side (the nonce only as its :func:`digest`, the verifier never
   leaving the server), and send the browser to
   :meth:`AuthorizeOnlyClient.authorization_url`.
2. On the callback, :meth:`AuthorizeOnlyClient.redeem` exchanges the code at
   the token endpoint and verifies the id_token's RS256 signature against the
   portal's keys, its ``iss``, ``aud`` and ``exp``, and that it carries every
   claim of :data:`REQUIRED_CLAIMS`.
3. :func:`failed_check` checks what binds the answer to the request: ``nonce``,
   ``acr``, no ``sid``, ``amr``, ``auth_time``, ``binding_message``, ``jti``
   and the shape of ``groups``.

What the person may approve (their ``groups``) is the RP's decision.
"""

import base64
import datetime
import hashlib
import hmac
import secrets
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, field
from typing import Any, Final
from urllib.parse import urlencode

import jwt
import requests

from sso_portal_client import oidc
from sso_portal_client.conf import portal_origin

#: The ``acr`` of an id_token from the authorize-only endpoint; an ordinary sign-in's id_token has none.
ACR: Final = 'urn:mec:authorize-only'
#: The endpoint's path on the portal's app origin.
PATH: Final = '/switch/authorize/'
#: How a person may identify there, as ``amr`` names it: store PIN, QR on their phone, password, LINE.
METHODS: Final = ('pin', 'qr', 'pwd', 'line')
#: The longest ``binding_message`` the portal accepts and shows ("Approve: ...").
BINDING_MESSAGE_MAX_LENGTH: Final = 60
#: How old the identification may be when :func:`failed_check` reads it, by default.
FRESH_SECONDS: Final = 120
#: What the id_token must carry for :meth:`AuthorizeOnlyClient.redeem` to return it.
REQUIRED_CLAIMS: Final = ('exp', 'iat', 'iss', 'aud', 'sub')

#: :attr:`AuthorizeOnlyError.reason` when the portal could not be asked, or answered with no id_token.
PORTAL_UNAVAILABLE: Final = 'portal_unavailable'
#: :attr:`AuthorizeOnlyError.reason` when the id_token does not verify.
INVALID_TOKEN: Final = 'invalid_token'  # noqa: S105 # nosec B105  # a reason name, not a secret


class AuthorizeOnlyError(Exception):
    """The portal could not be asked (:data:`PORTAL_UNAVAILABLE`), or answered with an id_token that does not
    verify (:data:`INVALID_TOKEN`)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def digest(value: str) -> str:
    """The sha256 of ``value``, hex: how a request's ``state`` or ``nonce`` is kept server-side."""
    return hashlib.sha256(value.encode()).hexdigest()


def code_challenge(verifier: str) -> str:
    """The PKCE ``S256`` challenge of ``verifier``."""
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()


def default_authorize_url() -> str:
    """The endpoint on the portal's app origin (``SSO_PORTAL_CLIENT['SERVER_URL']``'s)."""
    return f'{portal_origin()}{PATH}'


def _token() -> str:
    return secrets.token_urlsafe(32)


def _verifier() -> str:
    return secrets.token_urlsafe(64)


@dataclass(frozen=True, kw_only=True)
class AuthorizeOnlyRequest:
    """One request to the endpoint, for one approval. ``state``, ``nonce`` and ``code_verifier`` are made fresh
    unless given; every new request replaces the secrets of the last."""

    #: Registered on the authorize-only Application.
    redirect_uri: str
    #: What the person approving is shown ("Approve: ..."), at most :data:`BINDING_MESSAGE_MAX_LENGTH` characters;
    #: empty sends none.
    binding_message: str = ''
    #: A portal username to preselect on the PIN list; empty sends none.
    login_hint: str = ''
    # The request's secrets stay out of its repr, so a log line or traceback never carries them.
    state: str = field(default_factory=_token, repr=False)
    nonce: str = field(default_factory=_token, repr=False)
    #: The PKCE verifier: kept server-side, sent only with the code.
    code_verifier: str = field(default_factory=_verifier, repr=False)

    def __post_init__(self) -> None:
        if len(self.binding_message) > BINDING_MESSAGE_MAX_LENGTH:
            msg = f'binding_message is longer than {BINDING_MESSAGE_MAX_LENGTH} characters.'
            raise ValueError(msg)

    @property
    def code_challenge(self) -> str:
        return code_challenge(self.code_verifier)


class AuthorizeOnlyClient:
    """The authorize-only endpoint for one portal Application. Discovery and the portal's keys come from
    :mod:`sso_portal_client.oidc`, cached per process, so a client is cheap to make per call."""

    def __init__(self, *, client_id: str, client_secret: str, authorize_url: str = '') -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.authorize_url = authorize_url or default_authorize_url()

    def authorization_url(self, request: AuthorizeOnlyRequest, *, display: str = 'popup') -> str:
        """The URL that opens the endpoint for ``request``; ``display='page'`` for a full-page navigation."""
        query = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': request.redirect_uri,
            'scope': 'openid profile',
            'state': request.state,
            'nonce': request.nonce,
            'code_challenge': request.code_challenge,
            'code_challenge_method': 'S256',
            'prompt': 'login',
            'max_age': '0',
            'display': display,
        }
        if request.binding_message:
            query['binding_message'] = request.binding_message
        if request.login_hint:
            query['login_hint'] = request.login_hint
        return f'{self.authorize_url}?{urlencode(query)}'

    def redeem(self, *, code: str, code_verifier: str, redirect_uri: str) -> dict[str, Any]:
        """The claims of the id_token ``code`` is exchanged for: its RS256 signature, ``iss``, ``aud`` (this client)
        and ``exp`` verified, and every claim of :data:`REQUIRED_CLAIMS` present. Raises :class:`AuthorizeOnlyError`.

        Only what the portal alone can vouch for is checked here; :func:`failed_check` checks the rest against the
        request."""
        try:
            document = oidc.discovery()
        except oidc.UpstreamFetchError as error:
            raise AuthorizeOnlyError(PORTAL_UNAVAILABLE) from error
        token_endpoint = document.get('token_endpoint')
        if not isinstance(token_endpoint, str) or not token_endpoint:
            raise AuthorizeOnlyError(PORTAL_UNAVAILABLE)
        try:
            response = requests.post(
                token_endpoint,
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': redirect_uri,
                    'code_verifier': code_verifier,
                },
                auth=(self.client_id, self.client_secret),
                timeout=oidc.HTTP_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            token = response.json()['id_token']
        except (requests.RequestException, ValueError, KeyError, TypeError) as error:
            raise AuthorizeOnlyError(PORTAL_UNAVAILABLE) from error
        if not isinstance(token, str):
            raise AuthorizeOnlyError(PORTAL_UNAVAILABLE)
        try:
            # The token came straight from the token endpoint, so an unknown kid means a key the portal just
            # rotated in: fetch the set again at once.
            key = oidc.jwk_client(document['jwks_uri'], refetch_cooldown=False).get_signing_key_from_jwt(token)
            claims: dict[str, Any] = jwt.decode(
                token,
                key.key,
                algorithms=['RS256'],
                audience=self.client_id,
                issuer=document['issuer'],
                options={'require': list(REQUIRED_CLAIMS)},
            )
        except oidc.UpstreamFetchError as error:
            raise AuthorizeOnlyError(PORTAL_UNAVAILABLE) from error
        except jwt.PyJWTError as error:
            raise AuthorizeOnlyError(INVALID_TOKEN) from error
        return claims


def _fresh(auth_time: object, *, requested_at: datetime.datetime, now: datetime.datetime, fresh_seconds: int) -> bool:
    if not isinstance(auth_time, int) or isinstance(auth_time, bool):
        return False
    moment = now.timestamp()
    # A second of slack for the portal's clock rounding down to the whole second.
    return int(requested_at.timestamp()) <= auth_time <= moment + 1 and moment - auth_time <= fresh_seconds


def failed_check(
    claims: Mapping[str, Any],
    *,
    nonce_digest: str,
    binding_message: str,
    requested_at: datetime.datetime,
    now: datetime.datetime,
    methods: Collection[str] = METHODS,
    fresh_seconds: int = FRESH_SECONDS,
    jti_used: Callable[[str], bool] | None = None,
) -> str:
    """The first check the id_token's ``claims`` fail for the request they answer, by name; empty when they pass
    them all.

    In order: ``nonce`` (its :func:`digest` is ``nonce_digest``), ``acr`` (:data:`ACR`, so an ordinary sign-in
    never approves), ``sid`` (absent), ``amr`` (names one of ``methods``), ``auth_time`` (no earlier than
    ``requested_at``, not after ``now``, at most ``fresh_seconds`` old), ``binding_message`` (exactly the one sent;
    absent when none was), ``jti`` (present, and not one ``jti_used`` says was used already) and ``groups`` (a list
    when present).
    """
    nonce = claims.get('nonce')
    amr = claims.get('amr')
    jti = claims.get('jti')
    checks = (
        ('nonce', isinstance(nonce, str) and hmac.compare_digest(digest(nonce), nonce_digest)),
        ('acr', claims.get('acr') == ACR),
        ('sid', 'sid' not in claims),
        ('amr', isinstance(amr, list) and any(method in methods for method in amr)),
        (
            'auth_time',
            _fresh(claims.get('auth_time'), requested_at=requested_at, now=now, fresh_seconds=fresh_seconds),
        ),
        ('binding_message', claims.get('binding_message') == (binding_message or None)),
        ('jti', isinstance(jti, str) and bool(jti) and not (jti_used is not None and jti_used(jti))),
        ('groups', isinstance(claims.get('groups', []), list)),
    )
    return next((name for name, passed in checks if not passed), '')
