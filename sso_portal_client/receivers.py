"""Signal receivers that run group sync on every portal login.

Connected in ``SsoPortalClientConfig.ready()`` to two allauth signals
(verified against allauth 65.18 source):

- ``allauth.account.signals.user_logged_in`` — sent by
  ``account/adapter.py:post_login`` on EVERY completed login. For social
  logins the socialaccount flows pass ``sociallogin`` through
  ``signal_kwargs`` (``socialaccount/internal/flows/login.py:_login`` for
  repeat logins, ``flows/signup.py:complete_social_signup`` for the first
  login), so both first and subsequent portal logins land here.
- ``allauth.socialaccount.signals.social_account_added`` — sent when an
  existing local user *connects* the portal account (AuthProcess.CONNECT),
  a flow that completes without a ``user_logged_in`` send.

Claims location (allauth 65.18, ``openid_connect`` provider): the adapter's
``complete_login`` stores ``{'userinfo': ..., 'id_token': ...}`` in
``SocialAccount.extra_data`` — ``userinfo`` is the userinfo-endpoint
response, ``id_token`` the *decoded* id_token claims. The portal serves
``groups`` in both (its ``oidc_claim_scope`` maps groups→profile and DOT
runs ``get_additional_claims`` for userinfo too), while ``sid``/``amr``
appear only in the id_token. ``SocialLogin.lookup()`` overwrites
``extra_data`` on every repeat login, so the claims are always fresh.
"""

import logging
from typing import Any

from sso_portal_client.conf import PROVIDER_ID
from sso_portal_client.models import PortalSession
from sso_portal_client.signals import claims_synced
from sso_portal_client.sync import sync_user_groups

logger = logging.getLogger(__name__)


def _extract_claims(sociallogin: Any) -> dict[str, Any]:
    """Merge the sociallogin's persisted claims into one flat dict.

    id_token claims win over userinfo: the id_token is the only source that
    can carry a trustworthy ``sid``/``amr`` (the portal never returns them
    from userinfo). Falls back to the flat pre-65.11 extra_data layout.
    """
    extra_data = sociallogin.account.extra_data or {}
    userinfo = extra_data.get('userinfo')
    id_token = extra_data.get('id_token')
    if isinstance(userinfo, dict) or isinstance(id_token, dict):
        claims: dict[str, Any] = {}
        if isinstance(userinfo, dict):
            claims.update(userinfo)
        if isinstance(id_token, dict):
            claims.update(id_token)
        return claims
    return dict(extra_data)


def _record_portal_session(request: Any, user: Any, claims: dict[str, Any]) -> None:
    """Remember sid -> session_key so back-channel logout can find us.

    Django's login() cycles the session key (and, for DB-backed sessions,
    saves immediately), so ``session_key`` is the fresh post-login key here.
    """
    sid = claims.get('sid')
    session = getattr(request, 'session', None)
    session_key = getattr(session, 'session_key', None)
    if not sid or not session_key:
        return
    PortalSession.objects.update_or_create(
        session_key=session_key,
        defaults={'sid': sid, 'user': user},
    )


def _handle_portal_login(request: Any, user: Any, sociallogin: Any) -> None:
    if sociallogin is None or sociallogin.account.provider != PROVIDER_ID:
        return
    claims = _extract_claims(sociallogin)
    sync_user_groups(user, claims)
    _record_portal_session(request, user, claims)
    claims_synced.send(sender=None, user=user, claims=claims)


def on_user_logged_in(sender: Any, request: Any, user: Any, **kwargs: Any) -> None:  # noqa: ARG001
    """Runs on every allauth login; no-op unless it is a portal social login."""
    _handle_portal_login(request, user, kwargs.get('sociallogin'))


def on_social_account_added(sender: Any, request: Any, sociallogin: Any, **kwargs: Any) -> None:  # noqa: ARG001
    """Runs when a logged-in local user connects the portal account."""
    _handle_portal_login(request, sociallogin.user, sociallogin)
