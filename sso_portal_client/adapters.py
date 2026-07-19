"""Stable, collision-free RP-local usernames for portal logins.

Wire it up with::

    SOCIALACCOUNT_ADAPTER = 'sso_portal_client.adapters.SocialAccountAdapter'

(see README "Settings (the whole integration)" and "Stable usernames
(USERNAME_STRATEGY)"). Everything here is verified against allauth 65.18
source, same house style as the rest of this package (conf.py, receivers.py).

Where ``populate_user`` plugs in
(``socialaccount/providers/base/provider.py Provider.sociallogin_from_response``)::

    socialaccount = SocialAccount(extra_data=..., uid=self.extract_uid(response), provider=self.sub_id)
    ...
    sociallogin = SocialLogin(provider=self, account=socialaccount, ...)
    user = sociallogin.user = adapter.new_user(request, sociallogin)
    adapter.populate_user(request, sociallogin, common_fields)

Two things follow from that:

- ``sociallogin.account.uid`` and ``sociallogin.account.provider`` are both
  already set by the time ``populate_user`` runs — no need to re-derive
  either from ``extra_data``.
- ``OpenIDConnectProvider.extract_uid`` (providers/openid_connect/provider.py)
  returns ``str(data[self.app.settings.get("uid_field", "sub")])``, i.e.
  ``account.uid`` IS the ``sub`` claim allauth itself already extracted for
  us (authoritative even under a non-default ``uid_field`` override) — so
  this reads ``sociallogin.account.uid`` rather than re-parsing claims.
  ``Provider.sub_id`` (providers/base/provider.py) returns
  ``app.provider_id``, matching ``conf.PROVIDER_ID`` — the same identity
  ``receivers.py`` filters logins on.

What ``DefaultSocialAccountAdapter.populate_user`` does today
(``socialaccount/adapter.py``, ``providers/openid_connect/provider.py
extract_common_fields``): it maps ``username`` (from the ``preferred_username``
claim), ``email`` (from ``email``), and ``first_name``/``last_name`` (from
``given_name``/``family_name``, falling back to splitting the ``name`` claim
on the first space when either is absent) onto the unsaved user instance via
``user_username``/``user_email``/``user_field``. Calling ``super()`` first
keeps all of that — this override only overwrites the username afterwards,
and only for the portal's provider.

Collision handling today (what strategy ``'preferred_username'`` keeps):
``socialaccount/internal/flows/signup.py process_signup`` re-validates the
already-populated username with ``clean_username()`` — non-shallow this
time, so it DOES hit the DB — and on a collision clears it
(``user_username(user, "")``); ``DefaultSocialAccountAdapter.save_user`` (no
form, auto-signup) then falls through to ``account/adapter.py
populate_username`` -> ``generate_unique_username(...)``, which mints a
``name1``/``name2``-style deduped suffix. That path only fires on an actual
collision. Because ``preferred_username`` is a live, mutable portal profile
field, two failure modes follow: a renamed portal account can collide with
what is now a stranger's RP row and land a different username than before,
and an old RP row's username can later be handed to an unrelated new portal
user once the original renames away. ``'sub_at_issuer'`` (the new default)
sidesteps both: the value is derived from the immutable ``sub`` plus the
issuer host, so it can never collide with another portal user's username and
never touches the dedupe path at all.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from allauth.account.utils import user_username
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.utils import get_username_max_length
from django.core.exceptions import ImproperlyConfigured

from sso_portal_client.conf import PROVIDER_ID, get_settings, username_strategy

if TYPE_CHECKING:
    from django.http import HttpRequest


def _issuer_host() -> str:
    """Hostname of the configured issuer, derived from SERVER_URL.

    No new setting: SERVER_URL is already required by conf.get_settings(),
    and it already IS the issuer (see conf.discovery_url).
    """
    server_url: str = get_settings()['SERVER_URL']
    host = urlsplit(server_url).hostname
    if not host:
        msg = f"Cannot derive an issuer host from SSO_PORTAL_CLIENT['SERVER_URL'] = {server_url!r}."
        raise ImproperlyConfigured(msg)
    return host


class SocialAccountAdapter(DefaultSocialAccountAdapter):
    """Overrides only the username; everything else is stock allauth."""

    def populate_user(self, request: HttpRequest, sociallogin: Any, data: dict[str, Any]) -> Any:
        user = super().populate_user(request, sociallogin, data)
        if sociallogin.account.provider != PROVIDER_ID:
            return user
        if username_strategy() == 'preferred_username':
            return user

        # account.uid is the `sub` claim (see module docstring); the account
        # is already constructed with it by the time populate_user() runs.
        sub = sociallogin.account.uid
        candidate = f'{sub}@{_issuer_host()}'
        max_length = get_username_max_length()
        if len(candidate) > max_length:
            # Silently truncating would throw away exactly the bytes that
            # make the identifier unique — fail loudly instead so a real
            # RP notices at signup time rather than shipping silent
            # username collisions.
            msg = (
                f'Portal username {candidate!r} is {len(candidate)} chars, over the '
                f"{max_length}-char limit of this project's username field. Widen the "
                "User model's username field, or set SSO_PORTAL_CLIENT['USERNAME_STRATEGY'] "
                "= 'preferred_username' to accept a shorter, non-stable identifier instead."
            )
            raise ImproperlyConfigured(msg)
        # user_username() lowercases (unless ACCOUNT_PRESERVE_USERNAME_CASING),
        # harmless here: a UUID sub and a DNS hostname are both already
        # case-insensitive identifiers.
        user_username(user, candidate)
        return user
