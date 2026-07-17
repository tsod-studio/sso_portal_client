"""Read the portal's OIDC claims for a user, straight from allauth storage.

The claims delivered at login (id_token + userinfo) are persisted verbatim
in ``SocialAccount.extra_data`` — a JSON field. That blob is the raw record
of what the portal asserted; nothing needs a dedicated column on the RP
unless Django's own machinery reads it (groups, is_staff, the User basics —
which :mod:`sso_portal_client.sync` materializes on every login).

Everything else — ``picture``, ``locale``, and any claim the portal adds in
the future — should be read on demand through these helpers, giving RPs a
zero-migration path to new claims.

allauth 65 stores ``{'userinfo': {...}, 'id_token': {...}}``; earlier
versions used a flat layout. ``id_token`` wins (signed, authoritative),
then ``userinfo``, then the legacy flat dict.
"""

from __future__ import annotations

from typing import Any

PROVIDER_ID = 'sso_portal'


def get_claims(user: Any) -> dict[str, Any]:
    """Merged portal claims for ``user`` (id_token over userinfo over legacy).

    Returns an empty dict for anonymous users or users without a linked
    portal account.
    """
    if not getattr(user, 'is_authenticated', False):
        return {}
    account = user.socialaccount_set.filter(provider=PROVIDER_ID).first()
    if account is None:
        return {}
    data = account.extra_data or {}
    merged: dict[str, Any] = {}
    for container in (data, data.get('userinfo'), data.get('id_token')):
        if isinstance(container, dict):
            merged.update({k: v for k, v in container.items() if k not in ('userinfo', 'id_token')})
    return merged


def get_claim(user: Any, name: str, default: Any = None) -> Any:
    """A single portal claim for ``user`` (e.g. ``'picture'``, ``'locale'``)."""
    return get_claims(user).get(name, default)
