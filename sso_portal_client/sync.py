"""Group membership sync from the portal's ``groups`` OIDC claim.

Contract (sso_portal docs/app-integration-guide.md §7 "overwrite, not
append"): the ``groups`` claim is computed fresh from the portal's current
group membership on every login, so the RP must *replace* the derived state
each time — otherwise a user removed from a portal group keeps the local
permission forever.
"""

from typing import Any

from django.contrib.auth.models import Group

from sso_portal_client.conf import get_settings


def _resolve_groups(names: list[str]) -> list[Group]:
    """Map group names to Group rows, creating missing ones.

    One query fetches all existing rows; only genuinely missing names hit
    get_or_create (race-safe), so re-logins cost a single lookup query.
    """
    existing = {group.name: group for group in Group.objects.filter(name__in=names)}
    return [existing.get(name) or Group.objects.get_or_create(name=name)[0] for name in names]


def sync_user_groups(user: Any, claims: dict[str, Any]) -> None:
    """Sync ``user``'s Django groups (and staff/superuser flags) from claims.

    Pure function of (user, claims) + the SSO_PORTAL_CLIENT settings:

    - GROUP_PREFIX is None (default): the portal is the sole authority —
      membership is overwritten wholesale with the claim's groups.
    - GROUP_PREFIX = 'x-': only the namespace is managed — prefix-matching
      claim groups are added, the user's other 'x-*' memberships are removed,
      and both non-prefix local groups and non-prefix claim groups are left
      untouched.
    - STAFF_GROUPS / SUPERUSER_GROUPS non-empty: the boolean is set from the
      intersection with the claim's groups (grants AND revokes). Empty list
      (default): the flag is never touched.
    """
    cfg = get_settings()
    claim_groups = [name for name in (claims.get('groups') or []) if name]

    prefix = cfg['GROUP_PREFIX']
    if prefix is None:
        user.groups.set(_resolve_groups(claim_groups))
    else:
        managed = [name for name in claim_groups if name.startswith(prefix)]
        stale = list(user.groups.filter(name__startswith=prefix).exclude(name__in=managed))
        if stale:
            user.groups.remove(*stale)
        target = _resolve_groups(managed)
        if target:
            user.groups.add(*target)

    update_fields = []
    claim_set = set(claim_groups)
    for flag, setting_key in (('is_staff', 'STAFF_GROUPS'), ('is_superuser', 'SUPERUSER_GROUPS')):
        configured = cfg[setting_key]
        if not configured:
            continue
        desired = bool(claim_set & set(configured))
        if getattr(user, flag) != desired:
            setattr(user, flag, desired)
            update_fields.append(flag)
    if update_fields:
        user.save(update_fields=update_fields)
