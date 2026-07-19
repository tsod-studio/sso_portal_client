"""``PortalSwitchMiddleware`` — the two pieces of per-request plumbing every
RP embedding the switch widget used to hand-roll: the popup-friendly COOP
header, and a lazily-resolved ``request.portal_user`` for ``currentUser``.

MIDDLEWARE ordering (verified against the installed Django, 6.0.7,
``django/middleware/security.py``)
------------------------------------------------------------------------

``SecurityMiddleware.process_response`` does **not** unconditionally
overwrite the COOP header — it calls::

    response.setdefault('Cross-Origin-Opener-Policy', self.cross_origin_opener_policy)

i.e. ``HttpResponseBase.setdefault`` ("Set a header unless it has already
been set"), not a plain assignment. Since it never overwrites, the only
thing that matters is *who sets the header first* during the response
phase — and Django runs ``process_response`` in the **reverse** of
``MIDDLEWARE``'s order (the entry closest to the view unwinds first).

This middleware therefore MUST be placed **after**
``django.middleware.security.SecurityMiddleware`` in ``MIDDLEWARE`` (i.e.
closer to the view / later in the list)::

    MIDDLEWARE = [
        ...
        'django.middleware.security.SecurityMiddleware',
        ...
        'sso_portal_client.middleware.PortalSwitchMiddleware',   # AFTER SecurityMiddleware
        ...
    ]

Positioned there, this middleware's own response-phase code runs *before*
SecurityMiddleware's on the way back out, so its own ``response.setdefault(...)``
call wins the race and SecurityMiddleware's later ``same-origin`` default
becomes a no-op. Using ``setdefault`` ourselves (rather than a plain
assignment) is what gives the precedence rule its other half for free: a
view that explicitly sets its own ``Cross-Origin-Opener-Policy`` before
returning is *never* overwritten, by either middleware — whichever header
value exists first when this middleware's ``process_response``-equivalent
code runs is the one that ships. (Swap the two middlewares' order and this
inverts: SecurityMiddleware would set its ``same-origin`` default first,
and this middleware's own ``setdefault`` would then no-op against it.)

Opt out entirely with ``SSO_PORTAL_CLIENT['SET_COOP_HEADER'] = False`` (e.g.
an RP that sets its own COOP policy globally via ``SECURE_CROSS_ORIGIN_OPENER_POLICY``
and never wants this middleware to touch it).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.utils.functional import SimpleLazyObject

from sso_portal_client.claims import get_claims
from sso_portal_client.conf import get_settings

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.http import HttpRequest, HttpResponse

COOP_HEADER = 'Cross-Origin-Opener-Policy'
COOP_VALUE = 'same-origin-allow-popups'


def _resolve_portal_user(request: HttpRequest) -> dict[str, Any] | None:
    """The value ``request.portal_user`` lazily resolves to.

    ``None`` when the session is not portal-backed: anonymous, or a local/
    other-provider account with no linked ``sso_portal`` ``SocialAccount``
    (``claims.get_claims`` already returns ``{}`` for both — see its
    docstring). Otherwise a plain ``{'username', 'name', 'picture', 'locale'}``
    dict built straight from the portal's OIDC claims — never from
    ``user.username``/``user.get_full_name()`` alone, which is the classic
    bug this package's widget integration kit exists to prevent (an RP-local
    username, e.g. a `{sub}@{issuer-host}` value under the default
    ``USERNAME_STRATEGY``, is not the portal's own identity and must never
    reach the switch widget's ``currentUser``).
    """
    # Typed loosely on purpose: request.user is AnonymousUser or an instance
    # of settings.AUTH_USER_MODEL (django-stubs' `_AnyUser`), and
    # AnonymousUser has no get_full_name() — claims.get_claims() itself
    # takes an equally loose parameter (see its docstring) for the same
    # reason.
    user: Any = request.user
    if not getattr(user, 'is_authenticated', False):
        return None
    portal_claims = get_claims(user)
    if not portal_claims:
        return None
    name = portal_claims.get('name') or user.get_full_name() or portal_claims.get('preferred_username') or ''
    return {
        'username': portal_claims.get('preferred_username'),
        'name': name,
        'picture': portal_claims.get('picture'),
        'locale': portal_claims.get('locale'),
    }


class PortalSwitchMiddleware:
    """Attaches ``request.portal_user`` and sets the switch-popup COOP header.

    See the module docstring for the required ``MIDDLEWARE`` position
    (after ``SecurityMiddleware``) and the header precedence rule.

    ``request.portal_user`` is a ``SimpleLazyObject`` — resolving it runs one
    query (``claims.get_claims`` -> ``SocialAccount`` lookup), so a page that
    never reads ``request.portal_user`` (directly, via the ``portal_user``
    context processor, or via the ``{% portal_switch_widget %}`` tag) pays
    nothing for it.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Dynamic request attribute (no django-stubs declaration) — same
        # pattern as sso_portal's apps/store_switch/middleware.py
        # request.source_ip. Only this assignment site needs the
        # suppression; every read site uses getattr(request, 'portal_user', None).
        request.portal_user = SimpleLazyObject(lambda: _resolve_portal_user(request))  # type: ignore[attr-defined]
        response = self.get_response(request)
        if get_settings()['SET_COOP_HEADER']:
            response.setdefault(COOP_HEADER, COOP_VALUE)
        return response
