"""SampleStore views — plain Django authorization, nothing SSO-specific.

The point of the demo: ``/admin-area/`` is gated with a stock
``@permission_required`` decorator. No view here inspects an OIDC claim or a
group name. The ``store.view_admin_area`` permission reaches a user purely
because ``sso_portal_client`` synced them into the ``samplestore-admin`` group
(which owns that permission — see ``migrations/0002_admin_group.py``).
"""

from urllib.parse import urlparse

from django.contrib.auth.decorators import login_required, permission_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

from sso_portal_client.conf import get_settings

ADMIN_PERMISSION = 'store.view_admin_area'


def _portal_origin() -> str:
    """Portal origin (scheme://host[:port]) for the store-switch scripts,
    derived from SSO_PORTAL_CLIENT['SERVER_URL'] (the issuer, e.g. .../o).
    """
    parsed = urlparse(get_settings()['SERVER_URL'])
    return f'{parsed.scheme}://{parsed.netloc}'


def _portal_picture(user: object) -> str | None:
    """Best-effort avatar URL for the switch widget's badge.

    The portal issues a standard OIDC ``picture`` claim (a LINE avatar, when
    the user has a linked LINE social account). allauth 65 stores the token
    response under ``extra_data`` as ``{'userinfo': {...}, 'id_token': {...}}``;
    we check ``id_token`` first (authoritative, signed), then ``userinfo``, then
    a legacy flat layout where claims sit at the top level. Any absence (no
    social account, no claim) yields ``None`` and the widget falls back to
    initials.
    """
    account = user.socialaccount_set.filter(provider='sso_portal').first()  # type: ignore[attr-defined]
    if account is None:
        return None
    data = account.extra_data or {}
    for container in (data.get('id_token'), data.get('userinfo'), data):
        if isinstance(container, dict) and container.get('picture'):
            return container['picture']
    return None


def index(request: HttpRequest) -> HttpResponse:
    """Landing page: login state + the user's synced groups and flags."""
    context: dict[str, object] = {'portal_origin': _portal_origin()}
    if request.user.is_authenticated:
        context['group_names'] = sorted(request.user.groups.values_list('name', flat=True))
        context['admin_permission'] = ADMIN_PERMISSION
        context['portal_picture'] = _portal_picture(request.user)
    response = render(request, 'store/index.html', context)
    # The store-switch popup posts its ``sso:switched`` result back through
    # ``window.opener``. Django's SecurityMiddleware defaults every response to
    # ``Cross-Origin-Opener-Policy: same-origin``, which severs that opener for
    # the cross-origin portal popup — the message never arrives and the switch
    # silently fails (the page stays as it was, needing a second manual login
    # click). ``same-origin-allow-popups`` keeps this page isolated from being
    # opened BY others while still letting the popups IT opens keep their
    # opener. Any RP embedding the switch button/widget must do the same; see
    # static/js/switch.js's POPUP OPENER REQUIREMENT note on the portal.
    response['Cross-Origin-Opener-Policy'] = 'same-origin-allow-popups'
    return response


@login_required
@permission_required(ADMIN_PERMISSION, raise_exception=True)
def admin_area(request: HttpRequest) -> HttpResponse:
    """Staff-only area, gated by a standard Django permission.

    ``raise_exception=True`` makes a signed-in-but-unauthorized user get a 403
    (rendered by ``permission_denied`` below) instead of being bounced back to
    the login page — the latter would loop, since logging in again cannot grant
    a permission the portal has not.
    """
    return render(request, 'store/admin_area.html', {'admin_permission': ADMIN_PERMISSION})


def permission_denied(request: HttpRequest, exception: Exception | None = None) -> HttpResponse:  # noqa: ARG001
    """403 handler explaining that access derives from SSO group membership.

    Mirrors the Flask reference RP's denied page: shows the user's current
    Django groups (which the portal drives) so it is obvious the fix is a
    portal-side group change followed by a fresh login, not anything local.
    """
    group_names = sorted(request.user.groups.values_list('name', flat=True)) if request.user.is_authenticated else []
    context = {
        'group_names': group_names,
        'admin_permission': ADMIN_PERMISSION,
        'required_group': 'samplestore-admin',
    }
    return render(request, 'store/403.html', context, status=403)
