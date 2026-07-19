"""SampleStore views — plain Django authorization, nothing SSO-specific.

The point of the demo: ``/admin-area/`` is gated with a stock
``@permission_required`` decorator. No view here inspects an OIDC claim or a
group name. The ``store.view_admin_area`` permission reaches a user purely
because ``sso_portal_client`` synced them into the ``samplestore-admin`` group
(which owns that permission — see ``migrations/0002_admin_group.py``).

The store-switch widget's COOP header, ``currentUser``, static/app origins,
and login URL used to be hand-rolled here (see git history pre-widget-
integration-kit for the old ``_portal_origin``/``_portal_static_origin``
helpers and the manual ``json_script`` plumbing in ``index.html``) — that
whole error-prone surface is now ``sso_portal_client.middleware.
PortalSwitchMiddleware`` (COOP + ``request.portal_user``, wired in
``config/settings.py``) plus the ``{% portal_switch_widget %}`` tag, mounted
once, site-wide, in ``templates/store/base.html``. This view only supplies
what the widget's config can't derive: nothing, now — it is pure Django
authorization.
"""

from django.contrib.auth.decorators import login_required, permission_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

ADMIN_PERMISSION = 'store.view_admin_area'


def index(request: HttpRequest) -> HttpResponse:
    """Landing page: login state + the user's synced groups and flags."""
    context: dict[str, object] = {}
    if request.user.is_authenticated:
        context['group_names'] = sorted(request.user.groups.values_list('name', flat=True))
        context['admin_permission'] = ADMIN_PERMISSION
    return render(request, 'store/index.html', context)


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
