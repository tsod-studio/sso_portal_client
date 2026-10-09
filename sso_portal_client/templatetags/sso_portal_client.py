"""``{% portal_switch_widget %}`` — the whole switch-widget wiring in one tag.

Encodes the "two settings lines and one template tag" integration kit: the
COOP header and ``request.portal_user`` come from ``PortalSwitchMiddleware``
(see ``middleware.py``); this tag renders the two remaining hand-written,
error-prone pieces every RP used to duplicate — the widget's ``<script
src>`` tags and its ``PortalSwitchWidget.init({...})`` call, with
``portalOrigin``/``staticOrigin`` from ``conf.py``, ``loginUrl`` computed
server-side (allauth's provider login URL + ``next=<current path>``,
so a switch/sign-in lands the browser back where it started), ``currentUser``
from ``request.portal_user`` (``None`` -> anonymous-mode widget), and
``sessionPingUrl`` / ``localLogoutUrl`` reversed from this package's own
views, with ``csrfToken`` generated for the request's local logout POST.

Deliberately narrow surface: only ``require_session`` and ``strategy`` are
exposed as tag kwargs — the two options most RPs actually need to flip.
switch-widget.js has many more (``mount``, ``zIndex``, ``texts``,
``features``, ``lang``, ...; see its own docstring in the portal's
``static/js/switch-widget.js``) — an RP that needs any of those keeps
hand-initializing the widget directly, the same way it always could; this
tag is a convenience for the common case, not a full mirror of every option.

Load it: ``{% load sso_portal_client %}{% portal_switch_widget %}``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from allauth.socialaccount.adapter import get_adapter
from django import template
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.middleware.csrf import get_token
from django.urls import reverse

from sso_portal_client.conf import PROVIDER_ID, portal_origin, static_origin

if TYPE_CHECKING:
    from django.http import HttpRequest

register = template.Library()


def _login_url(request: HttpRequest) -> str:
    """allauth's login URL for the portal provider, ``process=login`` plus
    ``next=<current full path>`` (URL-encoded by ``get_login_url`` itself) —
    the return-to-origin pattern from the portal's integration guide §5, so
    a switch or fresh sign-in lands the browser back on the page it left
    instead of always the site default.
    """
    provider = get_adapter().get_provider(request, PROVIDER_ID)
    login_url: str = provider.get_login_url(
        request,
        process='login',
        **{REDIRECT_FIELD_NAME: request.get_full_path()},
    )
    return login_url


@register.inclusion_tag('sso_portal_client/switch_widget.html', takes_context=True)
def portal_switch_widget(
    context: template.Context, *, require_session: bool = False, strategy: str = ''
) -> dict[str, Any]:
    """Render the switch-widget ``<script>`` tags + ``PortalSwitchWidget.init(...)``.

    ``require_session`` / ``strategy`` map straight onto the widget's own
    ``requireSession`` / ``strategy`` init options (see module docstring for
    why the surface stops there).
    """
    request = context['request']
    # SimpleLazyObject (see middleware.py): truthiness is what forces
    # resolution (its __bool__ is proxied to the wrapped value's), NOT an
    # `is None` check, which would always be False for the wrapper itself
    # regardless of what it wraps. Pages that never call this tag (or read
    # request.portal_user another way) never pay this query.
    lazy_portal_user = getattr(request, 'portal_user', None)
    current_user = None
    if lazy_portal_user:
        # Rebuilt as a plain dict (not the lazy wrapper) so json_script's
        # json.dumps sees an ordinary, safely-serializable value.
        current_user = {
            'username': lazy_portal_user['username'],
            'name': lazy_portal_user['name'],
            'picture': lazy_portal_user['picture'],
            'locale': lazy_portal_user['locale'],
        }
    return {
        'portal_origin': portal_origin(),
        'static_origin': static_origin(),
        'login_url': _login_url(request),
        'current_user': current_user,
        'session_ping_url': reverse('sso_portal_client:session_ping'),
        'local_logout_url': reverse('sso_portal_client:local_logout'),
        'widget_csrf_token': get_token(request),
        'require_session': require_session,
        'strategy': strategy,
    }
