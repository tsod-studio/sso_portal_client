"""Template context processor exposing ``request.portal_user``.

Add to ``TEMPLATES[0]['OPTIONS']['context_processors']``::

    'sso_portal_client.context_processors.portal_user',

Then any template can read ``{{ portal_user.name }}`` etc. without a view
threading it through by hand. Graceful when ``PortalSwitchMiddleware`` (see
``middleware.py``) is not installed — ``portal_user`` is simply ``None``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from django.http import HttpRequest


def portal_user(request: HttpRequest) -> dict[str, Any]:
    """``{'portal_user': request.portal_user}``, or ``None`` when absent."""
    return {'portal_user': getattr(request, 'portal_user', None)}
