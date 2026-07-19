"""Minimal views backing tests/urls.py — exercised only by the test suite.

Not part of the package's public surface; these exist purely to give
test_middleware.py / test_templatetags.py a response/template to assert
against.
"""

from django.http import HttpRequest, HttpResponse
from django.shortcuts import render


def plain(request: HttpRequest) -> HttpResponse:
    """A view that touches nothing SSO-specific — for the COOP-header and
    zero-query-when-untouched tests."""
    return HttpResponse('ok')


def explicit_coop(request: HttpRequest) -> HttpResponse:
    """A view that sets its own COOP header before PortalSwitchMiddleware's
    process-response code runs — must survive untouched."""
    response = HttpResponse('ok')
    response['Cross-Origin-Opener-Policy'] = 'unsafe-none'
    return response


def touches_portal_user(request: HttpRequest) -> HttpResponse:
    """Forces resolution of the lazy request.portal_user (for contrast with
    `plain`, which must run zero extra queries)."""
    portal_user = request.portal_user  # type: ignore[attr-defined]
    return HttpResponse('yes' if portal_user else 'no')


def widget(request: HttpRequest) -> HttpResponse:
    """Renders {% portal_switch_widget %} with default kwargs."""
    return render(request, 'tests/widget.html', {})


def widget_with_kwargs(request: HttpRequest) -> HttpResponse:
    """Renders {% portal_switch_widget %} with require_session/strategy set."""
    return render(request, 'tests/widget_with_kwargs.html', {})
