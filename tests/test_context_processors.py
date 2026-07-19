"""``sso_portal_client.context_processors.portal_user``."""

from django.http import HttpRequest

from sso_portal_client.context_processors import portal_user


def test_returns_request_portal_user_when_present():
    request = HttpRequest()
    request.portal_user = {'username': 'alice-portal'}  # type: ignore[attr-defined]
    assert portal_user(request) == {'portal_user': {'username': 'alice-portal'}}


def test_none_when_middleware_absent():
    # No PortalSwitchMiddleware in the request pipeline that produced this
    # request -> no portal_user attribute at all; must not raise.
    request = HttpRequest()
    assert portal_user(request) == {'portal_user': None}
