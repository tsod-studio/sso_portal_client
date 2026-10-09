"""CSRF-protected, idempotent RP-local logout without a portal redirect."""

from typing import Any

import pytest
from django.contrib.sessions.models import Session
from django.middleware.csrf import get_token
from django.test import Client, RequestFactory
from django.urls import reverse

from sso_portal_client.models import PortalSession
from tests.test_views import make_session

pytestmark = pytest.mark.django_db
LOCAL_LOGOUT_URL = '/sso/local-logout/'


@pytest.fixture
def browser() -> Client:
    return Client(enforce_csrf_checks=True)


def csrf_header(browser: Client) -> str:
    request = RequestFactory().get('/')
    token = get_token(request)
    browser.cookies['csrftoken'] = request.META['CSRF_COOKIE']
    return token


def test_local_logout_url_name() -> None:
    assert reverse('sso_portal_client:local_logout') == LOCAL_LOGOUT_URL


def test_local_logout_ends_only_current_session(browser: Client, user: Any) -> None:
    browser.force_login(user)
    key = browser.session.session_key
    other_key = make_session()
    PortalSession.objects.create(user=user, sid='shared-sid', session_key=key)
    PortalSession.objects.create(user=user, sid='shared-sid', session_key=other_key)

    response = browser.post(LOCAL_LOGOUT_URL, HTTP_X_CSRFTOKEN=csrf_header(browser))

    assert response.status_code == 204
    assert response.content == b''
    assert 'Location' not in response.headers
    assert '_auth_user_id' not in browser.session
    assert not Session.objects.filter(session_key=key).exists()
    assert not PortalSession.objects.filter(session_key=key).exists()
    assert Session.objects.filter(session_key=other_key).exists()
    assert PortalSession.objects.filter(session_key=other_key).exists()


def test_local_logout_anonymous_is_idempotent(browser: Client) -> None:
    token = csrf_header(browser)
    for _ in range(2):
        response = browser.post(LOCAL_LOGOUT_URL, HTTP_X_CSRFTOKEN=token)
        assert response.status_code == 204
        assert response.content == b''


def test_local_logout_anonymous_session_tracking_is_removed(browser: Client, user: Any) -> None:
    session = browser.session
    session['seen'] = True
    session.save()
    key = session.session_key
    PortalSession.objects.create(user=user, sid='anonymous-sid', session_key=key)
    assert browser.post(LOCAL_LOGOUT_URL, HTTP_X_CSRFTOKEN=csrf_header(browser)).status_code == 204
    assert not PortalSession.objects.filter(session_key=key).exists()
    assert not Session.objects.filter(session_key=key).exists()


def test_local_logout_get_is_405(browser: Client) -> None:
    response = browser.get(LOCAL_LOGOUT_URL)
    assert response.status_code == 405
    assert response.headers['Allow'] == 'POST'


@pytest.mark.parametrize('authenticated', [True, False])
def test_local_logout_missing_csrf_is_403(browser: Client, user: Any, *, authenticated: bool) -> None:
    if authenticated:
        browser.force_login(user)
        key = browser.session.session_key
        PortalSession.objects.create(user=user, sid='protected-sid', session_key=key)
    response = browser.post(LOCAL_LOGOUT_URL)
    assert response.status_code == 403
    if authenticated:
        assert '_auth_user_id' in browser.session
        assert PortalSession.objects.filter(session_key=key).exists()


def test_local_logout_wrong_csrf_is_403(browser: Client) -> None:
    csrf_header(browser)
    assert browser.post(LOCAL_LOGOUT_URL, HTTP_X_CSRFTOKEN='invalid').status_code == 403
