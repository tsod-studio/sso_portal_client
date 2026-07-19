"""PortalSwitchMiddleware: COOP header precedence + lazy request.portal_user.

tests/settings.py wires SecurityMiddleware (Django default:
SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin') followed by
PortalSwitchMiddleware, exactly as sso_portal_client/middleware.py's
docstring requires — these tests exercise the real ordering, not a mock.
"""

import pytest
from allauth.socialaccount.models import SocialAccount
from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext

from sso_portal_client.middleware import COOP_VALUE

pytestmark = pytest.mark.django_db

PLAIN_URL = '/plain/'
EXPLICIT_COOP_URL = '/explicit-coop/'
TOUCHES_PORTAL_USER_URL = '/touches-portal-user/'


# --- COOP header -----------------------------------------------------------


def test_coop_header_set_by_default(client):
    response = client.get(PLAIN_URL)
    assert response['Cross-Origin-Opener-Policy'] == COOP_VALUE == 'same-origin-allow-popups'


def test_coop_header_wins_over_security_middleware_default(client):
    # SecurityMiddleware's own default ('same-origin') would sever
    # window.opener in the cross-origin switch popup; PortalSwitchMiddleware
    # must win this race (see its docstring on MIDDLEWARE ordering).
    response = client.get(PLAIN_URL)
    assert response['Cross-Origin-Opener-Policy'] != 'same-origin'


def test_view_explicit_coop_value_is_respected(client):
    # A view that sets its own COOP header before either middleware's
    # response-phase code runs must not be overwritten by either.
    response = client.get(EXPLICIT_COOP_URL)
    assert response['Cross-Origin-Opener-Policy'] == 'unsafe-none'


@override_settings(
    SSO_PORTAL_CLIENT={
        'SERVER_URL': 'http://127.0.0.1:8000/o',
        'CLIENT_ID': 'test-client-id',
        'CLIENT_SECRET': 'test-client-secret',
        'SET_COOP_HEADER': False,
    }
)
def test_set_coop_header_false_opts_out(client):
    # PortalSwitchMiddleware no-ops; SecurityMiddleware's own default then
    # applies unopposed (proving the opt-out doesn't just suppress the
    # header entirely — it hands control back to Django's stock behavior).
    response = client.get(PLAIN_URL)
    assert response['Cross-Origin-Opener-Policy'] == 'same-origin'


# --- request.portal_user ----------------------------------------------------


def test_portal_user_none_for_anonymous(client):
    response = client.get(TOUCHES_PORTAL_USER_URL)
    assert response.content == b'no'


def test_portal_user_none_for_local_account(client, user):
    # `user` (tests/conftest.py) has no linked sso_portal SocialAccount.
    client.force_login(user)
    response = client.get(TOUCHES_PORTAL_USER_URL)
    assert response.content == b'no'


def test_portal_user_resolves_for_portal_backed_session(client, user):
    SocialAccount.objects.create(
        user=user,
        provider='sso_portal',
        uid='42',
        extra_data={'id_token': {'preferred_username': 'alice-portal', 'name': 'Alice Portal'}},
    )
    client.force_login(user)
    response = client.get(TOUCHES_PORTAL_USER_URL)
    assert response.content == b'yes'


def test_portal_user_lazy_costs_zero_queries_when_untouched(client, user):
    """A page that never reads request.portal_user must run ZERO extra
    queries for it — proven directly, not just relative to another route.

    (Django's own request.user is itself a SimpleLazyObject via
    AuthenticationMiddleware, so a view that touches neither it nor
    request.portal_user issues no auth-related queries at all here — the
    absolute-zero assertion holds regardless.)
    """
    SocialAccount.objects.create(
        user=user,
        provider='sso_portal',
        uid='42',
        extra_data={'id_token': {'preferred_username': 'alice-portal', 'name': 'Alice Portal'}},
    )
    client.force_login(user)

    with CaptureQueriesContext(connection) as ctx:
        response = client.get(PLAIN_URL)

    assert response.content == b'ok'
    assert ctx.captured_queries == []


def test_portal_user_resolution_only_queries_when_read(client, user):
    """Contrast case: a view that DOES read request.portal_user pays the
    get_claims() query (SocialAccount lookup) — proving the zero-queries
    result above is laziness, not a route that never runs the middleware."""
    SocialAccount.objects.create(
        user=user,
        provider='sso_portal',
        uid='42',
        extra_data={'id_token': {'preferred_username': 'alice-portal', 'name': 'Alice Portal'}},
    )
    client.force_login(user)

    with CaptureQueriesContext(connection) as ctx:
        response = client.get(TOUCHES_PORTAL_USER_URL)

    assert response.content == b'yes'
    assert len(ctx.captured_queries) > 0
