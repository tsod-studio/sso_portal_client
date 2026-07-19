"""``{% portal_switch_widget %}`` (templatetags/sso_portal_client.py).

Rendered through real views (tests/views.py `widget` / `widget_with_kwargs`,
tests/templates/tests/widget*.html) so PortalSwitchMiddleware's
request.portal_user and the real MIDDLEWARE/TEMPLATES wiring are exercised
end to end, not mocked.
"""

import pytest
from allauth.socialaccount.models import SocialAccount

pytestmark = pytest.mark.django_db

WIDGET_URL = '/widget/'
WIDGET_WITH_KWARGS_URL = '/widget-with-kwargs/'


def test_script_tags_present(client):
    response = client.get(WIDGET_URL)
    content = response.content.decode()
    assert 'src="http://127.0.0.1:8000/static/js/switch-widget.js"' in content
    assert 'PortalSwitchWidget.init(' in content
    # switch.js (the plain data-portal-switch button enhancer) is NOT loaded
    # by this tag — the widget is self-contained (see switch-widget.js's own
    # docstring: "a deliberate duplicate, not a wrapper" of that handshake).
    assert 'switch.js"' not in content


def test_anonymous_current_user_is_null(client):
    response = client.get(WIDGET_URL)
    content = response.content.decode()
    assert '>null</script>' in content  # sso-portal-client-current-user


def test_local_account_current_user_is_null(client, user):
    # `user` has no linked sso_portal SocialAccount -> not portal-backed.
    client.force_login(user)
    response = client.get(WIDGET_URL)
    content = response.content.decode()
    assert '>null</script>' in content


def test_portal_backed_current_user_is_json_encoded(client, user):
    SocialAccount.objects.create(
        user=user,
        provider='sso_portal',
        uid='42',
        extra_data={
            'id_token': {
                'preferred_username': 'alice-portal',
                'name': 'Alice Portal',
                'picture': 'https://line.example/alice.jpg',
                'locale': 'zh-hant',
            }
        },
    )
    client.force_login(user)
    response = client.get(WIDGET_URL)
    content = response.content.decode()
    assert '"username": "alice-portal"' in content
    assert '"name": "Alice Portal"' in content
    assert '"picture": "https://line.example/alice.jpg"' in content
    assert '"locale": "zh-hant"' in content


def test_login_url_carries_process_login_and_next(client):
    response = client.get(WIDGET_URL)
    content = response.content.decode()
    assert 'process=login' in content
    # The return-to-origin pattern: next=<current full path>, URL-encoded.
    assert 'next=%2Fwidget%2F' in content


def test_require_session_and_strategy_default(client):
    response = client.get(WIDGET_URL)
    content = response.content.decode()
    assert '>false</script>' in content  # sso-portal-client-require-session default
    # Default strategy '' renders as an empty JSON string; the inline script
    # only sets options.strategy when it's truthy.
    assert '"redirect"' not in content


def test_require_session_and_strategy_passthrough(client):
    response = client.get(WIDGET_WITH_KWARGS_URL)
    content = response.content.decode()
    assert '>true</script>' in content  # sso-portal-client-require-session
    assert '"redirect"' in content  # sso-portal-client-strategy


def test_session_ping_url_reversed(client):
    response = client.get(WIDGET_URL)
    content = response.content.decode()
    assert '/sso/session-ping/' in content


def test_static_origin_override_moves_only_the_script_src(client, settings):
    settings.SSO_PORTAL_CLIENT = {
        **settings.SSO_PORTAL_CLIENT,
        'STATIC_ORIGIN': 'https://static.portal.example',
    }

    response = client.get(WIDGET_URL)
    content = response.content.decode()
    assert 'src="https://static.portal.example/static/js/switch-widget.js"' in content
    # portalOrigin (what the widget talks to at runtime) must stay the app
    # origin — only the <script src> moves to the static/CDN origin.
    assert '>"http://127.0.0.1:8000"</script>' in content
