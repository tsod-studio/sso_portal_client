"""Tests for the SampleStore demo RP.

Run from the example project (its own settings, separate from the package
suite)::

    cd example_project && uv run python manage.py test store

These assert the demo's contract without a live portal: the data migration
wires the permission onto the group, and view access follows standard Django
permission checks — exactly what ``sso_portal_client`` grants when it syncs a
user into ``samplestore-admin``.
"""

from allauth.socialaccount.models import SocialAccount
from django.conf import settings as django_settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.test import TestCase, override_settings
from django.urls import reverse

from sso_portal_client.claims import get_claim

User = get_user_model()

ADMIN_GROUP = 'samplestore-admin'
USERS_GROUP = 'samplestore-users'


class DataMigrationTests(TestCase):
    """The 0002 data migration attaches the permission to the admin group."""

    def test_admin_group_exists_with_permission(self) -> None:
        group = Group.objects.get(name=ADMIN_GROUP)
        codenames = set(group.permissions.values_list('codename', flat=True))
        self.assertIn('view_admin_area', codenames)

    def test_permission_belongs_to_store_app(self) -> None:
        permission = Permission.objects.get(codename='view_admin_area')
        self.assertEqual(permission.content_type.app_label, 'store')


class AdminAreaAccessTests(TestCase):
    """Access to /admin-area/ follows group membership -> permission."""

    def setUp(self) -> None:
        # Simulate what sso_portal_client's login sync does: drop the user into
        # a portal group. No claim plumbing needed — the permission ride-along
        # is pure Django.
        self.admin_group = Group.objects.get(name=ADMIN_GROUP)
        self.users_group, _ = Group.objects.get_or_create(name=USERS_GROUP)

    def test_user_in_admin_group_may_view_admin_area(self) -> None:
        alice = User.objects.create_user(username='alice')
        alice.groups.add(self.admin_group)
        self.client.force_login(alice)
        response = self.client.get(reverse('store:admin_area'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'store/admin_area.html')

    def test_user_without_permission_gets_explanatory_403(self) -> None:
        bob = User.objects.create_user(username='bob')
        bob.groups.add(self.users_group)
        self.client.force_login(bob)
        response = self.client.get(reverse('store:admin_area'))
        self.assertEqual(response.status_code, 403)
        self.assertTemplateUsed(response, 'store/403.html')
        self.assertContains(response, ADMIN_GROUP, status_code=403)
        # The denied page shows the user's actual groups so the fix is obvious.
        self.assertContains(response, USERS_GROUP, status_code=403)

    def test_anonymous_is_redirected_to_login(self) -> None:
        response = self.client.get(reverse('store:admin_area'))
        self.assertEqual(response.status_code, 302)
        self.assertIn('/accounts/login/', response['Location'])


class IndexTests(TestCase):
    def test_anonymous_index_shows_login_link(self) -> None:
        response = self.client.get(reverse('store:index'))
        self.assertEqual(response.status_code, 200)
        # The login link points straight at the openid_connect provider.
        self.assertContains(response, '/accounts/oidc/sso_portal/login/')

    def test_authenticated_index_lists_groups_and_flags(self) -> None:
        carol = User.objects.create_user(username='carol')
        carol.groups.add(Group.objects.get(name=ADMIN_GROUP))
        self.client.force_login(carol)
        response = self.client.get(reverse('store:index'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, ADMIN_GROUP)
        self.assertContains(response, 'carol')


class SwitchWiringTests(TestCase):
    """The store-switch widget's requirements on the RP page — now covered by
    ``PortalSwitchMiddleware`` (``config/settings.py``) and
    ``{% portal_switch_widget %}`` (mounted once, site-wide, in
    ``store/base.html``) instead of hand-rolled per-view code. See git
    history predating the widget integration kit for the old
    ``_portal_origin``/``_portal_static_origin`` helpers and manual
    ``json_script`` plumbing this replaced.
    """

    def test_index_sends_popup_friendly_coop(self) -> None:
        # Without this, Django's SecurityMiddleware default (same-origin) would
        # sever window.opener in the cross-origin switch popup and the
        # sso:switched message would never reach this page (the switch would
        # silently fail, needing a second manual login click).
        # Set by PortalSwitchMiddleware now, not the view.
        response = self.client.get(reverse('store:index'))
        self.assertEqual(response['Cross-Origin-Opener-Policy'], 'same-origin-allow-popups')

    def test_widget_mounts_on_every_page(self) -> None:
        # Mounted once in store/base.html -> present on the 403 page too, not
        # just the index (the badge is meant to be site-wide).
        response = self.client.get(reverse('store:index'))
        self.assertContains(response, 'switch-widget.js')
        self.assertContains(response, 'PortalSwitchWidget.init(')
        # switch.js (the standalone data-portal-switch button) is retired:
        # the widget's own dropdown already offers "Switch to" + sign-in, so
        # keeping a second, separately-initialized button/script would just
        # duplicate it once every page mounts the widget via one tag.
        self.assertNotContains(response, 'switch.js"')

    def test_anonymous_index_mounts_widget_in_anonymous_mode(self) -> None:
        response = self.client.get(reverse('store:index'))
        # request.portal_user is None on an anonymous page -> currentUser is
        # JSON null (anonymous-mode widget), not a currentUser object.
        self.assertContains(response, '>null</script>')

    def test_local_account_also_mounts_widget_in_anonymous_mode(self) -> None:
        # A signed-in user with no linked sso_portal SocialAccount is not
        # portal-backed (shouldn't occur under this demo's SOCIALACCOUNT_ONLY,
        # but PortalSwitchMiddleware must still degrade to anonymous mode
        # rather than ever leaking a local user.username into currentUser —
        # the exact bug this integration kit exists to prevent).
        frank = User.objects.create_user(username='frank')
        self.client.force_login(frank)
        response = self.client.get(reverse('store:index'))
        # The widget's currentUser JSON is null, not `{"username": "frank", ...}`
        # — 'frank' legitimately appears elsewhere on the page (the "Signed in
        # as" fallback text), just never inside the widget's own payload.
        current_user_script = '<script id="sso-portal-client-current-user" type="application/json">null</script>'
        self.assertContains(response, current_user_script)

    def test_authenticated_index_threads_the_portal_claims(self) -> None:
        dave = User.objects.create_user(username='dave', first_name='Dave', last_name='Lin')
        SocialAccount.objects.create(
            user=dave,
            provider='sso_portal',
            uid='dave-uid',
            extra_data={
                'id_token': {
                    'preferred_username': 'dave-portal',
                    'picture': 'https://line.example/dave.jpg',
                    'locale': 'zh-hant',
                }
            },
        )
        self.client.force_login(dave)
        response = self.client.get(reverse('store:index'))
        self.assertContains(response, 'dave-portal')
        self.assertContains(response, 'https://line.example/dave.jpg')
        self.assertContains(response, 'zh-hant')


class StaticOriginTests(TestCase):
    """``STATIC_ORIGIN`` (read via ``conf.static_origin()``) governs the
    widget's ``<script src>``; ``conf.portal_origin()`` (the app origin,
    ``SERVER_URL``) must stay untouched — only the script tag moves to the
    static/CDN origin in production.
    """

    def test_defaults_to_the_app_origin(self) -> None:
        # No STATIC_ORIGIN configured (the example project's default settings):
        # the script tag falls back to the same origin as portalOrigin, which
        # is what makes the portal's runserver-served /static/ work in dev
        # with zero extra config.
        response = self.client.get(reverse('store:index'))
        self.assertContains(response, 'src="http://127.0.0.1:8000/static/js/switch-widget.js"')

    @override_settings(
        SSO_PORTAL_CLIENT={**django_settings.SSO_PORTAL_CLIENT, 'STATIC_ORIGIN': 'https://static.portal.example'}
    )
    def test_static_origin_override_moves_only_the_script_tag(self) -> None:
        response = self.client.get(reverse('store:index'))
        self.assertContains(response, 'src="https://static.portal.example/static/js/switch-widget.js"')
        # portalOrigin (what PortalSwitchWidget.init reads at runtime) must
        # still be the app origin, not the static override — only the
        # script src tag moves.
        self.assertContains(response, '>"http://127.0.0.1:8000"</script>')
        self.assertNotContains(response, 'static.portal.example</script>')


class PortalPictureTests(TestCase):
    """`_portal_picture` reads the OIDC `picture` claim from extra_data."""

    def _user_with_extra_data(self, extra_data: dict) -> object:
        user = User.objects.create_user(username='pic-user')
        SocialAccount.objects.create(user=user, provider='sso_portal', uid='pic-uid', extra_data=extra_data)
        return user

    def test_prefers_id_token_over_userinfo(self) -> None:
        user = self._user_with_extra_data(
            {'id_token': {'picture': 'https://id.example/a.jpg'}, 'userinfo': {'picture': 'https://ui.example/b.jpg'}}
        )
        self.assertEqual(get_claim(user, 'picture'), 'https://id.example/a.jpg')

    def test_falls_back_to_userinfo(self) -> None:
        user = self._user_with_extra_data({'userinfo': {'picture': 'https://ui.example/b.jpg'}})
        self.assertEqual(get_claim(user, 'picture'), 'https://ui.example/b.jpg')

    def test_tolerates_legacy_flat_layout(self) -> None:
        user = self._user_with_extra_data({'picture': 'https://flat.example/c.jpg'})
        self.assertEqual(get_claim(user, 'picture'), 'https://flat.example/c.jpg')

    def test_none_without_a_social_account(self) -> None:
        user = User.objects.create_user(username='no-account')
        self.assertIsNone(get_claim(user, 'picture'))

    def test_none_when_claim_absent(self) -> None:
        user = self._user_with_extra_data({'userinfo': {}, 'id_token': {}})
        self.assertIsNone(get_claim(user, 'picture'))


class PortalClaimTests(TestCase):
    """`_portal_claim` reads an arbitrary named OIDC claim from extra_data."""

    def _user_with_extra_data(self, extra_data: dict) -> object:
        user = User.objects.create_user(username='claim-user')
        SocialAccount.objects.create(user=user, provider='sso_portal', uid='claim-uid', extra_data=extra_data)
        return user

    def test_prefers_id_token_over_userinfo(self) -> None:
        user = self._user_with_extra_data({'id_token': {'locale': 'zh-hant'}, 'userinfo': {'locale': 'en'}})
        self.assertEqual(get_claim(user, 'locale'), 'zh-hant')

    def test_falls_back_to_userinfo(self) -> None:
        user = self._user_with_extra_data({'userinfo': {'locale': 'en'}})
        self.assertEqual(get_claim(user, 'locale'), 'en')

    def test_tolerates_legacy_flat_layout(self) -> None:
        user = self._user_with_extra_data({'locale': 'ja'})
        self.assertEqual(get_claim(user, 'locale'), 'ja')

    def test_none_without_a_social_account(self) -> None:
        user = User.objects.create_user(username='claim-no-account')
        self.assertIsNone(get_claim(user, 'locale'))

    def test_none_when_claim_absent(self) -> None:
        user = self._user_with_extra_data({'userinfo': {}, 'id_token': {}})
        self.assertIsNone(get_claim(user, 'locale'))
