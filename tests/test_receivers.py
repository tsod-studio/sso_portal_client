"""Integration-style tests: allauth signals -> group sync + session tracking.

The SocialLogin fixtures carry recorded-style extra_data as allauth 65's
openid_connect adapter persists it: ``{'userinfo': {...}, 'id_token': {...}}``
(complete_login in providers/openid_connect/views.py), with the portal's
``groups`` claim present in both and ``sid`` only in the id_token.
"""

from datetime import timedelta

import pytest
from allauth.account.signals import user_logged_in
from allauth.socialaccount.models import SocialAccount, SocialLogin
from allauth.socialaccount.signals import social_account_added
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import RequestFactory, override_settings
from django.utils import timezone

from sso_portal_client.models import PortalSession
from sso_portal_client.signals import claims_synced

pytestmark = pytest.mark.django_db

USERINFO = {
    'sub': '42',
    'name': 'Alice Lin',
    'preferred_username': 'alice',
    'groups': ['staff', 'samplestore-admin'],
    'role': 'manager',
}
ID_TOKEN = {**USERINFO, 'sid': 'portal-sid-1', 'amr': ['pin'], 'aud': 'test-client-id'}


def make_request():
    request = RequestFactory().get('/')
    SessionMiddleware(lambda r: None).process_request(request)
    request.session.create()
    return request


def make_sociallogin(user, provider='sso_portal', extra_data=None):
    account = SocialAccount.objects.create(
        user=user,
        provider=provider,
        uid='42',
        extra_data=extra_data if extra_data is not None else {'userinfo': USERINFO, 'id_token': ID_TOKEN},
    )
    return SocialLogin(user=user, account=account)


def send_login(user, sociallogin, request=None):
    request = request or make_request()
    user_logged_in.send(sender=user.__class__, request=request, response=None, user=user, sociallogin=sociallogin)
    return request


def group_names(user):
    return set(user.groups.values_list('name', flat=True))


def test_login_signal_syncs_groups(user):
    send_login(user, make_sociallogin(user))
    assert group_names(user) == {'staff', 'samplestore-admin'}


def test_login_signal_records_portal_session(user):
    request = send_login(user, make_sociallogin(user))
    portal_session = PortalSession.objects.get()
    assert portal_session.sid == 'portal-sid-1'
    assert portal_session.session_key == request.session.session_key
    assert portal_session.user == user


def test_login_signal_fires_claims_synced_with_merged_claims(user):
    received = []
    claims_synced.connect(lambda sender, **kwargs: received.append(kwargs), weak=False, dispatch_uid='t1')
    try:
        send_login(user, make_sociallogin(user))
    finally:
        claims_synced.disconnect(dispatch_uid='t1')
    assert len(received) == 1
    assert received[0]['user'] == user
    claims = received[0]['claims']
    # Merged view: userinfo keys present, id_token-only keys present,
    # id_token wins on conflicts (it carries sid/amr).
    assert claims['role'] == 'manager'
    assert claims['sid'] == 'portal-sid-1'
    assert claims['amr'] == ['pin']
    assert claims['groups'] == ['staff', 'samplestore-admin']


def test_id_token_claims_win_over_userinfo(user):
    extra_data = {
        'userinfo': {'sub': '42', 'groups': ['from-userinfo']},
        'id_token': {'sub': '42', 'groups': ['from-id-token'], 'sid': 's'},
    }
    send_login(user, make_sociallogin(user, extra_data=extra_data))
    assert group_names(user) == {'from-id-token'}


def test_legacy_flat_extra_data_supported(user):
    # allauth < 65.11 stored the claims flat in extra_data.
    send_login(user, make_sociallogin(user, extra_data={'sub': '42', 'groups': ['staff'], 'sid': 'legacy-sid'}))
    assert group_names(user) == {'staff'}
    assert PortalSession.objects.get().sid == 'legacy-sid'


def test_other_provider_ignored(user):
    send_login(user, make_sociallogin(user, provider='google'))
    assert group_names(user) == set()
    assert not PortalSession.objects.exists()


def test_plain_login_without_sociallogin_ignored(user):
    request = make_request()
    user_logged_in.send(sender=user.__class__, request=request, response=None, user=user)
    assert group_names(user) == set()


def test_no_sid_claim_records_no_portal_session(user):
    send_login(user, make_sociallogin(user, extra_data={'userinfo': USERINFO}))
    assert group_names(user) == {'staff', 'samplestore-admin'}
    assert not PortalSession.objects.exists()


def test_repeat_login_same_session_updates_portal_session(user):
    sociallogin = make_sociallogin(user)
    request = send_login(user, sociallogin)
    sociallogin.account.extra_data = {'userinfo': USERINFO, 'id_token': {**ID_TOKEN, 'sid': 'portal-sid-2'}}
    send_login(user, sociallogin, request=request)
    portal_session = PortalSession.objects.get()
    assert portal_session.sid == 'portal-sid-2'


def test_social_account_added_signal_syncs(user):
    sociallogin = make_sociallogin(user)
    social_account_added.send(sender=SocialLogin, request=make_request(), sociallogin=sociallogin)
    assert group_names(user) == {'staff', 'samplestore-admin'}
    assert PortalSession.objects.get().sid == 'portal-sid-1'


@override_settings(
    SSO_PORTAL_CLIENT={
        'SERVER_URL': 'http://127.0.0.1:8000/o',
        'CLIENT_ID': 'test-client-id',
        'STAFF_GROUPS': ['samplestore-admin'],
    }
)
def test_login_signal_applies_staff_mapping(user):
    send_login(user, make_sociallogin(user))
    user.refresh_from_db()
    assert user.is_staff is True


class TestSessionCutoff:
    """Portal logins bind the RP session's expiry to the next local
    SESSION_CUTOFF_TIME (default midnight), so a station never crosses into
    the next business day still signed in as yesterday's user.
    """

    def _expected_next_cutoff(self, cutoff_hour=0, cutoff_minute=0):
        now = timezone.localtime()
        expected = now.replace(hour=cutoff_hour, minute=cutoff_minute, second=0, microsecond=0)
        if expected <= now:
            expected += timedelta(days=1)
        return expected

    def test_portal_login_expires_at_next_midnight(self, django_user_model):
        user = django_user_model.objects.create_user('alice')
        request = make_request()
        send_login(user, make_sociallogin(user), request=request)

        expiry = timezone.localtime(request.session.get_expiry_date())
        expected = self._expected_next_cutoff()
        # Second-level tolerance: get_expiry_date round-trips through the
        # session store, which may truncate microseconds.
        assert abs((expiry - expected).total_seconds()) < 2

    @override_settings(
        SSO_PORTAL_CLIENT={
            'SERVER_URL': 'http://127.0.0.1:8000/o',
            'CLIENT_ID': 'test-client-id',
            'SESSION_CUTOFF_TIME': '04:30',
        }
    )
    def test_custom_cutoff_time_is_honored(self, django_user_model):
        user = django_user_model.objects.create_user('alice')
        request = make_request()
        send_login(user, make_sociallogin(user), request=request)

        expiry = timezone.localtime(request.session.get_expiry_date())
        expected = self._expected_next_cutoff(4, 30)
        assert abs((expiry - expected).total_seconds()) < 2

    @override_settings(
        SSO_PORTAL_CLIENT={
            'SERVER_URL': 'http://127.0.0.1:8000/o',
            'CLIENT_ID': 'test-client-id',
            'SESSION_CUTOFF_TIME': None,
        }
    )
    def test_none_leaves_default_session_age(self, django_user_model, settings):
        user = django_user_model.objects.create_user('alice')
        request = make_request()
        send_login(user, make_sociallogin(user), request=request)

        assert request.session.get_expiry_age() == settings.SESSION_COOKIE_AGE

    def test_non_portal_login_untouched(self, django_user_model, settings):
        user = django_user_model.objects.create_user('bob')
        request = make_request()
        send_login(user, make_sociallogin(user, provider='github'), request=request)

        assert request.session.get_expiry_age() == settings.SESSION_COOKIE_AGE
