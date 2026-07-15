import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings

from sso_portal_client.conf import PROVIDER_ID, discovery_url, get_settings, provider_config


def test_defaults_merged():
    cfg = get_settings()
    assert cfg['SERVER_URL'] == 'http://127.0.0.1:8000/o'
    assert cfg['CLIENT_ID'] == 'test-client-id'
    assert cfg['CLIENT_SECRET'] == 'test-client-secret'
    assert cfg['GROUP_PREFIX'] is None
    assert cfg['STAFF_GROUPS'] == []
    assert cfg['SUPERUSER_GROUPS'] == []


@override_settings(SSO_PORTAL_CLIENT={'CLIENT_ID': 'x'})
def test_missing_server_url_raises():
    with pytest.raises(ImproperlyConfigured, match='SERVER_URL'):
        get_settings()


@override_settings(SSO_PORTAL_CLIENT={'SERVER_URL': 'http://portal.test/o'})
def test_missing_client_id_raises():
    with pytest.raises(ImproperlyConfigured, match='CLIENT_ID'):
        get_settings()


@override_settings(SSO_PORTAL_CLIENT={})
def test_empty_dict_raises():
    with pytest.raises(ImproperlyConfigured):
        get_settings()


@override_settings(SSO_PORTAL_CLIENT='not-a-dict')
def test_non_dict_raises():
    with pytest.raises(ImproperlyConfigured, match='must be a dict'):
        get_settings()


@override_settings(SSO_PORTAL_CLIENT={'SERVER_URL': 'x', 'CLIENT_ID': 'y', 'TYPO_KEY': 1})
def test_unknown_key_raises():
    with pytest.raises(ImproperlyConfigured, match='TYPO_KEY'):
        get_settings()


def test_discovery_url_appends_well_known():
    assert discovery_url() == 'http://127.0.0.1:8000/o/.well-known/openid-configuration'


@override_settings(
    SSO_PORTAL_CLIENT={
        'SERVER_URL': 'http://portal.test/o/.well-known/openid-configuration',
        'CLIENT_ID': 'x',
    }
)
def test_discovery_url_accepts_full_discovery_url():
    assert discovery_url() == 'http://portal.test/o/.well-known/openid-configuration'


def test_provider_config_shape():
    config = provider_config()
    assert list(config) == ['APPS']
    (app,) = config['APPS']
    assert app['provider_id'] == PROVIDER_ID == 'sso_portal'
    assert app['name'] == 'SSO Portal'
    assert app['client_id'] == 'test-client-id'
    assert app['secret'] == 'test-client-secret'
    # allauth appends /.well-known/openid-configuration itself.
    assert app['settings']['server_url'] == 'http://127.0.0.1:8000/o'
    # Per-app PKCE switch (allauth oauth2 provider get_pkce_params).
    assert app['settings']['oauth_pkce_enabled'] is True
