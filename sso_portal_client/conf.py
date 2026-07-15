"""Validated access to the ``SSO_PORTAL_CLIENT`` settings dict.

An RP configures the whole package through a single settings dict::

    SSO_PORTAL_CLIENT = {
        'SERVER_URL': 'http://127.0.0.1:8000/o',   # issuer; discovery derived
        'CLIENT_ID': '...',
        'CLIENT_SECRET': '...',
        'GROUP_PREFIX': None,    # None => manage ALL group memberships
        'STAFF_GROUPS': [],      # claim groups granting is_staff (empty = never touch)
        'SUPERUSER_GROUPS': [],  # same for is_superuser (empty = never touch)
    }
"""

from typing import Any

from django.conf import settings as django_settings
from django.core.exceptions import ImproperlyConfigured

# The allauth `provider_id` for the portal's SocialApp entry. Receivers use it
# to filter logins (SocialAccount.provider stores app.provider_id, verified
# against allauth 65.18 providers/base/provider.py sub_id).
PROVIDER_ID = 'sso_portal'

_DEFAULTS: dict[str, Any] = {
    'SERVER_URL': None,
    'CLIENT_ID': None,
    'CLIENT_SECRET': '',
    'GROUP_PREFIX': None,
    'STAFF_GROUPS': [],
    'SUPERUSER_GROUPS': [],
}

_REQUIRED = ('SERVER_URL', 'CLIENT_ID')


def get_settings() -> dict[str, Any]:
    """Return the merged (defaults + user) SSO_PORTAL_CLIENT settings dict.

    Raises ImproperlyConfigured when SERVER_URL or CLIENT_ID is missing/empty.
    """
    user_settings = getattr(django_settings, 'SSO_PORTAL_CLIENT', {})
    if not isinstance(user_settings, dict):
        msg = 'SSO_PORTAL_CLIENT must be a dict.'
        raise ImproperlyConfigured(msg)
    unknown = set(user_settings) - set(_DEFAULTS)
    if unknown:
        msg = f'Unknown SSO_PORTAL_CLIENT key(s): {", ".join(sorted(unknown))}'
        raise ImproperlyConfigured(msg)
    merged = {**_DEFAULTS, **user_settings}
    for key in _REQUIRED:
        if not merged[key]:
            msg = f'SSO_PORTAL_CLIENT[{key!r}] is required.'
            raise ImproperlyConfigured(msg)
    return merged


def discovery_url() -> str:
    """The portal's OIDC discovery document URL, derived from SERVER_URL.

    Mirrors allauth's convention (OpenIDConnectProvider.wk_server_url):
    SERVER_URL may be either the bare issuer or a full discovery URL.
    """
    url = get_settings()['SERVER_URL'].rstrip('/')
    if '/.well-known/' not in url:
        url += '/.well-known/openid-configuration'
    return url


def provider_config() -> dict[str, Any]:
    """Build the ``SOCIALACCOUNT_PROVIDERS['openid_connect']`` provider dict.

    Usage in an RP's settings module::

        from sso_portal_client import provider_config
        SOCIALACCOUNT_PROVIDERS = {'openid_connect': provider_config()}

    Notes (verified against allauth 65.18 source):

    - ``settings['server_url']`` accepts the bare issuer URL; allauth appends
      ``/.well-known/openid-configuration`` itself when the URL does not
      already contain ``/.well-known/``.
    - ``settings['oauth_pkce_enabled']`` is the per-app PKCE switch
      (providers/oauth2/provider.py get_pkce_params); the portal requires
      PKCE (S256) for all clients.
    """
    cfg = get_settings()
    return {
        'APPS': [
            {
                'provider_id': PROVIDER_ID,
                'name': 'SSO Portal',
                'client_id': cfg['CLIENT_ID'],
                'secret': cfg['CLIENT_SECRET'],
                'settings': {
                    'server_url': cfg['SERVER_URL'],
                    'oauth_pkce_enabled': True,
                },
            }
        ],
    }
