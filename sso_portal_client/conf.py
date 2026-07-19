"""Validated access to the ``SSO_PORTAL_CLIENT`` settings dict.

An RP configures the whole package through a single settings dict::

    SSO_PORTAL_CLIENT = {
        'SERVER_URL': 'http://127.0.0.1:8000/o',   # issuer; discovery derived
        'CLIENT_ID': '...',
        'CLIENT_SECRET': '...',
        'GROUP_PREFIX': None,    # None => manage ALL group memberships
        'STAFF_GROUPS': [],      # claim groups granting is_staff (empty = never touch)
        'SUPERUSER_GROUPS': [],  # same for is_superuser (empty = never touch)
        'POST_LOGOUT_REDIRECT_URL': None,  # absolute URL for RP-initiated logout
        'STATIC_ORIGIN': None,   # origin serving the portal's /static/js/*; None => SERVER_URL's origin
        'SESSION_CUTOFF_TIME': '00:00',  # local time-of-day sessions die at; None disables
        'USERNAME_STRATEGY': 'sub_at_issuer',  # or 'preferred_username'; see adapters.py
        'SET_COOP_HEADER': True,  # PortalSwitchMiddleware sets the popup-friendly COOP header
    }
"""

import datetime
from typing import Any
from urllib.parse import urlsplit

from django.conf import settings as django_settings
from django.core.exceptions import ImproperlyConfigured

# The allauth `provider_id` for the portal's SocialApp entry. Receivers use it
# to filter logins (SocialAccount.provider stores app.provider_id, verified
# against allauth 65.18 providers/base/provider.py sub_id).
PROVIDER_ID = 'sso_portal'

# Namespaced Django-session key under which the RAW id_token JWT would be
# stashed at login to enable a prompt-free RP-initiated logout. It is NOT
# populated by this package: allauth 65.18 exposes no supported hook that
# surfaces the raw id_token string (the openid_connect adapter decodes it and
# discards the raw JWT; SocialAccount.extra_data['id_token'] holds only the
# decoded claims), and the callback view hardcodes the stock adapter, so
# capture would require monkeypatching or re-registering a custom provider.
# `views.global_logout` reads this key if something else (a future allauth
# release, or a host project that CAN reach the raw token) has set it, and
# omits the id_token_hint otherwise. See the README "Log out everywhere"
# section for the degraded-but-functional no-hint UX.
SESSION_ID_TOKEN_KEY = '_sso_portal_client_id_token'  # noqa: S105 # nosec B105  # session key name, not a secret

# Valid values for USERNAME_STRATEGY. See adapters.SocialAccountAdapter.
_USERNAME_STRATEGIES = ('sub_at_issuer', 'preferred_username')

_DEFAULTS: dict[str, Any] = {
    'SERVER_URL': None,
    'CLIENT_ID': None,
    'CLIENT_SECRET': '',  # nosec B105  # empty default, not a secret value
    'GROUP_PREFIX': None,
    'STAFF_GROUPS': [],
    'SUPERUSER_GROUPS': [],
    'POST_LOGOUT_REDIRECT_URL': None,
    'STATIC_ORIGIN': None,
    'SESSION_CUTOFF_TIME': '00:00',
    'USERNAME_STRATEGY': 'sub_at_issuer',
    'SET_COOP_HEADER': True,
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


def session_cutoff_time() -> 'datetime.time | None':
    """The local time-of-day at which portal-established RP sessions expire.

    Parsed from ``SESSION_CUTOFF_TIME`` ('HH:MM', local time per Django's
    ``TIME_ZONE``). The default '00:00' scopes every session to the calendar
    day it was created on — matching the portal's day-scoped store model
    (per-day enrollment, "today's" quick-switch lists), so a station never
    greets the morning shift with yesterday's login. ``None`` disables the
    cutoff and leaves Django's ``SESSION_COOKIE_AGE`` in charge.
    """
    raw = get_settings()['SESSION_CUTOFF_TIME']
    if raw is None:
        return None
    try:
        hour, minute = str(raw).split(':')
        return datetime.time(int(hour), int(minute))
    except (TypeError, ValueError) as exc:
        msg = f"SSO_PORTAL_CLIENT['SESSION_CUTOFF_TIME'] must be 'HH:MM' or None, got {raw!r}."
        raise ImproperlyConfigured(msg) from exc


def username_strategy() -> str:
    """The validated ``USERNAME_STRATEGY`` value.

    ``'sub_at_issuer'`` (default): ``adapters.SocialAccountAdapter`` sets the
    RP-local username to ``f'{sub}@{issuer_host}'`` on every new portal
    signup — stable and collision-free because ``sub`` is immutable and
    globally unique per portal user. ``'preferred_username'``: keeps
    allauth's stock behavior (username seeded from the mutable
    ``preferred_username`` claim, deduped with a numeric suffix on
    collision). See the README "Stable usernames" section.
    """
    raw: str = get_settings()['USERNAME_STRATEGY']
    if raw not in _USERNAME_STRATEGIES:
        msg = f"SSO_PORTAL_CLIENT['USERNAME_STRATEGY'] must be one of {_USERNAME_STRATEGIES!r}, got {raw!r}."
        raise ImproperlyConfigured(msg)
    return raw


def discovery_url() -> str:
    """The portal's OIDC discovery document URL, derived from SERVER_URL.

    Mirrors allauth's convention (OpenIDConnectProvider.wk_server_url):
    SERVER_URL may be either the bare issuer or a full discovery URL.
    """
    url: str = get_settings()['SERVER_URL'].rstrip('/')
    if '/.well-known/' not in url:
        url += '/.well-known/openid-configuration'
    return url


def portal_origin() -> str:
    """The portal's APP origin (``scheme://host[:port]``), derived from
    ``SERVER_URL`` (the issuer, e.g. ``.../o``).

    This is what the switch widget talks to at runtime (``portalOrigin``,
    the login URL, the switch popup) — it must stay the app origin even in
    production, where it differs from ``static_origin()`` below. Was
    duplicated per-RP as ``_portal_origin()`` before the widget integration
    kit (``middleware.py`` / ``templatetags/sso_portal_client.py``) centralized
    it here.
    """
    parsed = urlsplit(get_settings()['SERVER_URL'])
    return f'{parsed.scheme}://{parsed.netloc}'


def static_origin() -> str:
    """Origin serving the portal's static JS (``switch-widget.js``).

    Defaults to :func:`portal_origin`, which is correct in development where
    the portal's runserver serves ``/static/`` from the app origin itself.
    In production the portal's app origin serves no ``/static/`` at all
    (static assets live on a separate CDN domain — the portal's
    ``STATIC_URL``), so deployments there must set
    ``SSO_PORTAL_CLIENT['STATIC_ORIGIN']`` to that CDN origin.
    """
    override = get_settings()['STATIC_ORIGIN']
    if not override:
        return portal_origin()
    parsed = urlsplit(override)
    return f'{parsed.scheme}://{parsed.netloc}'


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
