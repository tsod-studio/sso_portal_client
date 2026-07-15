"""Reusable Django app: SSO-portal OIDC login with automatic group sync.

Public API:

- ``sso_portal_client.provider_config()`` — build the allauth
  ``SOCIALACCOUNT_PROVIDERS['openid_connect']`` dict from the RP's
  ``SSO_PORTAL_CLIENT`` settings.
- ``sso_portal_client.signals.claims_synced`` — fired after every group sync.
"""

from sso_portal_client.conf import provider_config

__all__ = ['provider_config']
