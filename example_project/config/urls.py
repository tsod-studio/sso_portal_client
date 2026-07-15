"""Root URLconf for the SampleStore demo RP.

- ``accounts/`` — allauth (OIDC login/callback for the ``sso_portal`` provider)
- ``sso/`` — sso_portal_client (back-channel logout + session ping)
- ``''`` — the store app (index + admin-area)
"""

from django.urls import include, path

# Custom 403 handler: renders store/403.html, which explains that access is
# derived from SSO group -> Django permission (mirrors the Flask sample's
# denied page). Django only uses this when DEBUG is False; the store tests
# assert against the template directly, and the runbook notes it.
handler403 = 'store.views.permission_denied'

urlpatterns = [
    path('accounts/', include('allauth.urls')),
    path('sso/', include('sso_portal_client.urls')),
    path('', include('store.urls')),
]
