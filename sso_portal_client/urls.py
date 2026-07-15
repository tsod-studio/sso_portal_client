"""URLconf — include as ``path('sso/', include('sso_portal_client.urls'))``."""

from django.urls import path

from sso_portal_client import views

app_name = 'sso_portal_client'

urlpatterns = [
    path('backchannel-logout/', views.backchannel_logout, name='backchannel_logout'),
    path('session-ping/', views.session_ping, name='session_ping'),
]
