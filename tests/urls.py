from django.urls import include, path

urlpatterns = [
    path('accounts/', include('allauth.urls')),
    path('sso/', include('sso_portal_client.urls')),
]
