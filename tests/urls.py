from django.urls import include, path

from tests import views

urlpatterns = [
    path('accounts/', include('allauth.urls')),
    path('sso/', include('sso_portal_client.urls')),
    path('plain/', views.plain),
    path('explicit-coop/', views.explicit_coop),
    path('touches-portal-user/', views.touches_portal_user),
    path('widget/', views.widget),
    path('widget-with-kwargs/', views.widget_with_kwargs),
]
