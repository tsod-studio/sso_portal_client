"""URLconf for the store app."""

from django.urls import path

from store import views

app_name = 'store'

urlpatterns = [
    path('', views.index, name='index'),
    path('admin-area/', views.admin_area, name='admin_area'),
]
