import pytest

from sso_portal_client import views


@pytest.fixture
def user(django_user_model):
    return django_user_model.objects.create_user(username='alice', password='not-used')


@pytest.fixture(autouse=True)
def reset_logout_caches() -> None:
    views._reset_logout_caches()
