import pytest


@pytest.fixture
def user(django_user_model):
    return django_user_model.objects.create_user(username='alice', password='not-used')
