"""On-demand claim readers in ``sso_portal_client.claims``."""

import pytest
from allauth.socialaccount.models import SocialAccount
from django.contrib.auth.models import AnonymousUser, User

from sso_portal_client.claims import get_claim, get_claims

pytestmark = pytest.mark.django_db


def test_anonymous_user_has_no_claims() -> None:
    assert get_claims(AnonymousUser()) == {}
    assert get_claim(AnonymousUser(), 'picture', 'fallback') == 'fallback'


def test_object_without_auth_state_has_no_claims() -> None:
    # Anything lacking ``is_authenticated`` (e.g. None from an unauthenticated
    # code path) is treated as anonymous rather than raising.
    assert get_claims(None) == {}


def test_merges_all_layers_without_nesting_containers(user: User) -> None:
    SocialAccount.objects.create(
        user=user,
        provider='sso_portal',
        uid='42',
        extra_data={
            'legacy': 'flat',
            'userinfo': {'locale': 'en', 'picture': 'https://ui.example/b.jpg'},
            'id_token': {'picture': 'https://id.example/a.jpg', 'sid': 's1'},
        },
    )
    assert get_claims(user) == {
        'legacy': 'flat',
        'locale': 'en',
        'picture': 'https://id.example/a.jpg',
        'sid': 's1',
    }
