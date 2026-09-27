"""``PortalSession`` model behaviour."""

import pytest
from django.contrib.auth.models import User

from sso_portal_client.models import PortalSession

pytestmark = pytest.mark.django_db


def test_str_identifies_sid_and_session_key(user: User) -> None:
    portal_session = PortalSession.objects.create(user=user, sid='portal-sid-1', session_key='abc123')
    assert str(portal_session) == 'PortalSession(sid=portal-sid-1, session_key=abc123)'
