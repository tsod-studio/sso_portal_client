import pytest
from django.contrib.auth.models import Group
from django.test import override_settings

from sso_portal_client.sync import sync_user_groups

pytestmark = pytest.mark.django_db


def group_names(user):
    return set(user.groups.values_list('name', flat=True))


def sso(**overrides):
    base = {'SERVER_URL': 'http://portal.test/o', 'CLIENT_ID': 'cid'}
    return override_settings(SSO_PORTAL_CLIENT={**base, **overrides})


# --- Full-authority scope (GROUP_PREFIX None, the default) -------------------


def test_full_scope_creates_and_sets_groups(user):
    with sso():
        sync_user_groups(user, {'groups': ['staff', 'store-managers']})
    assert group_names(user) == {'staff', 'store-managers'}
    assert Group.objects.filter(name='store-managers').exists()


def test_full_scope_overwrites_removals_propagate(user):
    user.groups.add(Group.objects.create(name='staff'), Group.objects.create(name='old-team'))
    with sso():
        sync_user_groups(user, {'groups': ['staff']})
    assert group_names(user) == {'staff'}
    # The Group row itself survives — only the membership is removed.
    assert Group.objects.filter(name='old-team').exists()


def test_full_scope_removes_local_only_groups(user):
    user.groups.add(Group.objects.create(name='local-thing'))
    with sso():
        sync_user_groups(user, {'groups': ['portal-group']})
    assert group_names(user) == {'portal-group'}


def test_full_scope_empty_claim_clears_memberships(user):
    user.groups.add(Group.objects.create(name='staff'))
    with sso():
        sync_user_groups(user, {'groups': []})
    assert group_names(user) == set()


def test_full_scope_missing_claim_clears_memberships(user):
    user.groups.add(Group.objects.create(name='staff'))
    with sso():
        sync_user_groups(user, {})
    assert group_names(user) == set()


def test_full_scope_none_claim_clears_memberships(user):
    user.groups.add(Group.objects.create(name='staff'))
    with sso():
        sync_user_groups(user, {'groups': None})
    assert group_names(user) == set()


def test_falsy_group_names_filtered(user):
    with sso():
        sync_user_groups(user, {'groups': ['staff', '', None]})
    assert group_names(user) == {'staff'}


def test_full_scope_idempotent(user):
    with sso():
        sync_user_groups(user, {'groups': ['staff', 'store-managers']})
        sync_user_groups(user, {'groups': ['staff', 'store-managers']})
    assert group_names(user) == {'staff', 'store-managers'}
    assert Group.objects.filter(name='staff').count() == 1


def test_reuses_existing_group_rows(user):
    existing = Group.objects.create(name='staff')
    with sso():
        sync_user_groups(user, {'groups': ['staff']})
    assert list(user.groups.all()) == [existing]


# --- Namespace scope (GROUP_PREFIX set) ---------------------------------------


def test_prefix_scope_adds_and_creates_namespace_groups(user):
    with sso(GROUP_PREFIX='shop-'):
        sync_user_groups(user, {'groups': ['shop-admin', 'shop-users']})
    assert group_names(user) == {'shop-admin', 'shop-users'}


def test_prefix_scope_removes_stale_namespace_memberships(user):
    user.groups.add(Group.objects.create(name='shop-admin'), Group.objects.create(name='shop-users'))
    with sso(GROUP_PREFIX='shop-'):
        sync_user_groups(user, {'groups': ['shop-users']})
    assert group_names(user) == {'shop-users'}


def test_prefix_scope_preserves_local_non_prefix_groups(user):
    user.groups.add(Group.objects.create(name='local-editors'))
    with sso(GROUP_PREFIX='shop-'):
        sync_user_groups(user, {'groups': ['shop-users']})
    assert group_names(user) == {'local-editors', 'shop-users'}


def test_prefix_scope_ignores_non_prefix_claim_groups(user):
    with sso(GROUP_PREFIX='shop-'):
        sync_user_groups(user, {'groups': ['shop-users', 'other-app-admin', 'staff']})
    assert group_names(user) == {'shop-users'}
    assert not Group.objects.filter(name='other-app-admin').exists()


def test_prefix_scope_empty_claim_clears_only_namespace(user):
    user.groups.add(Group.objects.create(name='shop-admin'), Group.objects.create(name='local-editors'))
    with sso(GROUP_PREFIX='shop-'):
        sync_user_groups(user, {'groups': []})
    assert group_names(user) == {'local-editors'}


def test_prefix_scope_idempotent(user):
    user.groups.add(Group.objects.create(name='local-editors'))
    with sso(GROUP_PREFIX='shop-'):
        sync_user_groups(user, {'groups': ['shop-users']})
        sync_user_groups(user, {'groups': ['shop-users']})
    assert group_names(user) == {'local-editors', 'shop-users'}


# --- Staff / superuser flags ---------------------------------------------------


def test_empty_staff_groups_never_touches_flag(user):
    user.is_staff = True
    user.save()
    with sso():
        sync_user_groups(user, {'groups': ['whatever']})
    user.refresh_from_db()
    assert user.is_staff is True


def test_staff_granted_from_claim(user):
    with sso(STAFF_GROUPS=['shop-admin']):
        sync_user_groups(user, {'groups': ['shop-admin']})
    user.refresh_from_db()
    assert user.is_staff is True
    assert user.is_superuser is False


def test_staff_revoked_when_claim_group_gone(user):
    user.is_staff = True
    user.save()
    with sso(STAFF_GROUPS=['shop-admin']):
        sync_user_groups(user, {'groups': ['shop-users']})
    user.refresh_from_db()
    assert user.is_staff is False


def test_superuser_granted_and_revoked(user):
    with sso(SUPERUSER_GROUPS=['portal-root']):
        sync_user_groups(user, {'groups': ['portal-root']})
        user.refresh_from_db()
        assert user.is_superuser is True
        sync_user_groups(user, {'groups': []})
    user.refresh_from_db()
    assert user.is_superuser is False


def test_empty_superuser_groups_never_touches_flag(user):
    user.is_superuser = True
    user.save()
    with sso(STAFF_GROUPS=['shop-admin']):
        sync_user_groups(user, {'groups': []})
    user.refresh_from_db()
    assert user.is_superuser is True


def test_flags_use_full_claim_set_even_with_prefix_scope(user):
    # STAFF_GROUPS matches against ALL claim groups, not just the managed
    # namespace — the flag mapping and the membership scope are independent.
    with sso(GROUP_PREFIX='shop-', STAFF_GROUPS=['portal-operators']):
        sync_user_groups(user, {'groups': ['shop-users', 'portal-operators']})
    user.refresh_from_db()
    assert user.is_staff is True
    assert group_names(user) == {'shop-users'}
