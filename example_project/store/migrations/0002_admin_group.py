"""Data migration: the headline demo of sso_portal_client.

Create the ``samplestore-admin`` Group and attach the ``store.view_admin_area``
permission to it. From then on, ``sso_portal_client`` grants that permission to
anyone the portal places in the group — group membership arriving over OIDC
becomes a normal Django permission with zero runtime claim inspection.

The permission is created here explicitly rather than looked up, because
Django's auto-created permissions land in a ``post_migrate`` signal that fires
only *after* this migration runs — on a fresh database the permission would
not yet exist. Creating it directly (idempotent ``get_or_create`` against the
same content type Django would use) makes the migration self-contained and
safe to run in any order. Reverse simply removes the group.
"""

from django.db import migrations
from django.db.backends.base.schema import BaseDatabaseSchemaEditor
from django.db.migrations.state import StateApps

ADMIN_GROUP = 'samplestore-admin'
PERMISSION_CODENAME = 'view_admin_area'
PERMISSION_NAME = 'Can view the admin area'


def create_admin_group(apps: StateApps, schema_editor: BaseDatabaseSchemaEditor) -> None:  # noqa: ARG001
    Group = apps.get_model('auth', 'Group')
    Permission = apps.get_model('auth', 'Permission')
    ContentType = apps.get_model('contenttypes', 'ContentType')

    content_type, _ = ContentType.objects.get_or_create(app_label='store', model='adminarea')
    permission, _ = Permission.objects.get_or_create(
        codename=PERMISSION_CODENAME,
        content_type=content_type,
        defaults={'name': PERMISSION_NAME},
    )
    group, _ = Group.objects.get_or_create(name=ADMIN_GROUP)
    group.permissions.add(permission)


def remove_admin_group(apps: StateApps, schema_editor: BaseDatabaseSchemaEditor) -> None:  # noqa: ARG001
    Group = apps.get_model('auth', 'Group')
    Group.objects.filter(name=ADMIN_GROUP).delete()


class Migration(migrations.Migration):
    dependencies = [
        ('store', '0001_initial'),
        ('auth', '__first__'),
        ('contenttypes', '__first__'),
    ]

    operations = [
        migrations.RunPython(create_admin_group, remove_admin_group),
    ]
