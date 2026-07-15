"""Models for the SampleStore demo.

There is exactly one, and it stores nothing: ``AdminArea`` exists only so
Django's auth framework materializes a ``store.view_admin_area`` permission.
That permission is attached to the ``samplestore-admin`` group in a data
migration (see ``migrations/0002_admin_group.py``); ``sso_portal_client`` then
grants it automatically to anyone the portal places in that group. No rows are
ever created.
"""

from typing import ClassVar

from django.db import models


class AdminArea(models.Model):
    """Permission anchor for the custom ``view_admin_area`` permission.

    ``default_permissions = ()`` suppresses the add/change/delete/view
    permissions Django would otherwise create for a real model — this one is
    never instantiated, so only the custom permission is meaningful.
    """

    class Meta:
        default_permissions = ()
        permissions: ClassVar = [('view_admin_area', 'Can view the admin area')]

    def __str__(self) -> str:
        return 'AdminArea (permission anchor)'
