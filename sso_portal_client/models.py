"""Session bookkeeping for OIDC back-channel logout.

The portal's logout fan-out (store switching, RP-initiated logout) targets
RP sessions by the id_token's ``sid`` claim. To honor it we must be able to
map a ``sid`` back to concrete ``django_session`` rows — that is all this
model does.
"""

from django.conf import settings
from django.db import models


class PortalSession(models.Model):
    """Maps a portal session id (``sid`` id_token claim) to a local session.

    ``session_key`` is unique on its own (a Django session belongs to exactly
    one portal session at a time; re-login cycles the session key), which
    also guarantees the (sid, session_key) pair is unique. ``sid`` is indexed
    because back-channel logout looks rows up by it.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='portal_sessions',
    )
    sid = models.CharField(max_length=255, db_index=True)
    session_key = models.CharField(max_length=40, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f'PortalSession(sid={self.sid}, session_key={self.session_key})'
