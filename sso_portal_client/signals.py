"""Signals emitted by sso_portal_client."""

from django.dispatch import Signal

# Emitted after group sync completed for a portal login.
# Arguments:
# - user: the local Django user
# - claims: dict of OIDC claims the sync ran against (userinfo merged with
#   the id_token's claims; id_token wins — it is the only source that can
#   carry `sid`/`amr`).
#
# RPs hang custom claim mapping here (e.g. the portal's `role` claim, which
# this package deliberately does not map to any model).
claims_synced = Signal()
