from django.apps import AppConfig


class SsoPortalClientConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'sso_portal_client'
    verbose_name = 'SSO Portal Client'

    def ready(self) -> None:
        # Signal wiring must happen once all apps are loaded, hence the
        # function-scoped imports (same pattern as sso_portal's plugins).
        from allauth.account.signals import user_logged_in  # noqa: PLC0415
        from allauth.socialaccount.signals import social_account_added  # noqa: PLC0415

        from sso_portal_client import receivers  # noqa: PLC0415

        user_logged_in.connect(
            receivers.on_user_logged_in,
            dispatch_uid='sso_portal_client.user_logged_in',
        )
        social_account_added.connect(
            receivers.on_social_account_added,
            dispatch_uid='sso_portal_client.social_account_added',
        )
