from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _

class JwtPasswordlessConfig(AppConfig):
    name = 'jwt_passwordless'
    verbose = _("JWT Passwordless")

    def ready(self):
        import jwt_passwordless.signals
