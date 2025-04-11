from django.utils.module_loading import import_string
from jwt_passwordless.settings import api_settings
from jwt_passwordless.utils import (
    create_callback_token_for_user,
)


class TokenService(object):
    @staticmethod
    def send_token(user, alias_type, token_type, request=None, **message_payload):
        token = create_callback_token_for_user(user, alias_type, token_type)
        send_action = None

        if user.pk in api_settings.PASSWORDLESS_DEMO_USERS.keys():
            return True
        if alias_type == 'email':
            send_action = import_string(api_settings.PASSWORDLESS_EMAIL_CALLBACK)
        elif alias_type == 'mobile':
            send_action = import_string(api_settings.PASSWORDLESS_SMS_CALLBACK)
        # Send to alias
        success = send_action(user, token, request, **message_payload)
        return success
