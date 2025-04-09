import logging
from django.utils.module_loading import import_string
from rest_framework import parsers, renderers, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated 
from rest_framework.views import APIView
from jwt_passwordless.models import CallbackToken
from jwt_passwordless.settings import api_settings
from jwt_passwordless.serializers import (
    EmailAuthSerializer,
    MobileAuthSerializer,
    CallbackTokenAuthSerializer,
    CallbackTokenVerificationSerializer
)
from jwt_passwordless.services import TokenService

logger = logging.getLogger(__name__)


class AbstractBaseObtainCallbackToken(APIView):
    """
    This returns a 6-digit callback token we can trade for a user's Auth Token.
    """
    success_response = "A login token has been sent to you."
    failure_response = "Unable to send you a login code. Try again later."

    message_payload = {}

    @property
    def serializer_class(self):
        # Our serializer depending on type
        raise NotImplementedError

    @property
    def alias_type(self):
        # Alias Type
        raise NotImplementedError

    @property
    def token_type(self):
        # Token Type
        raise NotImplementedError

    def post(self, request, *args, **kwargs):
        if self.alias_type.upper() not in api_settings.PASSWORDLESS_AUTH_TYPES:
            # Only allow auth types allowed in settings.
            return Response(status=status.HTTP_404_NOT_FOUND)

        serializer = self.serializer_class(data=request.data, context={'request': request})
        if serializer.is_valid(raise_exception=True):
            # Validate -
            user = serializer.validated_data['user']
            # Create and send callback token
            success = TokenService.send_token(user, self.alias_type, self.token_type, **self.message_payload)

            # Respond With Success Or Failure of Sent
            if success:
                status_code = status.HTTP_200_OK
                response_detail = self.success_response
            else:
                status_code = status.HTTP_400_BAD_REQUEST
                response_detail = self.failure_response
            return Response({"detail": response_detail}, status=status_code)
        else:
            return Response(serializer.error_messages, status=status.HTTP_400_BAD_REQUEST)


class ObtainEmailCallbackToken(AbstractBaseObtainCallbackToken):
    permission_classes = (AllowAny,)
    serializer_class = EmailAuthSerializer
    success_response = "A login token has been sent to your email."
    failure_response = "Unable to email you a login code. Try again later."

    alias_type = "email"
    token_type = CallbackToken.TOKEN_TYPE_AUTH

    email_subject = api_settings.PASSWORDLESS_EMAIL_SUBJECT
    email_plaintext = api_settings.PASSWORDLESS_EMAIL_PLAINTEXT_MESSAGE
    email_html = api_settings.PASSWORDLESS_EMAIL_TOKEN_HTML_TEMPLATE_NAME
    message_payload = {"email_subject": email_subject,
                       "email_plaintext": email_plaintext,
                       "email_html": email_html}


class ObtainMobileCallbackToken(AbstractBaseObtainCallbackToken):
    permission_classes = (AllowAny,)
    serializer_class = MobileAuthSerializer
    success_response = "We texted you a login code."
    failure_response = "Unable to send you a login code. Try again later."

    alias_type = "mobile"
    token_type = CallbackToken.TOKEN_TYPE_AUTH

    mobile_message = api_settings.PASSWORDLESS_MOBILE_MESSAGE
    message_payload = {"mobile_message": mobile_message}




class AbstractBaseObtainAuthToken(APIView):
    """
    This is a duplicate of rest_framework's own ObtainAuthToken method.
    Instead, this returns an Auth Token based on our 6 digit callback token and source.
    """
    serializer_class = None

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.validated_data["user"]
            token_creator = import_string(api_settings.PASSWORDLESS_AUTH_TOKEN_CREATOR)
            (token, _) = token_creator(user)

            if token:
                TokenSerializer = import_string(api_settings.PASSWORDLESS_AUTH_TOKEN_SERIALIZER)
                token_serializer = TokenSerializer(data=token.__dict__, partial=True, context={"request": request})
                if token_serializer.is_valid():
                    # Return our key for consumption.
                    return Response(token_serializer.data, status=status.HTTP_200_OK)
        else:
            logger.error("Couldn't log in unknown user. Errors on serializer: {}".format(serializer.error_messages))
        return Response({"detail": "Couldn't log you in. Try again later."}, status=status.HTTP_400_BAD_REQUEST)


class ObtainAuthTokenFromCallbackToken(AbstractBaseObtainAuthToken):
    """
    Overridden to support JWT tokens
    """
    serializer_class = CallbackTokenAuthSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.validated_data["user"]
            from django.utils.module_loading import import_string
            from .settings import api_settings
            
            token_creator = import_string(api_settings.PASSWORDLESS_AUTH_TOKEN_CREATOR)
            token_obj, _ = token_creator(user)

            if token_obj:
                TokenSerializer = import_string(api_settings.PASSWORDLESS_AUTH_TOKEN_SERIALIZER)
                token_serializer = TokenSerializer(data=token_obj, context={"request": request})
                if token_serializer.is_valid():
                    return Response(token_serializer.data, status=status.HTTP_200_OK)
            
            return Response({"detail": "Couldn't log you in. Try again later."}, 
                           status=status.HTTP_400_BAD_REQUEST)


