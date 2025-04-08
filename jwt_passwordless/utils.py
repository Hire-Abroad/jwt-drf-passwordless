import logging
import os
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.core.mail import send_mail
from django.template import loader
from django.utils import timezone
from jwt_passwordless.models import CallbackToken
from jwt_passwordless.settings import api_settings


logger = logging.getLogger(__name__)
User = get_user_model()


def authenticate_by_token(callback_token):
    try:
        token = CallbackToken.objects.get(key=callback_token, is_active=True, type=CallbackToken.TOKEN_TYPE_AUTH)

        # Returning a user designates a successful authentication.
        token.user = User.objects.get(pk=token.user.pk)
        token.is_active = False  # Mark this token as used.
        token.save()

        return token.user

    except CallbackToken.DoesNotExist:
        logger.debug("jwt_passwordless: Challenged with a callback token that doesn't exist.")
    except User.DoesNotExist:
        logger.debug("jwt_passwordless: Authenticated user somehow doesn't exist.")
    except PermissionDenied:
        logger.debug("jwt_passwordless: Permission denied while authenticating.")

    return None


def create_callback_token_for_user(user, alias_type, token_type):
    token = None
    alias_type_u = alias_type.upper()
    to_alias_field = getattr(api_settings, f'PASSWORDLESS_USER_{alias_type_u}_FIELD_NAME')
    if user.pk in api_settings.PASSWORDLESS_DEMO_USERS.keys():
        token = CallbackToken.objects.filter(user=user).first()
        if token:
            return token
        else:
            return CallbackToken.objects.create(
                user=user,
                key=api_settings.PASSWORDLESS_DEMO_USERS[user.pk],
                to_alias_type=alias_type_u,
                to_alias=getattr(user, to_alias_field),
                type=token_type
            )
    
    token = CallbackToken.objects.create(user=user,
                                            to_alias_type=alias_type_u,
                                            to_alias=getattr(user, to_alias_field),
                                            type=token_type)



    if token is not None:
        return token

    return None


def validate_token_age(callback_token):
    """
    Returns True if a given token is within the age expiration limit.
    """

    try:
        token = CallbackToken.objects.get(key=callback_token, is_active=True)
        seconds = (timezone.now() - token.created_at).total_seconds()
        token_expiry_time = api_settings.PASSWORDLESS_TOKEN_EXPIRE_TIME
        if token.user.pk in api_settings.PASSWORDLESS_DEMO_USERS.keys():
            return True
        if seconds <= token_expiry_time:
            return True
        else:
            # Invalidate our token.
            token.is_active = False
            token.save()
            return False

    except CallbackToken.DoesNotExist:
        # No valid token.
        return False


def verify_user_alias(user, token):
    """
    Marks a user's contact point as verified depending on accepted token type.
    """
    if token.to_alias_type == 'EMAIL':
        if token.to_alias == getattr(user, api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME):
            setattr(user, api_settings.PASSWORDLESS_USER_EMAIL_VERIFIED_FIELD_NAME, True)
    elif token.to_alias_type == 'MOBILE':
        if token.to_alias == getattr(user, api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME):
            setattr(user, api_settings.PASSWORDLESS_USER_MOBILE_VERIFIED_FIELD_NAME, True)
    else:
        return False
    user.save()
    return True


def inject_template_context(context):
    """
    Injects additional context into email template.
    """
    for processor in api_settings.PASSWORDLESS_CONTEXT_PROCESSORS:
        context.update(processor())
    return context


def send_email_with_callback_token(user, email_token, **kwargs):
    """
    Sends a Email to user.email.

    Passes silently without sending in test environment
    """

    try:
        if api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS:
            # Make sure we have a sending address before sending.

            # Get email subject and message
            email_subject = kwargs.get('email_subject',
                                       api_settings.PASSWORDLESS_EMAIL_SUBJECT)
            email_plaintext = kwargs.get('email_plaintext',
                                         api_settings.PASSWORDLESS_EMAIL_PLAINTEXT_MESSAGE)
            email_html = kwargs.get('email_html',
                                    api_settings.PASSWORDLESS_EMAIL_TOKEN_HTML_TEMPLATE_NAME)

            # Inject context if user specifies.
            context = inject_template_context({'callback_token': email_token.key, })
            html_message = loader.render_to_string(email_html, context,)
            send_mail(
                email_subject,
                email_plaintext % email_token.key,
                api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS,
                [getattr(user, api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME)],
                fail_silently=False,
                html_message=html_message,)

        else:
            logger.debug("Failed to send token email. Missing PASSWORDLESS_EMAIL_NOREPLY_ADDRESS.")
            return False
        return True

    except Exception as e:
        logger.debug("Failed to send token email to user: %d."
                  "Possibly no email on user object. Email entered was %s" %
                  (user.id, getattr(user, api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME)))
        logger.debug(e)
        return False



def create_jwt_token_for_user(user):
    """Create a JWT token for the given user"""
    from rest_framework_simplejwt.tokens import RefreshToken
    from .settings import api_settings
    
    
    try:
        refresh = RefreshToken.for_user(user)
        
        # Add custom claims if needed
        if hasattr(user, 'email'):
            refresh['email'] = user.email
            
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, True
        
    except Exception as e:
        # Log the error
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error creating JWT token: {str(e)}")
        
        return None, False