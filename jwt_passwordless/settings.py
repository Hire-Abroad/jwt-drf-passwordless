from django.conf import settings
from rest_framework.settings import APISettings

USER_SETTINGS = getattr(settings, 'PASSWORDLESS_AUTH', None)

DEFAULTS = {

    # Allowed auth types, can be EMAIL, MOBILE, or both.
    'PASSWORDLESS_AUTH_TYPES': ['EMAIL'],

    # URL Prefix for Authentication Endpoints
    'PASSWORDLESS_AUTH_PREFIX': 'auth/',

    #  URL Prefix for Verification Endpoints
    'PASSWORDLESS_VERIFY_PREFIX': 'auth/verify/',

    # Amount of time that tokens last, in seconds
    'PASSWORDLESS_TOKEN_EXPIRE_TIME': 15 * 60,

    # The user's email field name
    'PASSWORDLESS_USER_EMAIL_FIELD_NAME': 'email',

    # The user's mobile field name
    'PASSWORDLESS_USER_MOBILE_FIELD_NAME': 'mobile',

    # Marks itself as verified the first time a user completes auth via token.
    # Automatically unmarks itself if email is changed.
    'PASSWORDLESS_USER_MARK_EMAIL_VERIFIED': False,
    'PASSWORDLESS_USER_EMAIL_VERIFIED_FIELD_NAME': 'email_verified',

    # Marks itself as verified the first time a user completes auth via token.
    # Automatically unmarks itself if mobile number is changed.
    'PASSWORDLESS_USER_MARK_MOBILE_VERIFIED': False,
    'PASSWORDLESS_USER_MOBILE_VERIFIED_FIELD_NAME': 'mobile_verified',

    # The email the callback token is sent from
    'PASSWORDLESS_EMAIL_NOREPLY_ADDRESS': None,

    # The email subject
    'PASSWORDLESS_EMAIL_SUBJECT': "Your Login Token",

    # A plaintext email message overridden by the html message. Takes one string.
    'PASSWORDLESS_EMAIL_PLAINTEXT_MESSAGE': "Enter this token to sign in: %s",

    # The email template name.
    'PASSWORDLESS_EMAIL_TOKEN_HTML_TEMPLATE_NAME': "passwordless_default_token_email.html",

    # Your twilio number that sends the callback tokens.
    'PASSWORDLESS_MOBILE_NOREPLY_NUMBER': None,

    # The message sent to mobile users logging in. Takes one string.
    'PASSWORDLESS_MOBILE_MESSAGE': "Use this code to log in: %s",

    # Registers previously unseen aliases as new users.
    'PASSWORDLESS_REGISTER_NEW_USERS': True,

    # Suppresses actual SMS for testing
    'PASSWORDLESS_TEST_SUPPRESSION': False,

    # Context Processors for Email Template
    'PASSWORDLESS_CONTEXT_PROCESSORS': [],

    # The verification email subject
    'PASSWORDLESS_EMAIL_VERIFICATION_SUBJECT': "Your Verification Token",

    # A plaintext verification email message overridden by the html message. Takes one string.
    'PASSWORDLESS_EMAIL_VERIFICATION_PLAINTEXT_MESSAGE': "Enter this verification code: %s",

    # The verification email template name.
    'PASSWORDLESS_EMAIL_VERIFICATION_TOKEN_HTML_TEMPLATE_NAME': "passwordless_default_verification_token_email.html",

    # The message sent to mobile users logging in. Takes one string.
    'PASSWORDLESS_MOBILE_VERIFICATION_MESSAGE': "Enter this verification code: %s",

    # Automatically send verification email or sms when a user changes their alias.
    'PASSWORDLESS_AUTO_SEND_VERIFICATION_TOKEN': False,

    'PASSWORDLESS_EMAIL_CALLBACK': 'jwt_passwordless.utils.send_email_with_callback_token',
    'PASSWORDLESS_SMS_CALLBACK': 'jwt_passwordless.utils.send_sms_with_callback_token',
    
    # Token Generation Retry Count
    'PASSWORDLESS_TOKEN_GENERATION_ATTEMPTS': 3,
    
    # New JWT settings
    'PASSWORDLESS_AUTH_TOKEN_CREATOR': 'jwt_passwordless.utils.create_jwt_token_for_user',
    'PASSWORDLESS_AUTH_TOKEN_SERIALIZER': 'jwt_passwordless.serializers.JWTTokenResponseSerializer',
    
    # Secondary email settings (placeholder for future)
    'PASSWORDLESS_USE_SECONDARY_EMAIL': False,
    'PASSWORDLESS_USER_SECONDARY_EMAIL_FIELD_NAME': 'secondary_email',
    'PASSWORDLESS_USER_SECONDARY_EMAIL_VERIFIED_FIELD_NAME': 'secondary_email_verified',
    'PASSWORDLESS_EMAIL_LOOKUP_STRATEGY': 'PRIMARY_ONLY',
    
    'PASSWORDLESS_DEMO_USERS': {},
    
    # Token length settings
    'PASSWORDLESS_TOKEN_LENGTH': 6,
}

# List of settings that may be in string import notation.
IMPORT_STRINGS = (
    'PASSWORDLESS_EMAIL_TOKEN_HTML_TEMPLATE',
    'PASSWORDLESS_CONTEXT_PROCESSORS',
)

api_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)
