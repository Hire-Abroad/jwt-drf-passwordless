import logging
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.core.validators import RegexValidator
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from jwt_passwordless.models import CallbackToken
from jwt_passwordless.settings import api_settings
from jwt_passwordless.utils import verify_user_alias, validate_token_age

logger = logging.getLogger(__name__)
User = get_user_model()


class TokenField(serializers.CharField):
    default_error_messages = {
        'required': _('Invalid Token'),
        'invalid': _('Invalid Token'),
        'blank': _('Invalid Token'),
        'max_length': _('Tokens are {max_length} digits long.'),
        'min_length': _('Tokens are {min_length} digits long.')
    }


class AbstractBaseAliasAuthenticationSerializer(serializers.Serializer):
    """
    Abstract class that returns a callback token based on the field given
    Returns a token if valid, None or a message if not.
    """

    @property
    def alias_type(self):
        # The alias type, either email or mobile
        raise NotImplementedError

    def validate(self, attrs):
        alias = attrs.get(self.alias_type)

        if alias:
            # Create or authenticate a user
            # Return THem

            if api_settings.PASSWORDLESS_REGISTER_NEW_USERS is True:
                # If new aliases should register new users.
                try:
                    user = User.objects.get(**{self.alias_type+'__iexact': alias})
                except User.DoesNotExist:
                    user = User.objects.create(**{self.alias_type: alias})
                    user.set_unusable_password()
                    user.save()
            else:
                # If new aliases should not register new users.
                try:
                    user = User.objects.get(**{self.alias_type+'__iexact': alias})
                except User.DoesNotExist:
                    user = None

            if user:
                if not user.is_active:
                    # If valid, return attrs so we can create a token in our logic controller
                    msg = _('User account is disabled.')
                    raise serializers.ValidationError(msg)
            else:
                msg = _('No account is associated with this alias.')
                raise serializers.ValidationError(msg)
        else:
            msg = _('Missing %s.') % self.alias_type
            raise serializers.ValidationError(msg)

        attrs['user'] = user
        return attrs


class EmailAuthSerializer(AbstractBaseAliasAuthenticationSerializer):
    @property
    def alias_type(self):
        return api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Dynamically add the email field with the customized field name
        self.fields[api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME] = serializers.EmailField()
        


class MobileAuthSerializer(AbstractBaseAliasAuthenticationSerializer):
    @property
    def alias_type(self):
        return api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME

    phone_regex = RegexValidator(regex=r'^\+[1-9]\d{1,14}$',
                                 message="Mobile number must be entered in the format:"
                                         " '+999999999'. Up to 15 digits allowed.")
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Dynamically add the mobile field with the customized field name
        self.fields[api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME] = serializers.CharField(
            validators=[self.phone_regex], max_length=17
        )







"""
Callback Token
"""


def token_age_validator(value):
    """
    Check token age
    Makes sure a token is within the proper expiration datetime window.
    """
    valid_token = validate_token_age(value)
    if not valid_token:
        raise serializers.ValidationError("The token you entered isn't valid.")
    return value


class AbstractBaseCallbackTokenSerializer(serializers.Serializer):
    """
    Abstract class inspired by DRF's own token serializer.
    Returns a user if valid, None or a message if not.
    """
    phone_regex = RegexValidator(regex=r'^\+[1-9]\d{1,14}$',
                                message="Mobile number must be entered in the format:"
                                        " '+999999999'. Up to 15 digits allowed.")

    token = TokenField(min_length=3, max_length=6, validators=[token_age_validator])

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Dynamically add the email field with the customized field name
        self.fields[api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME] = serializers.EmailField(required=False)
        
        # Dynamically add the mobile field with the customized field name
        self.fields[api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME] = serializers.CharField(
            required=False, validators=[self.phone_regex], max_length=17
        )

    def validate_alias(self, attrs):
        # Use the customized field names from settings to get values
        email = attrs.get(api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME, None)
        mobile = attrs.get(api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME, None)

        if email and mobile:
            raise serializers.ValidationError()

        if not email and not mobile:
            raise serializers.ValidationError()

        if email:
            return api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME, email
        elif mobile:
            return api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME, mobile

        return None

class CallbackTokenAuthSerializer(AbstractBaseCallbackTokenSerializer):

    def validate(self, attrs):
        # Check Aliases
        try:
            alias_type, alias = self.validate_alias(attrs)
            callback_token = attrs.get('token', None)
            user = User.objects.get(**{alias_type+'__iexact': alias})
            token = CallbackToken.objects.get(**{'user': user,
                                                 'key': callback_token,
                                                 'type': CallbackToken.TOKEN_TYPE_AUTH,
                                                 'is_active': True})

            if token.user == user:
                # Check the token type for our uni-auth method.
                # authenticates and checks the expiry of the callback token.
                if not user.is_active:
                    msg = _('User account is disabled.')
                    raise serializers.ValidationError(msg)

                if api_settings.PASSWORDLESS_USER_MARK_EMAIL_VERIFIED \
                        or api_settings.PASSWORDLESS_USER_MARK_MOBILE_VERIFIED:
                    # Mark this alias as verified
                    user = User.objects.get(pk=token.user.pk)
                    success = verify_user_alias(user, token)

                    if success is False:
                        msg = _('Error validating user alias.')
                        raise serializers.ValidationError(msg)

                attrs['user'] = user
                return attrs

            else:
                msg = _('Invalid Token')
                raise serializers.ValidationError(msg)
        except CallbackToken.DoesNotExist:
            msg = _('Invalid alias parameters provided.')
            raise serializers.ValidationError(msg)
        except User.DoesNotExist:
            msg = _('Invalid user alias parameters provided.')
            raise serializers.ValidationError(msg)
        except ValidationError:
            msg = _('Invalid alias parameters provided.')
            raise serializers.ValidationError(msg)


class CallbackTokenVerificationSerializer(AbstractBaseCallbackTokenSerializer):
    """
    Takes a user and a token, verifies the token belongs to the user and
    validates the alias that the token was sent from.
    """

    def validate(self, attrs):
        try:
            alias_type, alias = self.validate_alias(attrs)
            user_id = self.context.get("user_id")
            user = User.objects.get(**{'id': user_id, alias_type+'__iexact': alias})
            callback_token = attrs.get('token', None)

            token = CallbackToken.objects.get(**{'user': user,
                                                 'key': callback_token,
                                                 'type': CallbackToken.TOKEN_TYPE_VERIFY,
                                                 'is_active': True})

            if token.user == user:
                # Mark this alias as verified
                success = verify_user_alias(user, token)
                if success is False:
                    logger.debug("jwt_passwordless: Error verifying alias.")

                attrs['user'] = user
                return attrs
            else:
                msg = _('This token is invalid. Try again later.')
                logger.debug("jwt_passwordless: User token mismatch when verifying alias.")

        except CallbackToken.DoesNotExist:
            msg = _('We could not verify this alias.')
            logger.debug("jwt_passwordless: Tried to validate alias with bad token.")
            pass
        except User.DoesNotExist:
            msg = _('We could not verify this alias.')
            logger.debug("jwt_passwordless: Tried to validate alias with bad user.")
            pass
        except PermissionDenied:
            msg = _('Insufficient permissions.')
            logger.debug("jwt_passwordless: Permission denied while validating alias.")
            pass

        raise serializers.ValidationError(msg)


"""
Responses
"""


class TokenResponseSerializer(serializers.Serializer):
    """
    Our default response serializer.
    """
    token = serializers.CharField(source='key')
    key = serializers.CharField(write_only=True)


class JWTTokenResponseSerializer(serializers.Serializer):
    """
    JWT token response serializer
    """
    access = serializers.CharField()
    refresh = serializers.CharField()
    