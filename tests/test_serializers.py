from unittest import mock
from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError

from jwt_passwordless.models import CallbackToken
from jwt_passwordless.serializers import (
    EmailAuthSerializer, 
    MobileAuthSerializer,
    CallbackTokenAuthSerializer,
    CallbackTokenVerificationSerializer,
    AbstractBaseCallbackTokenSerializer
)
from jwt_passwordless.settings import api_settings, DEFAULTS

User = get_user_model()


class SerializersTest(TestCase):
    """
    Tests for the jwt_passwordless serializers.
    """

    def setUp(self):
        # Create our test user
        self.email = 'test@example.com'
        self.mobile = '+15551234567'
        
        self.email_field_name = api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME
        self.mobile_field_name = api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME
        
        self.user = User.objects.create(
            **{self.email_field_name: self.email, self.mobile_field_name: self.mobile}
        )
        
        # Set up settings for tests
        api_settings.PASSWORDLESS_AUTH_TYPES = ['EMAIL', 'MOBILE']
        api_settings.PASSWORDLESS_REGISTER_NEW_USERS = True
        api_settings.PASSWORDLESS_USER_MARK_EMAIL_VERIFIED = True
        api_settings.PASSWORDLESS_USER_MARK_MOBILE_VERIFIED = True
        
        # Setup token for tests
        self.auth_token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            to_alias_type='EMAIL',
            to_alias=self.email,
            is_active=True
        )

    def test_email_auth_serializer_valid(self):
        """Test EmailAuthSerializer with valid data."""
        serializer = EmailAuthSerializer(data={'email': self.email})
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data['user'], self.user)

    def test_email_auth_serializer_new_user(self):
        """Test EmailAuthSerializer creating a new user."""
        new_email = 'newuser@example.com'
        serializer = EmailAuthSerializer(data={'email': new_email})
        self.assertTrue(serializer.is_valid())
        
        # Check a new user was created
        new_user = User.objects.get(**{self.email_field_name: new_email})
        self.assertIsNotNone(new_user)
        self.assertEqual(serializer.validated_data['user'], new_user)

    def test_email_auth_serializer_no_registration(self):
        """Test EmailAuthSerializer with registration disabled."""
        api_settings.PASSWORDLESS_REGISTER_NEW_USERS = False
        
        new_email = 'anotheruser@example.com'
        serializer = EmailAuthSerializer(data={'email': new_email})
        
        with self.assertRaises(ValidationError):
            serializer.is_valid(raise_exception=True)
            
        # Check no new user was created
        self.assertFalse(User.objects.filter(**{self.email_field_name: new_email}).exists())
        
        # Reset setting
        api_settings.PASSWORDLESS_REGISTER_NEW_USERS = True

    @mock.patch('jwt_passwordless.serializers.User.objects.get')
    def test_email_auth_serializer_inactive_user(self, mock_get):
        """Test EmailAuthSerializer with an inactive user."""
        # Set up the mock to return an inactive user
        inactive_user = User.objects.create(
            **{self.email_field_name: 'inactive@example.com', self.mobile_field_name: '+15551112222'}
        )
        inactive_user.is_active = False
        inactive_user.save()
        
        mock_get.return_value = inactive_user
        
        serializer = EmailAuthSerializer(data={'email': 'inactive@example.com'})
        
        with self.assertRaises(ValidationError):
            serializer.is_valid(raise_exception=True)

    def test_email_auth_serializer_missing_email(self):
        """Test EmailAuthSerializer with missing email."""
        serializer = EmailAuthSerializer(data={})
        
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)
        
    def test_mobile_auth_serializer_valid(self):
        """Test MobileAuthSerializer with valid data."""
        serializer = MobileAuthSerializer(data={'mobile': self.mobile})
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data['user'], self.user)

    def test_mobile_auth_serializer_new_user(self):
        """Test MobileAuthSerializer creating a new user."""
        new_mobile = '+15559876543'
        serializer = MobileAuthSerializer(data={'mobile': new_mobile})
        self.assertTrue(serializer.is_valid())
        
        # Check a new user was created
        new_user = User.objects.get(**{self.mobile_field_name: new_mobile})
        self.assertIsNotNone(new_user)
        self.assertEqual(serializer.validated_data['user'], new_user)

    def test_mobile_auth_serializer_invalid_mobile(self):
        """Test MobileAuthSerializer with invalid mobile number."""
        serializer = MobileAuthSerializer(data={'mobile': 'not-a-phone-number'})
        
        self.assertFalse(serializer.is_valid())
        self.assertIn('mobile', serializer.errors)

    def test_callback_token_auth_serializer_valid(self):
        """Test CallbackTokenAuthSerializer with valid data."""
        serializer = CallbackTokenAuthSerializer(data={
            'email': self.email,
            'token': self.auth_token.key
        })
        
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data['user'], self.user)

    def test_callback_token_auth_serializer_invalid_token(self):
        """Test CallbackTokenAuthSerializer with invalid token."""
        serializer = CallbackTokenAuthSerializer(data={
            'email': self.email,
            'token': 'invalid-token'
        })
        
        self.assertFalse(serializer.is_valid())

    def test_callback_token_auth_serializer_inactive_token(self):
        """Test CallbackTokenAuthSerializer with inactive token."""
        # Make token inactive
        self.auth_token.is_active = False
        self.auth_token.save()
        
        serializer = CallbackTokenAuthSerializer(data={
            'email': self.email,
            'token': self.auth_token.key
        })
        
        self.assertFalse(serializer.is_valid())
        
        # Reset token
        self.auth_token.is_active = True
        self.auth_token.save()

    @mock.patch('jwt_passwordless.serializers.User.objects.get')
    def test_callback_token_auth_serializer_inactive_user(self, mock_get):
        """Test CallbackTokenAuthSerializer with inactive user."""
        # Create a new inactive user
        inactive_user = User.objects.create(
            **{self.email_field_name: 'inactive@example.com', self.mobile_field_name: '+15551112222'}
        )
        inactive_user.is_active = False
        inactive_user.save()
        
        # Configure mock to return our token with inactive user
        mock_get.return_value = inactive_user
        
        serializer = CallbackTokenAuthSerializer(data={
            'email': 'inactive@example.com',
            'token': '654321'
        })
        
        with self.assertRaises(ValidationError):
            serializer.is_valid(raise_exception=True)

    def test_callback_token_auth_serializer_both_aliases(self):
        """Test CallbackTokenAuthSerializer with both email and mobile."""
        serializer = CallbackTokenAuthSerializer(data={
            'email': self.email,
            'mobile': self.mobile,
            'token': self.auth_token.key
        })
        
        self.assertFalse(serializer.is_valid())

    def test_callback_token_auth_serializer_no_aliases(self):
        """Test CallbackTokenAuthSerializer with no aliases."""
        serializer = CallbackTokenAuthSerializer(data={
            'token': self.auth_token.key
        })
        
        self.assertFalse(serializer.is_valid())

    def test_callback_token_verification_serializer_valid(self):
        """Test CallbackTokenVerificationSerializer with valid data."""
        # Create a verification token
        verify_token = CallbackToken.objects.create(
            user=self.user,
            key='654321',
            type=CallbackToken.TOKEN_TYPE_VERIFY,
            to_alias_type='EMAIL',
            to_alias=self.email,
            is_active=True
        )
        
        serializer = CallbackTokenVerificationSerializer(
            data={'email': self.email, 'token': verify_token.key},
            context={'user_id': self.user.id}
        )
        
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data['user'], self.user)

    def test_callback_token_verification_serializer_invalid_token(self):
        """Test CallbackTokenVerificationSerializer with invalid token."""
        serializer = CallbackTokenVerificationSerializer(
            data={'email': self.email, 'token': 'invalid-token'},
            context={'user_id': self.user.id}
        )
        
        self.assertFalse(serializer.is_valid())

    def test_custom_email_field_name(self):
        """Test serializers with custom email field name."""
        # Save original field name
        original_email_field = api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME
        
        # Change field name
        api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME = 'secondary_email'
        
        # Create user with secondary email
        secondary_email = 'secondary@example.com'
        user = User.objects.create(secondary_email=secondary_email)
        
        # Test EmailAuthSerializer
        email_serializer = EmailAuthSerializer(data={'secondary_email': secondary_email})
        self.assertTrue(email_serializer.is_valid())
        self.assertEqual(email_serializer.validated_data['user'], user)
        
        # Test CallbackTokenAuthSerializer
        token = CallbackToken.objects.create(
            user=user,
            key='789012',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            to_alias_type='EMAIL',
            to_alias=secondary_email,
            is_active=True
        )
        
        token_serializer = CallbackTokenAuthSerializer(data={
            'secondary_email': secondary_email,
            'token': token.key
        })
        
        self.assertTrue(token_serializer.is_valid())
        self.assertEqual(token_serializer.validated_data['user'], user)
        
        # Restore original field name
        api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME = original_email_field

    def test_custom_mobile_field_name(self):
        """Test serializers with custom mobile field name."""
        # Save original field name
        original_mobile_field = api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME
        
        # Change field name
        api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME = 'secondary_mobile'
        
        # Create user with secondary mobile
        secondary_mobile = '+15558889999'
        user = User.objects.create(secondary_mobile=secondary_mobile)
        
        # Test MobileAuthSerializer
        mobile_serializer = MobileAuthSerializer(data={'secondary_mobile': secondary_mobile})
        self.assertTrue(mobile_serializer.is_valid())
        self.assertEqual(mobile_serializer.validated_data['user'], user)
        
        # Test CallbackTokenAuthSerializer
        token = CallbackToken.objects.create(
            user=user,
            key='345678',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            to_alias_type='MOBILE',
            to_alias=secondary_mobile,
            is_active=True
        )
        
        token_serializer = CallbackTokenAuthSerializer(data={
            'secondary_mobile': secondary_mobile,
            'token': token.key
        })
        
        self.assertTrue(token_serializer.is_valid())
        self.assertEqual(token_serializer.validated_data['user'], user)
        
        # Restore original field name
        api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME = original_mobile_field

    def tearDown(self):
        # Reset settings to defaults
        api_settings.PASSWORDLESS_AUTH_TYPES = DEFAULTS['PASSWORDLESS_AUTH_TYPES']
        api_settings.PASSWORDLESS_REGISTER_NEW_USERS = DEFAULTS['PASSWORDLESS_REGISTER_NEW_USERS']
        api_settings.PASSWORDLESS_USER_MARK_EMAIL_VERIFIED = DEFAULTS['PASSWORDLESS_USER_MARK_EMAIL_VERIFIED']
        api_settings.PASSWORDLESS_USER_MARK_MOBILE_VERIFIED = DEFAULTS['PASSWORDLESS_USER_MARK_MOBILE_VERIFIED']
        api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME = DEFAULTS['PASSWORDLESS_USER_EMAIL_FIELD_NAME']
        api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME = DEFAULTS['PASSWORDLESS_USER_MOBILE_FIELD_NAME']



