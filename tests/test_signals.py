from unittest import mock
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from jwt_passwordless.models import CallbackToken
from jwt_passwordless.settings import api_settings, DEFAULTS

User = get_user_model()


class SignalsTest(TestCase):
    """
    Tests for the jwt_passwordless signals.
    """

    def setUp(self):
        # Create our test user
        self.email = 'test@example.com'
        self.mobile = '+15551234567'
        
        self.email_field_name = api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME
        self.mobile_field_name = api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME
        self.email_verified_field_name = api_settings.PASSWORDLESS_USER_EMAIL_VERIFIED_FIELD_NAME
        self.mobile_verified_field_name = api_settings.PASSWORDLESS_USER_MOBILE_VERIFIED_FIELD_NAME
        
        self.user = User.objects.create(
            **{self.email_field_name: self.email, self.mobile_field_name: self.mobile}
        )
        
        # Set up settings for tests
        api_settings.PASSWORDLESS_USER_MARK_EMAIL_VERIFIED = True
        api_settings.PASSWORDLESS_USER_MARK_MOBILE_VERIFIED = True
        api_settings.PASSWORDLESS_AUTO_SEND_VERIFICATION_TOKEN = False
        api_settings.PASSWORDLESS_DEMO_USERS = {}

    def test_invalidate_previous_tokens(self):
        """Test invalidation of previous tokens when a new one is created."""
        # Create an initial token
        token1 = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=True
        )
        
        # Create a second token
        token2 = CallbackToken.objects.create(
            user=self.user,
            key='654321',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=True
        )
        
        # Refresh the first token from the database
        token1.refresh_from_db()
        
        # The first token should be inactive
        self.assertFalse(token1.is_active)
        # The second token should still be active
        self.assertTrue(token2.is_active)

    def test_demo_user_tokens_not_invalidated(self):
        """Test that tokens for demo users are not invalidated."""
        # Set up demo user
        api_settings.PASSWORDLESS_DEMO_USERS = {self.user.pk: '111222'}
        
        # Create an initial token
        token1 = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=True
        )
        
        # Create a second token
        token2 = CallbackToken.objects.create(
            user=self.user,
            key='654321',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=True
        )
        
        # Refresh the first token from the database
        token1.refresh_from_db()
        
        # The first token should still be active for demo users
        self.assertTrue(token1.is_active)
        # The second token should also be active
        self.assertTrue(token2.is_active)
        
        # Reset demo users
        api_settings.PASSWORDLESS_DEMO_USERS = {}

    def test_different_token_types_not_invalidated(self):
        """Test that tokens of different types don't invalidate each other."""
        # Create an auth token
        auth_token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=True
        )
        
        # Create a verify token
        verify_token = CallbackToken.objects.create(
            user=self.user,
            key='654321',
            type=CallbackToken.TOKEN_TYPE_VERIFY,
            is_active=True
        )
        
        # Refresh the auth token from the database
        auth_token.refresh_from_db()
        
        # The auth token should still be active
        self.assertTrue(auth_token.is_active)
        # The verify token should also be active
        self.assertTrue(verify_token.is_active)

    def test_tokens_for_different_users_not_invalidated(self):
        """Test that tokens for different users don't invalidate each other."""
        # Create another user
        other_user = User.objects.create(
            **{self.email_field_name: 'other@example.com', self.mobile_field_name: '+15559876543'}
        )
        
        # Create a token for the first user
        token1 = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=True
        )
        
        # Create a token for the second user
        token2 = CallbackToken.objects.create(
            user=other_user,
            key='654321',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=True
        )
        
        # Refresh both tokens from the database
        token1.refresh_from_db()
        token2.refresh_from_db()
        
        # Both tokens should still be active
        self.assertTrue(token1.is_active)
        self.assertTrue(token2.is_active)

    @mock.patch('jwt_passwordless.models.CallbackToken.objects.filter')
    def test_check_unique_tokens_retry(self, mock_filter):
        """Test token uniqueness check with retry."""
        # First call returns a non-empty queryset (token exists)
        # Second call returns an empty queryset (token doesn't exist)
        mock_filter.side_effect = [
            mock.MagicMock(exists=lambda: True),
            mock.MagicMock(exists=lambda: False)
        ]
        
        # Create a token (should trigger retry)
        token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=True
        )
        
        # Check that filter was called twice
        self.assertEqual(mock_filter.call_count, 2)
        
        # Token should have been created successfully
        self.assertIsNotNone(token)
        self.assertTrue(token.is_active)

    @mock.patch('jwt_passwordless.models.CallbackToken.objects.filter')
    def test_check_unique_tokens_max_retries(self, mock_filter):
        """Test token uniqueness check with max retries exceeded."""
        # All calls return a non-empty queryset (token always exists)
        mock_filter.return_value = mock.MagicMock(exists=lambda: True)
        
        # Attempt to create a token (should fail after max retries)
        with self.assertRaises(ValidationError):
            CallbackToken.objects.create(
                user=self.user,
                key='123456',
                type=CallbackToken.TOKEN_TYPE_AUTH,
                is_active=True
            )
        
        # Check that filter was called the expected number of times
        expected_calls = api_settings.PASSWORDLESS_TOKEN_GENERATION_ATTEMPTS
        self.assertEqual(mock_filter.call_count, expected_calls + 1)  # +1 for the initial call

    @mock.patch('jwt_passwordless.services.TokenService.send_token')
    def test_update_email_verification_flag(self, mock_send_token):
        """Test email verification flag is updated when email changes."""
        # Set user as verified
        setattr(self.user, self.email_verified_field_name, True)
        self.user.save()
        
        # Change email
        setattr(self.user, self.email_field_name, 'newemail@example.com')
        self.user.save()
        
        # Refresh user
        self.user.refresh_from_db()
        
        # Check verification flag is now False
        self.assertFalse(getattr(self.user, self.email_verified_field_name))
        
        # Token should not have been sent
        mock_send_token.assert_not_called()

    @mock.patch('jwt_passwordless.services.TokenService.send_token')
    def test_update_mobile_verification_flag(self, mock_send_token):
        """Test mobile verification flag is updated when mobile changes."""
        # Set user as verified
        setattr(self.user, self.mobile_verified_field_name, True)
        self.user.save()
        
        # Change mobile
        setattr(self.user, self.mobile_field_name, '+15559876543')
        self.user.save()
        
        # Refresh user
        self.user.refresh_from_db()
        
        # Check verification flag is now False
        self.assertFalse(getattr(self.user, self.mobile_verified_field_name))
        
        # Token should not have been sent
        mock_send_token.assert_not_called()

    @mock.patch('jwt_passwordless.services.TokenService.send_token')
    def test_auto_send_verification_email(self, mock_send_token):
        """Test auto-sending verification token when email changes."""
        # Enable auto-send
        api_settings.PASSWORDLESS_AUTO_SEND_VERIFICATION_TOKEN = True
        
        # Set user as verified
        setattr(self.user, self.email_verified_field_name, True)
        self.user.save()
        
        # Change email
        setattr(self.user, self.email_field_name, 'newemail@example.com')
        self.user.save()
        
        # Token should have been sent
        mock_send_token.assert_called_once()
        
        # Reset setting
        api_settings.PASSWORDLESS_AUTO_SEND_VERIFICATION_TOKEN = False

    @mock.patch('jwt_passwordless.services.TokenService.send_token')
    def test_auto_send_verification_mobile(self, mock_send_token):
        """Test auto-sending verification token when mobile changes."""
        # Enable auto-send
        api_settings.PASSWORDLESS_AUTO_SEND_VERIFICATION_TOKEN = True
        
        # Set user as verified
        setattr(self.user, self.mobile_verified_field_name, True)
        self.user.save()
        
        # Change mobile
        setattr(self.user, self.mobile_field_name, '+15559876543')
        self.user.save()
        
        # Token should have been sent
        mock_send_token.assert_called_once()
        
        # Reset setting
        api_settings.PASSWORDLESS_AUTO_SEND_VERIFICATION_TOKEN = False

    def test_no_verification_flag_update_on_new_user(self):
        """Test verification flags are not affected for new users."""
        # Create a new user
        new_user = User.objects.create(
            **{self.email_field_name: 'brand-new@example.com', self.mobile_field_name: '+15551112222'}
        )
        
        # By default, verification fields should be False
        self.assertFalse(getattr(new_user, self.email_verified_field_name))
        self.assertFalse(getattr(new_user, self.mobile_verified_field_name))

    def test_no_verification_flag_update_on_same_value(self):
        """Test verification flags are not affected when value doesn't change."""
        # Set user as verified
        setattr(self.user, self.email_verified_field_name, True)
        setattr(self.user, self.mobile_verified_field_name, True)
        self.user.save()
        
        # Update with same values
        setattr(self.user, self.email_field_name, self.email)
        setattr(self.user, self.mobile_field_name, self.mobile)
        self.user.save()
        
        # Refresh user
        self.user.refresh_from_db()
        
        # Verification flags should still be True
        self.assertTrue(getattr(self.user, self.email_verified_field_name))
        self.assertTrue(getattr(self.user, self.mobile_verified_field_name))

    def tearDown(self):
        # Reset settings to defaults
        api_settings.PASSWORDLESS_USER_MARK_EMAIL_VERIFIED = DEFAULTS['PASSWORDLESS_USER_MARK_EMAIL_VERIFIED']
        api_settings.PASSWORDLESS_USER_MARK_MOBILE_VERIFIED = DEFAULTS['PASSWORDLESS_USER_MARK_MOBILE_VERIFIED']
        api_settings.PASSWORDLESS_AUTO_SEND_VERIFICATION_TOKEN = DEFAULTS['PASSWORDLESS_AUTO_SEND_VERIFICATION_TOKEN']
        api_settings.PASSWORDLESS_DEMO_USERS = DEFAULTS['PASSWORDLESS_DEMO_USERS']