from django.test import TestCase
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from jwt_passwordless.models import (
    CallbackToken,
    CallbackTokenManger,
    generate_hex_token,
    generate_numeric_token
)
from jwt_passwordless.settings import api_settings, DEFAULTS

User = get_user_model()


class ModelTestCase(TestCase):
    """
    Tests for the jwt_passwordless models.
    """

    def setUp(self):
        self.email = 'test@example.com'
        self.mobile = '+15551234567'
        
        self.email_field_name = api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME
        self.mobile_field_name = api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME
        
        self.user = User.objects.create(
            **{self.email_field_name: self.email, self.mobile_field_name: self.mobile}
        )

    def test_hex_token_generation(self):
        """Test generation of hex tokens."""
        token1 = generate_hex_token()
        token2 = generate_hex_token()
        
        # Tokens should be strings
        self.assertIsInstance(token1, str)
        self.assertIsInstance(token2, str)
        
        # Tokens should be different
        self.assertNotEqual(token1, token2)
        
        # Tokens should be hex format
        self.assertEqual(len(token1), 32)  # UUID1 hex is 32 characters
        self.assertTrue(all(c in '0123456789abcdef' for c in token1.lower()))

    def test_numeric_token_generation_default_length(self):
        """Test generation of numeric tokens with default length."""
        # Default length should be applied
        token = generate_numeric_token()
        
        # Token should be a string
        self.assertIsInstance(token, str)
        
        # Token should be all digits
        self.assertTrue(token.isdigit())
        
        # Token should have correct length (default or constrained)
        expected_length = min(6, max(3, api_settings.PASSWORDLESS_TOKEN_LENGTH))
        self.assertEqual(len(token), expected_length)

    def test_numeric_token_generation_custom_length(self):
        """Test generation of numeric tokens with custom length."""
        # Save original setting
        original_length = api_settings.PASSWORDLESS_TOKEN_LENGTH
        
        # Test with different lengths
        for length in [3, 4, 5, 6, 7, 8]:
            api_settings.PASSWORDLESS_TOKEN_LENGTH = length
            token = generate_numeric_token()
            expected_length = min(6, max(3, length))
            self.assertEqual(len(token), expected_length)
        
        # Restore original setting
        api_settings.PASSWORDLESS_TOKEN_LENGTH = original_length

    def test_callback_token_manager_active(self):
        """Test the active() method of CallbackTokenManger."""
        # signals invalidates old tokens for the same user, so that I created the inactive token first
        # Create active and inactive tokens
        inactive_token = CallbackToken.objects.create(
            user=self.user,
            key='654321',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=False
        )
        
        active_token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=True
        )
        
        
        # Get active tokens
        active_tokens = CallbackToken.objects.active()
                
        # Check that only active token is included
        self.assertEqual(active_tokens.count(), 1)
        self.assertIn(active_token, active_tokens)
        self.assertNotIn(inactive_token, active_tokens)

    def test_callback_token_manager_inactive(self):
        """Test the inactive() method of CallbackTokenManger."""
        # Create active and inactive tokens
        inactive_token = CallbackToken.objects.create(
            user=self.user,
            key='654321',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=False
        )
        # signals invalidates old tokens for the same user, so that I created the inactive token first
        active_token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=True
        )
        
        
        # Get inactive tokens
        inactive_tokens = CallbackToken.objects.inactive()
        
        # Check that only inactive token is included
        self.assertEqual(inactive_tokens.count(), 1)
        self.assertIn(inactive_token, inactive_tokens)
        self.assertNotIn(active_token, inactive_tokens)
        
    def test_callback_token_str_representation(self):
        """Test the string representation of CallbackToken."""
        token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH
        )
        
        # String representation should be the key
        self.assertEqual(str(token), '123456')
        
    def test_callback_token_types(self):
        """Test the token types of CallbackToken."""
        auth_token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH
        )
        
        verify_token = CallbackToken.objects.create(
            user=self.user,
            key='654321',
            type=CallbackToken.TOKEN_TYPE_VERIFY
        )
        
        # Check token types
        self.assertEqual(auth_token.type, CallbackToken.TOKEN_TYPE_AUTH)
        self.assertEqual(verify_token.type, CallbackToken.TOKEN_TYPE_VERIFY)
        
        
    def tearDown(self):
        # Clean up
        CallbackToken.objects.all().delete()