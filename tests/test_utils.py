import datetime
import os
from unittest import mock
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from jwt_passwordless.models import CallbackToken
from jwt_passwordless.settings import api_settings, DEFAULTS
from jwt_passwordless.utils import (
    authenticate_by_token,
    create_callback_token_for_user,
    validate_token_age,
    verify_user_alias,
    inject_template_context,
    send_email_with_callback_token,
    send_sms_with_callback_token,
    create_jwt_token_for_user,
)
from django.core.exceptions import PermissionDenied


User = get_user_model()


class UtilsTest(TestCase):
    """
    Test the utility functions for jwt_passwordless
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
        
        api_settings.PASSWORDLESS_USER_MARK_EMAIL_VERIFIED = True
        api_settings.PASSWORDLESS_USER_MARK_MOBILE_VERIFIED = True
        api_settings.PASSWORDLESS_TEST_SUPPRESSION = True
        api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS = 'noreply@example.com'
        api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER = '+15551234567'
        api_settings.PASSWORDLESS_TOKEN_EXPIRE_TIME = 15 * 60  # 15 minutes

    def test_authenticate_by_token_valid(self):
        """Test authentication with a valid token."""
        token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=True
        )
        
        authenticated_user = authenticate_by_token(token.key)
        self.assertEqual(authenticated_user, self.user)
        
        # Check token is marked as used (inactive)
        token.refresh_from_db()
        self.assertFalse(token.is_active)

    def test_authenticate_by_token_nonexistent(self):
        """Test authentication with a token that doesn't exist."""
        authenticated_user = authenticate_by_token('invalid-token')
        self.assertIsNone(authenticated_user)

    def test_authenticate_by_token_inactive(self):
        """Test authentication with an inactive token."""
        token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=False
        )
        
        authenticated_user = authenticate_by_token(token.key)
        self.assertIsNone(authenticated_user)

    def test_create_callback_token_for_user_email(self):
        """Test creating a callback token for a user's email."""
        token = create_callback_token_for_user(
            user=self.user,
            alias_type='email',
            token_type=CallbackToken.TOKEN_TYPE_AUTH
        )
        
        self.assertIsNotNone(token)
        self.assertEqual(token.user, self.user)
        self.assertEqual(token.to_alias_type, 'EMAIL')
        self.assertEqual(token.to_alias, self.email)
        self.assertEqual(token.type, CallbackToken.TOKEN_TYPE_AUTH)
        self.assertTrue(token.is_active)

    def test_create_callback_token_for_user_mobile(self):
        """Test creating a callback token for a user's mobile."""
        token = create_callback_token_for_user(
            user=self.user,
            alias_type='mobile',
            token_type=CallbackToken.TOKEN_TYPE_AUTH
        )
        
        self.assertIsNotNone(token)
        self.assertEqual(token.user, self.user)
        self.assertEqual(token.to_alias_type, 'MOBILE')
        self.assertEqual(token.to_alias, self.mobile)
        self.assertEqual(token.type, CallbackToken.TOKEN_TYPE_AUTH)
        self.assertTrue(token.is_active)

    def test_create_callback_token_for_demo_user(self):
        """Test creating a callback token for a demo user."""
        # Set up a demo user
        api_settings.PASSWORDLESS_DEMO_USERS = {self.user.pk: '111222'}
        
        token = create_callback_token_for_user(
            user=self.user,
            alias_type='email',
            token_type=CallbackToken.TOKEN_TYPE_AUTH
        )
        
        self.assertIsNotNone(token)
        self.assertEqual(token.key, '111222')
        
        # Clean up
        api_settings.PASSWORDLESS_DEMO_USERS = {}

    def test_validate_token_age_valid(self):
        """Test validation of a token within the age limit."""
        token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=True
        )
        
        is_valid = validate_token_age(token.key)
        self.assertTrue(is_valid)

    def test_validate_token_age_expired(self):
        """Test validation of an expired token."""
        token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=True
        )
        
        # Set token creation time to past expiry
        expired_time = timezone.now() - datetime.timedelta(seconds=api_settings.PASSWORDLESS_TOKEN_EXPIRE_TIME + 60)
        CallbackToken.objects.filter(pk=token.pk).update(created_at=expired_time)
        
        is_valid = validate_token_age(token.key)
        self.assertFalse(is_valid)
        
        # Check token is marked as inactive
        token.refresh_from_db()
        self.assertFalse(token.is_active)

    def test_validate_token_age_nonexistent(self):
        """Test validation of a non-existent token."""
        is_valid = validate_token_age('nonexistent-token')
        self.assertFalse(is_valid)

    def test_validate_token_age_demo_user(self):
        """Test validation of a token for a demo user."""
        token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=True
        )
        
        # Set user as a demo user
        api_settings.PASSWORDLESS_DEMO_USERS = {self.user.pk: '123456'}
        
        # Even with an expired token, demo user tokens are always valid
        expired_time = timezone.now() - datetime.timedelta(seconds=api_settings.PASSWORDLESS_TOKEN_EXPIRE_TIME + 60)
        CallbackToken.objects.filter(pk=token.pk).update(created_at=expired_time)
        
        is_valid = validate_token_age(token.key)
        self.assertTrue(is_valid)
        
        # Clean up
        api_settings.PASSWORDLESS_DEMO_USERS = {}

    def test_verify_user_alias_email(self):
        """Test verification of a user's email alias."""
        token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            to_alias_type='EMAIL',
            to_alias=self.email
        )
        
        setattr(self.user, api_settings.PASSWORDLESS_USER_EMAIL_VERIFIED_FIELD_NAME, False)
        self.user.save()
        
        result = verify_user_alias(self.user, token)
        self.assertTrue(result)
        
        # Check user is marked as verified
        self.user.refresh_from_db()
        self.assertTrue(getattr(self.user, api_settings.PASSWORDLESS_USER_EMAIL_VERIFIED_FIELD_NAME))

    def test_verify_user_alias_mobile(self):
        """Test verification of a user's mobile alias."""
        token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            to_alias_type='MOBILE',
            to_alias=self.mobile
        )
        
        setattr(self.user, api_settings.PASSWORDLESS_USER_MOBILE_VERIFIED_FIELD_NAME, False)
        self.user.save()
        
        result = verify_user_alias(self.user, token)
        self.assertTrue(result)
        
        # Check user is marked as verified
        self.user.refresh_from_db()
        self.assertTrue(getattr(self.user, api_settings.PASSWORDLESS_USER_MOBILE_VERIFIED_FIELD_NAME))

    def test_verify_user_alias_mismatched_email(self):
        """Test verification with mismatched email alias."""
        token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            to_alias_type='EMAIL',
            to_alias='different@example.com'  # Different from user's email
        )
        
        setattr(self.user, api_settings.PASSWORDLESS_USER_EMAIL_VERIFIED_FIELD_NAME, False)
        self.user.save()
        
        result = verify_user_alias(self.user, token)
        self.assertTrue(result)
        
        # Check user is still not verified
        self.user.refresh_from_db()
        self.assertFalse(getattr(self.user, api_settings.PASSWORDLESS_USER_EMAIL_VERIFIED_FIELD_NAME))

    def test_verify_user_alias_unsupported_type(self):
        """Test verification with an unsupported alias type."""
        token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            to_alias_type='UNSUPPORTED',  # Unsupported type
            to_alias='value'
        )
        
        result = verify_user_alias(self.user, token)
        self.assertFalse(result)

    @mock.patch('jwt_passwordless.utils.send_mail')
    def test_send_email_with_callback_token_success(self, mock_send_mail):
        """Test successful sending of email with callback token."""
        api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS = 'noreply@example.com'
        token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            to_alias_type='EMAIL',
            to_alias=self.email
        )
        
        result = send_email_with_callback_token(
            user=self.user,
            email_token=token,
            email_subject='Test Subject',
            email_plaintext='Your token is %s',
            email_html=api_settings.PASSWORDLESS_EMAIL_TOKEN_HTML_TEMPLATE_NAME
        )
        
        self.assertTrue(result)
        mock_send_mail.assert_called_once()
        api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS = DEFAULTS['PASSWORDLESS_EMAIL_NOREPLY_ADDRESS']

    @mock.patch('jwt_passwordless.utils.send_mail')
    def test_send_email_no_noreply_address(self, mock_send_mail):
        """Test email sending with no noreply address configured."""
        token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            to_alias_type='EMAIL',
            to_alias=self.email
        )
        
        # Remove noreply address
        api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS = None
        
        result = send_email_with_callback_token(
            user=self.user,
            email_token=token
        )
        
        self.assertFalse(result)
        mock_send_mail.assert_not_called()
        
        # Restore setting
        api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS = 'noreply@example.com'

    @mock.patch('jwt_passwordless.utils.send_mail')
    def test_send_email_exception(self, mock_send_mail):
        """Test email sending with an exception occurring."""
        token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            to_alias_type='EMAIL',
            to_alias=self.email
        )
        
        # Make send_mail raise an exception
        mock_send_mail.side_effect = Exception("Test exception")
        
        result = send_email_with_callback_token(
            user=self.user,
            email_token=token
        )
        
        self.assertFalse(result)

    def test_send_sms_test_suppression(self):
        """Test SMS sending with test suppression enabled."""
        token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            to_alias_type='MOBILE',
            to_alias=self.mobile
        )
        
        api_settings.PASSWORDLESS_TEST_SUPPRESSION = True
        
        result = send_sms_with_callback_token(
            user=self.user,
            mobile_token=token
        )
        
        self.assertTrue(result)

    def test_send_sms_no_noreply_number(self):
        """Test SMS sending with no noreply number configured."""
        token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            to_alias_type='MOBILE',
            to_alias=self.mobile
        )
        
        # Remove noreply number with suppression on
        api_settings.PASSWORDLESS_TEST_SUPPRESSION = True
        api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER = None
        
        result = send_sms_with_callback_token(
            user=self.user,
            mobile_token=token
        )
        
        self.assertFalse(result)
        
        # Restore setting
        api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER = '+15551234567'

    @mock.patch('jwt_passwordless.utils.RefreshToken')
    def test_create_jwt_token_for_user_success(self, mock_refresh_token):
        """Test successful creation of JWT token for user."""
        # Set up mock refresh token
        mock_token = mock.MagicMock()
        mock_token.access_token = 'access-token'
        mock_refresh_token.for_user.return_value = mock_token
        mock_token.__str__.return_value = 'refresh-token'
        
        token_data, success = create_jwt_token_for_user(self.user)
        
        self.assertTrue(success)
        self.assertEqual(token_data['access'], 'access-token')
        self.assertEqual(token_data['refresh'], 'refresh-token')
        mock_refresh_token.for_user.assert_called_once_with(self.user)

    @mock.patch('jwt_passwordless.utils.RefreshToken.for_user', side_effect=Exception("Test exception"))
    def test_create_jwt_token_for_user_exception(self, mock_refresh_token):
        """Test JWT token creation with an exception occurring."""
        token_data, success = create_jwt_token_for_user(self.user)
        
        self.assertFalse(success)
        self.assertIsNone(token_data)

    def test_inject_template_context(self):
        """Test injecting context into email template."""
        # Define a mock context processor
        def mock_processor():
            return {'additional_context': 'value'}
        
        # Save original processors
        original_processors = api_settings.PASSWORDLESS_CONTEXT_PROCESSORS
        
        # Set our mock processor
        api_settings.PASSWORDLESS_CONTEXT_PROCESSORS = [mock_processor]
        
        context = {'callback_token': '123456'}
        result = inject_template_context(context)
        
        self.assertEqual(result['callback_token'], '123456')
        self.assertEqual(result['additional_context'], 'value')
        
        # Restore original processors
        api_settings.PASSWORDLESS_CONTEXT_PROCESSORS = original_processors

    def tearDown(self):
        # Reset settings to defaults
        api_settings.PASSWORDLESS_USER_MARK_EMAIL_VERIFIED = DEFAULTS['PASSWORDLESS_USER_MARK_EMAIL_VERIFIED']
        api_settings.PASSWORDLESS_USER_MARK_MOBILE_VERIFIED = DEFAULTS['PASSWORDLESS_USER_MARK_MOBILE_VERIFIED']
        api_settings.PASSWORDLESS_TEST_SUPPRESSION = DEFAULTS['PASSWORDLESS_TEST_SUPPRESSION']
        api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS = DEFAULTS['PASSWORDLESS_EMAIL_NOREPLY_ADDRESS']
        api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER = DEFAULTS['PASSWORDLESS_MOBILE_NOREPLY_NUMBER']
        api_settings.PASSWORDLESS_TOKEN_EXPIRE_TIME = DEFAULTS['PASSWORDLESS_TOKEN_EXPIRE_TIME']
        api_settings.PASSWORDLESS_DEMO_USERS = DEFAULTS['PASSWORDLESS_DEMO_USERS']





class AdditionalUtilsTest(TestCase):
    """
    Additional tests to improve coverage for jwt_passwordless.utils
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
        
        api_settings.PASSWORDLESS_USER_MARK_EMAIL_VERIFIED = True
        api_settings.PASSWORDLESS_USER_MARK_MOBILE_VERIFIED = True
        api_settings.PASSWORDLESS_TEST_SUPPRESSION = True
        api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS = 'noreply@example.com'
        api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER = '+15551234567'
        api_settings.PASSWORDLESS_TOKEN_EXPIRE_TIME = 15 * 60  # 15 minutes

    def test_authenticate_by_token_user_does_not_exist(self):
        """Test authentication when user does not exist."""
        token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=True
        )
        
        # Mock User.objects.get to raise DoesNotExist
        with mock.patch('jwt_passwordless.utils.User.objects.get', side_effect=User.DoesNotExist):
            authenticated_user = authenticate_by_token(token.key)
            self.assertIsNone(authenticated_user)

    def test_authenticate_by_token_permission_denied(self):
        """Test authentication when permission is denied."""
        token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=True
        )
        
        # Mock User.objects.get to raise PermissionDenied
        with mock.patch('jwt_passwordless.utils.User.objects.get', side_effect=PermissionDenied):
            authenticated_user = authenticate_by_token(token.key)
            self.assertIsNone(authenticated_user)

    def test_create_callback_token_for_user_existing_demo_token(self):
        """Test creating a callback token for a demo user that already has a token."""
        # Set up a demo user
        api_settings.PASSWORDLESS_DEMO_USERS = {self.user.pk: '111222'}
        
        # Create an existing token
        existing_token = CallbackToken.objects.create(
            user=self.user,
            key='111222',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            to_alias_type='EMAIL',
            to_alias=self.email
        )
        
        token = create_callback_token_for_user(
            user=self.user,
            alias_type='email',
            token_type=CallbackToken.TOKEN_TYPE_AUTH
        )
        
        self.assertEqual(token, existing_token)
        
        # Clean up
        api_settings.PASSWORDLESS_DEMO_USERS = {}

    def test_create_callback_token_none_return(self):
        """Test the edge case where token creation might return None."""
        # Use mocking to force token to be None - this hits the final return None path
        with mock.patch('jwt_passwordless.utils.CallbackToken.objects.create', return_value=None):
            token = create_callback_token_for_user(
                user=self.user,
                alias_type='email',
                token_type=CallbackToken.TOKEN_TYPE_AUTH
            )
            self.assertIsNone(token)


    @mock.patch('jwt_passwordless.utils.send_mail')
    def test_send_email_with_callback_token_custom_context(self, mock_send_mail):
        """Test sending email with custom context processors."""
        
        def custom_context_processor():
            return {'site_name': 'Test Site'}
        
        # Save original processors
        original_processors = api_settings.PASSWORDLESS_CONTEXT_PROCESSORS
        api_settings.PASSWORDLESS_CONTEXT_PROCESSORS = [custom_context_processor]
        
        token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            to_alias_type='EMAIL',
            to_alias=self.email
        )
        
        result = send_email_with_callback_token(
            user=self.user,
            email_token=token
        )
        
        self.assertTrue(result)
        
        # Verify context was injected
        mock_send_mail.assert_called_once()
        # Restore original processors
        api_settings.PASSWORDLESS_CONTEXT_PROCESSORS = original_processors

    def test_send_sms_with_callback_token_missing_twilio_env(self):
        """Test SMS sending with missing Twilio environment variables."""
        token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            to_alias_type='MOBILE',
            to_alias=self.mobile
        )
        
        # Disable test suppression to test Twilio path
        api_settings.PASSWORDLESS_TEST_SUPPRESSION = False
        
        # Mock KeyError when accessing Twilio environment variables
        with mock.patch.dict('os.environ', clear=True):  # Empty environment
            result = send_sms_with_callback_token(
                user=self.user,
                mobile_token=token
            )
            
            self.assertFalse(result)
        
        # Restore test suppression
        api_settings.PASSWORDLESS_TEST_SUPPRESSION = True

    
    def test_send_sms_with_callback_token_missing_noreply_number(self):
        """Test SMS sending with missing noreply number but real Twilio attempt."""
        token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            to_alias_type='MOBILE',
            to_alias=self.mobile
        )
        
        # Disable test suppression and remove noreply number
        api_settings.PASSWORDLESS_TEST_SUPPRESSION = False
        original_noreply = api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER
        api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER = None
        
        result = send_sms_with_callback_token(
            user=self.user,
            mobile_token=token
        )
        
        self.assertFalse(result)
        
        # Restore settings
        api_settings.PASSWORDLESS_TEST_SUPPRESSION = True
        api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER = original_noreply

    def tearDown(self):
        # Reset settings to defaults
        api_settings.PASSWORDLESS_USER_MARK_EMAIL_VERIFIED = DEFAULTS['PASSWORDLESS_USER_MARK_EMAIL_VERIFIED']
        api_settings.PASSWORDLESS_USER_MARK_MOBILE_VERIFIED = DEFAULTS['PASSWORDLESS_USER_MARK_MOBILE_VERIFIED']
        api_settings.PASSWORDLESS_TEST_SUPPRESSION = DEFAULTS['PASSWORDLESS_TEST_SUPPRESSION']
        api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS = DEFAULTS['PASSWORDLESS_EMAIL_NOREPLY_ADDRESS']
        api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER = DEFAULTS['PASSWORDLESS_MOBILE_NOREPLY_NUMBER']
        api_settings.PASSWORDLESS_TOKEN_EXPIRE_TIME = DEFAULTS['PASSWORDLESS_TOKEN_EXPIRE_TIME']
        api_settings.PASSWORDLESS_DEMO_USERS = DEFAULTS['PASSWORDLESS_DEMO_USERS']