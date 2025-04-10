from unittest import mock
from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APIClient

from jwt_passwordless.models import CallbackToken
from jwt_passwordless.settings import api_settings, DEFAULTS

User = get_user_model()


class ViewsTest(TestCase):
    """
    Tests for the jwt_passwordless views.
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
        api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS = 'noreply@example.com'
        api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER = '+15550000000'
        api_settings.PASSWORDLESS_TEST_SUPPRESSION = True
        
        # Create client
        self.client = APIClient()
        
        # URLs
        self.email_url = reverse('jwt_passwordless:auth_email')
        self.mobile_url = reverse('jwt_passwordless:auth_mobile')
        self.token_url = reverse('jwt_passwordless:auth_token')

    @mock.patch('jwt_passwordless.services.TokenService.send_token')
    def test_obtain_email_callback_token_success(self, mock_send_token):
        """Test successful email token request."""
        # Configure mock to return success
        mock_send_token.return_value = True
        
        # Make request
        response = self.client.post(self.email_url, {'email': self.email})
        
        # Check response
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['detail'], "A login token has been sent to your email.")
        
        # Check the token service was called correctly
        mock_send_token.assert_called_once()
        args, kwargs = mock_send_token.call_args
        self.assertEqual(args[0], self.user)
        self.assertEqual(args[1], 'email')
        self.assertEqual(args[2], CallbackToken.TOKEN_TYPE_AUTH)

    @mock.patch('jwt_passwordless.services.TokenService.send_token')
    def test_obtain_email_callback_token_failure(self, mock_send_token):
        """Test failed email token request."""
        # Configure mock to return failure
        mock_send_token.return_value = False
        
        # Make request
        response = self.client.post(self.email_url, {'email': self.email})
        
        # Check response
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['detail'], "Unable to email you a login code. Try again later.")

    def test_obtain_email_callback_token_invalid_data(self):
        """Test email token request with invalid data."""
        # Make request with invalid email
        response = self.client.post(self.email_url, {'email': 'invalid-email'})
        
        # Check response
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_obtain_email_callback_token_disabled_auth_type(self):
        """Test email token request with disabled auth type."""
        # Disable email auth
        api_settings.PASSWORDLESS_AUTH_TYPES = ['MOBILE']
        
        # Make request
        response = self.client.post(self.email_url, {'email': self.email})
        
        # Check response
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        
        # Reset setting
        api_settings.PASSWORDLESS_AUTH_TYPES = ['EMAIL', 'MOBILE']

    @mock.patch('jwt_passwordless.services.TokenService.send_token')
    def test_obtain_mobile_callback_token_success(self, mock_send_token):
        """Test successful mobile token request."""
        # Configure mock to return success
        mock_send_token.return_value = True
        
        # Make request
        response = self.client.post(self.mobile_url, {'mobile': self.mobile})
        
        # Check response
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['detail'], "We texted you a login code.")
        
        # Check the token service was called correctly
        mock_send_token.assert_called_once()
        args, kwargs = mock_send_token.call_args
        self.assertEqual(args[0], self.user)
        self.assertEqual(args[1], 'mobile')
        self.assertEqual(args[2], CallbackToken.TOKEN_TYPE_AUTH)

    @mock.patch('jwt_passwordless.services.TokenService.send_token')
    def test_obtain_mobile_callback_token_failure(self, mock_send_token):
        """Test failed mobile token request."""
        # Configure mock to return failure
        mock_send_token.return_value = False
        
        # Make request
        response = self.client.post(self.mobile_url, {'mobile': self.mobile})
        
        # Check response
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['detail'], "Unable to send you a login code. Try again later.")

    def test_obtain_mobile_callback_token_invalid_data(self):
        """Test mobile token request with invalid data."""
        # Make request with invalid mobile
        response = self.client.post(self.mobile_url, {'mobile': 'invalid-mobile'})
        
        # Check response
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_obtain_mobile_callback_token_disabled_auth_type(self):
        """Test mobile token request with disabled auth type."""
        # Disable mobile auth
        api_settings.PASSWORDLESS_AUTH_TYPES = ['EMAIL']
        
        # Make request
        response = self.client.post(self.mobile_url, {'mobile': self.mobile})
        
        # Check response
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        
        # Reset setting
        api_settings.PASSWORDLESS_AUTH_TYPES = ['EMAIL', 'MOBILE']

    @mock.patch('jwt_passwordless.utils.create_jwt_token_for_user')
    def test_obtain_auth_token_email_success(self, mock_create_token):
        """Test successful token auth via email."""
        # Create token
        auth_token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=True
        )
        
        # Configure mock to return success
        mock_create_token.return_value = ({'access': 'access-token', 'refresh': 'refresh-token'}, True)
        
        # Make request
        response = self.client.post(self.token_url, {'email': self.email, 'token': auth_token.key})
        
        # Check response
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['access'], 'access-token')
        self.assertEqual(response.data['refresh'], 'refresh-token')
        
        # Check the token creation function was called
        mock_create_token.assert_called_once_with(self.user)

    @mock.patch('jwt_passwordless.utils.create_jwt_token_for_user')
    def test_obtain_auth_token_mobile_success(self, mock_create_token):
        """Test successful token auth via mobile."""
        # Create token
        auth_token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=True
        )
        
        # Configure mock to return success
        mock_create_token.return_value = ({'access': 'access-token', 'refresh': 'refresh-token'}, True)
        
        # Make request
        response = self.client.post(self.token_url, {'mobile': self.mobile, 'token': auth_token.key})
        
        # Check response
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['access'], 'access-token')
        self.assertEqual(response.data['refresh'], 'refresh-token')
        
        # Check the token creation function was called
        mock_create_token.assert_called_once_with(self.user)

    def test_obtain_auth_token_invalid_data(self):
        """Test token auth with invalid data."""
        # Make request with invalid token
        response = self.client.post(self.token_url, {'email': self.email, 'token': 'invalid-token'})
        
        # Check response
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_obtain_auth_token_inactive_token(self):
        """Test token auth with inactive token."""
        # Create inactive token
        auth_token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=False
        )
        
        # Make request
        response = self.client.post(self.token_url, {'email': self.email, 'token': auth_token.key})
        
        # Check response
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_obtain_auth_token_nonexistent_user(self):
        """Test token auth with non-existent user."""
        # Make request with non-existent user
        response = self.client.post(self.token_url, {'email': 'nonexistent@example.com', 'token': '123456'})
        
        # Check response
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @mock.patch('jwt_passwordless.utils.create_jwt_token_for_user')
    def test_obtain_auth_token_token_creation_failure(self, mock_create_token):
        """Test token auth with token creation failure."""
        # Create token
        auth_token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=True
        )
        
        # Configure mock to return failure
        mock_create_token.return_value = (None, False)
        
        # Make request
        response = self.client.post(self.token_url, {'email': self.email, 'token': auth_token.key})
        
        # Check response
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['detail'], "Couldn't log you in. Try again later.")

    @mock.patch('jwt_passwordless.utils.create_jwt_token_for_user')
    def test_obtain_auth_token_invalid_serializer(self, mock_create_token):
        """Test token auth with invalid token serializer."""
        # Create token
        auth_token = CallbackToken.objects.create(
            user=self.user,
            key='123456',
            type=CallbackToken.TOKEN_TYPE_AUTH,
            is_active=True
        )
        
        # Configure mock to return data that won't validate
        mock_create_token.return_value = ({'invalid': 'data'}, True)
        
        # Make request
        response = self.client.post(self.token_url, {'email': self.email, 'token': auth_token.key})
        
        # Check response
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    
    def tearDown(self):
        # Reset settings to defaults
        api_settings.PASSWORDLESS_AUTH_TYPES = DEFAULTS['PASSWORDLESS_AUTH_TYPES']
        api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS = DEFAULTS['PASSWORDLESS_EMAIL_NOREPLY_ADDRESS']
        api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER = DEFAULTS['PASSWORDLESS_MOBILE_NOREPLY_NUMBER']
        api_settings.PASSWORDLESS_TEST_SUPPRESSION = DEFAULTS['PASSWORDLESS_TEST_SUPPRESSION']


