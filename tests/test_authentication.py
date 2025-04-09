from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken

from django.contrib.auth import get_user_model
from django.urls import reverse
from jwt_passwordless.settings import api_settings, DEFAULTS
from jwt_passwordless.models import CallbackToken

User = get_user_model()


class EmailSignUpCallbackTokenTests(APITestCase):

    def setUp(self):
        api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS = 'noreply@example.com'
        self.email_field_name = api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME

        self.url = reverse('jwt_passwordless:auth_email')

    def test_email_signup_failed(self):
        email = 'failedemail182+'
        data = {'email': email}

        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_email_signup_success(self):
        email = 'aaron@example.com'
        data = {'email': email}

        # Verify user doesn't exist yet
        user = User.objects.filter(**{self.email_field_name: 'aaron@example.com'}).first()
        # Make sure our user isn't None, meaning the user was created.
        self.assertEqual(user, None)

        # verify a new user was created with serializer
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        user = User.objects.get(**{self.email_field_name: 'aaron@example.com'})
        self.assertNotEqual(user, None)

        # Verify a token exists for the user
        self.assertEqual(CallbackToken.objects.filter(user=user, is_active=True).exists(), 1)

    def test_email_signup_disabled(self):
        api_settings.PASSWORDLESS_REGISTER_NEW_USERS = False

        # Verify user doesn't exist yet
        user = User.objects.filter(**{self.email_field_name: 'aaron@example.com'}).first()
        # Make sure our user isn't None, meaning the user was created.
        self.assertEqual(user, None)

        email = 'aaron@example.com'
        data = {'email': email}

        # verify a new user was not created
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(**{self.email_field_name: 'aaron@example.com'}).first()
        self.assertEqual(user, None)

        # Verify no token was created for the user
        self.assertEqual(CallbackToken.objects.filter(user=user, is_active=True).exists(), 0)
    
    def test_email_signup_with_custom_email_field(self):
        """
        Test that a user can be created with a custom email field name.
        """
        api_settings.PASSWORDLESS_REGISTER_NEW_USERS = True
        api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME = 'secondary_email'
        self.email_field_name = api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME
        email = 'test@example.com'
        data = {self.email_field_name: email}

        # Verify user doesn't exist yet
        user = User.objects.filter(**{self.email_field_name: 'test@example.com'}).first()
        # Make sure our user isn't None, meaning the user was created.
        self.assertEqual(user, None)

        # verify a new user was created with serializer
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        user = User.objects.get(**{self.email_field_name: 'test@example.com'})
        self.assertNotEqual(user, None)

        # Verify a token exists for the user
        self.assertEqual(CallbackToken.objects.filter(user=user, is_active=True).exists(), 1)

    def tearDown(self):
        api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS = DEFAULTS['PASSWORDLESS_EMAIL_NOREPLY_ADDRESS']
        api_settings.PASSWORDLESS_REGISTER_NEW_USERS = DEFAULTS['PASSWORDLESS_REGISTER_NEW_USERS']
        api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME = DEFAULTS['PASSWORDLESS_USER_EMAIL_FIELD_NAME']


class EmailLoginCallbackTokenTests(APITestCase):

    def setUp(self):
        api_settings.PASSWORDLESS_AUTH_TYPES = ['EMAIL']
        api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS = 'noreply@example.com'

        self.email = 'aaron@example.com'
        self.url = reverse('jwt_passwordless:auth_email')
        self.challenge_url = reverse('jwt_passwordless:auth_token')

        self.email_field_name = api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME
        self.user = User.objects.create(**{self.email_field_name: self.email})

    def test_email_auth_failed(self):
        data = {'email': self.email}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Token sent to alias
        challenge_data = {'email': self.email, 'token': '123456'}  # Send an arbitrary token instead

        # Try to auth with the callback token
        challenge_response = self.client.post(self.challenge_url, challenge_data)
        self.assertEqual(challenge_response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_email_auth_missing_alias(self):
        data = {'email': self.email}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Token sent to alias
        callback_token = CallbackToken.objects.filter(user=self.user, is_active=True).first()
        challenge_data = {'token': callback_token}  # Missing Alias

        # Try to auth with the callback token
        challenge_response = self.client.post(self.challenge_url, challenge_data)
        self.assertEqual(challenge_response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_email_auth_bad_alias(self):
        data = {'email': self.email}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Token sent to alias
        callback_token = CallbackToken.objects.filter(user=self.user, is_active=True).first()
        challenge_data = {'email': 'abcde@example.com', 'token': callback_token}  # Bad Alias

        # Try to auth with the callback token
        challenge_response = self.client.post(self.challenge_url, challenge_data)
        self.assertEqual(challenge_response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_email_auth_expired(self):
        data = {'email': self.email}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Token sent to alias
        callback_token = CallbackToken.objects.filter(user=self.user, is_active=True).first()
        challenge_data = {'email': self.email, 'token': callback_token}

        data = {'email': self.email}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Second token sent to alias
        second_callback_token = CallbackToken.objects.filter(user=self.user, is_active=True).first()
        second_challenge_data = {'email': self.email, 'token': second_callback_token}

        # Try to auth with the old callback token
        challenge_response = self.client.post(self.challenge_url, challenge_data)
        self.assertEqual(challenge_response.status_code, status.HTTP_400_BAD_REQUEST)

        # Try to auth with the new callback token
        second_challenge_response = self.client.post(self.challenge_url, second_challenge_data)
        self.assertEqual(second_challenge_response.status_code, status.HTTP_200_OK)

        # Verify JWT Token format
        self.assertIn('access', second_challenge_response.data)
        self.assertIn('refresh', second_challenge_response.data)

    def test_email_auth_success(self):
        data = {'email': self.email}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Token sent to alias
        callback_token = CallbackToken.objects.filter(user=self.user, is_active=True).first()
        challenge_data = {'email': self.email, 'token': callback_token}

        # Try to auth with the callback token
        challenge_response = self.client.post(self.challenge_url, challenge_data)
        self.assertEqual(challenge_response.status_code, status.HTTP_200_OK)

        # Verify JWT Token format 
        self.assertIn('access', challenge_response.data)
        self.assertIn('refresh', challenge_response.data)
        
        # Basic validation that these appear to be JWT tokens
        self.assertEqual(len(challenge_response.data['access'].split('.')), 3)
        self.assertEqual(len(challenge_response.data['refresh'].split('.')), 3)
    
    def test_email_auth_success_with_custom_email_field(self):
        """
        Test that a user can be authenticated with a custom email field name.
        """
        api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME = 'secondary_email'
        self.email_field_name = api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME
        data = {self.email_field_name: self.email}
        setattr(self.user, self.email_field_name, self.email)
        setattr(self.user, 'email', None)
        self.user.save()
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        callback_token = CallbackToken.objects.filter(user=self.user, is_active=True).first()
        challenge_data = {self.email_field_name: self.email, 'token': callback_token}

        challenge_response = self.client.post(self.challenge_url, challenge_data)
        self.assertEqual(challenge_response.status_code, status.HTTP_200_OK)

        self.assertIn('access', challenge_response.data)
        self.assertIn('refresh', challenge_response.data)
        
        self.assertEqual(len(challenge_response.data['access'].split('.')), 3)
        self.assertEqual(len(challenge_response.data['refresh'].split('.')), 3)

    def tearDown(self):
        api_settings.PASSWORDLESS_AUTH_TYPES = DEFAULTS['PASSWORDLESS_AUTH_TYPES']
        api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS = DEFAULTS['PASSWORDLESS_EMAIL_NOREPLY_ADDRESS']
        api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME = DEFAULTS['PASSWORDLESS_USER_EMAIL_FIELD_NAME']
        self.user.delete()


"""
Mobile Tests
"""


class MobileSignUpCallbackTokenTests(APITestCase):

    def setUp(self):
        api_settings.PASSWORDLESS_TEST_SUPPRESSION = True
        api_settings.PASSWORDLESS_AUTH_TYPES = ['MOBILE']
        api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER = '+15550000000'
        self.url = reverse('jwt_passwordless:auth_mobile')

        self.mobile_field_name = api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME

    def test_mobile_signup_failed(self):
        mobile = 'sidfj98zfd'
        data = {'mobile': mobile}

        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_mobile_signup_success(self):
        mobile = '+15551234567'
        data = {'mobile': mobile}

        # Verify user doesn't exist yet
        user = User.objects.filter(**{self.mobile_field_name: '+15551234567'}).first()
        # Make sure our user isn't None, meaning the user was created.
        self.assertEqual(user, None)

        # verify a new user was created with serializer
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        user = User.objects.get(**{self.mobile_field_name: '+15551234567'})
        self.assertNotEqual(user, None)

        # Verify a token exists for the user
        self.assertEqual(CallbackToken.objects.filter(user=user, is_active=True).exists(), 1)

    def test_mobile_signup_disabled(self):
        api_settings.PASSWORDLESS_REGISTER_NEW_USERS = False

        # Verify user doesn't exist yet
        user = User.objects.filter(**{self.mobile_field_name: '+15557654321'}).first()
        # Make sure our user isn't None, meaning the user was created.
        self.assertEqual(user, None)

        mobile = '+15557654321'
        data = {'mobile': mobile}

        # verify a new user was not created
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(**{self.mobile_field_name: '+15557654321'}).first()
        self.assertEqual(user, None)

        # Verify no token was created for the user
        self.assertEqual(CallbackToken.objects.filter(user=user, is_active=True).exists(), 0)
    
    def test_mobile_signup_with_custom_mobile_field(self):
        """
        Test that a user can be created with a custom mobile field name.
        """
        api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME = 'secondary_mobile'
        self.mobile_field_name = api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME
        
        mobile = '+15551234567'
        data = {self.mobile_field_name: mobile}

        # Verify user doesn't exist yet
        user = User.objects.filter(**{self.mobile_field_name: '+15551234567'}).first()
        # Make sure our user isn't None, meaning the user was created.
        self.assertEqual(user, None)

        # verify a new user was created with serializer
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        user = User.objects.get(**{self.mobile_field_name: '+15551234567'})
        self.assertNotEqual(user, None)

        # Verify a token exists for the user
        self.assertEqual(CallbackToken.objects.filter(user=user, is_active=True).exists(), 1)

    def tearDown(self):
        api_settings.PASSWORDLESS_TEST_SUPPRESSION = DEFAULTS['PASSWORDLESS_TEST_SUPPRESSION']
        api_settings.PASSWORDLESS_AUTH_TYPES = DEFAULTS['PASSWORDLESS_AUTH_TYPES']
        api_settings.PASSWORDLESS_REGISTER_NEW_USERS = DEFAULTS['PASSWORDLESS_REGISTER_NEW_USERS']
        api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER = DEFAULTS['PASSWORDLESS_MOBILE_NOREPLY_NUMBER']
        api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME = DEFAULTS['PASSWORDLESS_USER_MOBILE_FIELD_NAME']


def create_custom_jwt_token(user):
    """Test helper to create a custom JWT token response"""
    from jwt_passwordless.utils import create_jwt_token_for_user
    token_data, _ = create_jwt_token_for_user(user)
    
    # Ensure it's a dict with access and refresh
    token_data['access'] = 'dummy-access-token'
    token_data['refresh'] = 'dummy-refresh-token'
    
    return token_data, True


class OverrideJWTTokenCreationTests(APITestCase):
    def setUp(self):
        super().setUp()

        api_settings.PASSWORDLESS_AUTH_TOKEN_CREATOR = 'tests.test_authentication.create_custom_jwt_token'
        api_settings.PASSWORDLESS_AUTH_TYPES = ['EMAIL']
        api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS = 'noreply@example.com'

        self.email = 'aaron@example.com'
        self.url = reverse('jwt_passwordless:auth_email')
        self.challenge_url = reverse('jwt_passwordless:auth_token')

        self.email_field_name = api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME
        self.user = User.objects.create(**{self.email_field_name: self.email})

    def test_token_creation_gets_overridden(self):
        """Ensure that if we change the token creation function, the overridden one gets called"""
        data = {'email': self.email}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Token sent to alias
        callback_token = CallbackToken.objects.filter(user=self.user, is_active=True).first()
        challenge_data = {'email': self.email, 'token': callback_token}

        # Try to auth with the callback token
        challenge_response = self.client.post(self.challenge_url, challenge_data)
        self.assertEqual(challenge_response.status_code, status.HTTP_200_OK)

        # Verify Custom JWT Token
        self.assertEqual(challenge_response.data['access'], 'dummy-access-token')
        self.assertEqual(challenge_response.data['refresh'], 'dummy-refresh-token')

    def tearDown(self):
        api_settings.PASSWORDLESS_AUTH_TOKEN_CREATOR = DEFAULTS['PASSWORDLESS_AUTH_TOKEN_CREATOR']
        api_settings.PASSWORDLESS_AUTH_TYPES = DEFAULTS['PASSWORDLESS_AUTH_TYPES']
        api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS = DEFAULTS['PASSWORDLESS_EMAIL_NOREPLY_ADDRESS']
        self.user.delete()
        super().tearDown()


class MobileLoginCallbackTokenTests(APITestCase):

    def setUp(self):
        api_settings.PASSWORDLESS_TEST_SUPPRESSION = True
        api_settings.PASSWORDLESS_AUTH_TYPES = ['MOBILE']
        api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER = '+15550000000'

        self.mobile = '+15551234567'
        self.url = reverse('jwt_passwordless:auth_mobile')
        self.challenge_url = reverse('jwt_passwordless:auth_token')

        self.mobile_field_name = api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME

        self.user = User.objects.create(**{self.mobile_field_name: self.mobile})

    def test_mobile_auth_failed(self):
        data = {'mobile': self.mobile}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Token sent to alias
        challenge_data = {'mobile': self.mobile, 'token': '123456'}  # Send an arbitrary token instead

        # Try to auth with the callback token
        challenge_response = self.client.post(self.challenge_url, challenge_data)
        self.assertEqual(challenge_response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_mobile_auth_expired(self):
        data = {'mobile': self.mobile}
        first_response = self.client.post(self.url, data)
        self.assertEqual(first_response.status_code, status.HTTP_200_OK)

        # Token sent to alias
        first_callback_token = CallbackToken.objects.filter(user=self.user, is_active=True).first()
        first_challenge_data = {'mobile': self.mobile, 'token': first_callback_token}

        data = {'mobile': self.mobile}
        second_response = self.client.post(self.url, data)
        self.assertEqual(second_response.status_code, status.HTTP_200_OK)

        # Second token sent to alias
        second_callback_token = CallbackToken.objects.filter(user=self.user, is_active=True).first()
        second_challenge_data = {'mobile': self.mobile, 'token': second_callback_token}

        # Try to auth with the old callback token
        challenge_response = self.client.post(self.challenge_url, first_challenge_data)
        self.assertEqual(challenge_response.status_code, status.HTTP_400_BAD_REQUEST)

        # Try to auth with the new callback token
        second_challenge_response = self.client.post(self.challenge_url, second_challenge_data)
        self.assertEqual(second_challenge_response.status_code, status.HTTP_200_OK)

        # Verify JWT Token format
        self.assertIn('access', second_challenge_response.data)
        self.assertIn('refresh', second_challenge_response.data)

    def test_mobile_auth_success(self):
        data = {'mobile': self.mobile}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Token sent to alias
        callback_token = CallbackToken.objects.filter(user=self.user, is_active=True).first()
        challenge_data = {'mobile': self.mobile, 'token': callback_token}

        # Try to auth with the callback token
        challenge_response = self.client.post(self.challenge_url, challenge_data)
        self.assertEqual(challenge_response.status_code, status.HTTP_200_OK)

        # Verify JWT Token format
        self.assertIn('access', challenge_response.data)
        self.assertIn('refresh', challenge_response.data)
        
        # Basic validation that these appear to be JWT tokens
        self.assertEqual(len(challenge_response.data['access'].split('.')), 3)
        self.assertEqual(len(challenge_response.data['refresh'].split('.')), 3)

    def test_mobile_auth_success_with_custom_mobile_field(self):
        """
        Test that a user can be authenticated with a custom mobile field name.
        """
        api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME = 'secondary_mobile'
        self.mobile_field_name = api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME
        
        mobile = '+15551234567'
        data = {self.mobile_field_name: mobile}
        setattr(self.user, self.mobile_field_name, self.mobile)
        setattr(self.user, 'mobile', None)
        self.user.save()
        
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        callback_token = CallbackToken.objects.filter(user=self.user, is_active=True).first()
        challenge_data = {self.mobile_field_name: mobile, 'token': callback_token}

        challenge_response = self.client.post(self.challenge_url, challenge_data)
        self.assertEqual(challenge_response.status_code, status.HTTP_200_OK)

        self.assertIn('access', challenge_response.data)
        self.assertIn('refresh', challenge_response.data)
        
        self.assertEqual(len(challenge_response.data['access'].split('.')), 3)
        self.assertEqual(len(challenge_response.data['refresh'].split('.')), 3)

    def tearDown(self):
        api_settings.PASSWORDLESS_TEST_SUPPRESSION = DEFAULTS['PASSWORDLESS_TEST_SUPPRESSION']
        api_settings.PASSWORDLESS_AUTH_TYPES = DEFAULTS['PASSWORDLESS_AUTH_TYPES']
        api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER = DEFAULTS['PASSWORDLESS_MOBILE_NOREPLY_NUMBER']
        api_settings.PASSWORDLESS_REGISTER_NEW_USERS = DEFAULTS['PASSWORDLESS_REGISTER_NEW_USERS']
        api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME = DEFAULTS['PASSWORDLESS_USER_MOBILE_FIELD_NAME']
        self.user.delete()