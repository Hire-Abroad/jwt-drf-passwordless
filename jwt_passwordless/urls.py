from jwt_passwordless.settings import api_settings
from django.urls import path, include
from jwt_passwordless.views import (
     ObtainEmailCallbackToken,
     ObtainMobileCallbackToken,
     ObtainAuthTokenFromCallbackToken,
     VerifyAliasFromCallbackToken,
     ObtainEmailVerificationCallbackToken,
     ObtainMobileVerificationCallbackToken,
)
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

app_name = 'jwt_passwordless'

urlpatterns = [
     path(api_settings.PASSWORDLESS_AUTH_PREFIX + 'email/', ObtainEmailCallbackToken.as_view(), name='auth_email'),
     path(api_settings.PASSWORDLESS_AUTH_PREFIX + 'mobile/', ObtainMobileCallbackToken.as_view(), name='auth_mobile'),
     path(api_settings.PASSWORDLESS_AUTH_PREFIX + 'token/', ObtainAuthTokenFromCallbackToken.as_view(), name='auth_token'),
     path(api_settings.PASSWORDLESS_VERIFY_PREFIX + 'email/', ObtainEmailVerificationCallbackToken.as_view(), name='verify_email'),
     path(api_settings.PASSWORDLESS_VERIFY_PREFIX + 'mobile/', ObtainMobileVerificationCallbackToken.as_view(), name='verify_mobile'),
     path(api_settings.PASSWORDLESS_VERIFY_PREFIX, VerifyAliasFromCallbackToken.as_view(), name='verify_token'),
     path('jwt/refresh/', TokenRefreshView.as_view(), name='token_refresh'),    
]
