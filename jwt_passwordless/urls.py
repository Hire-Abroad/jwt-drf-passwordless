from jwt_passwordless.settings import api_settings
from django.urls import path, include
from jwt_passwordless.views import (
     ObtainEmailCallbackToken,
     ObtainMobileCallbackToken,
     ObtainAuthTokenFromCallbackToken,
)

app_name = 'jwt_passwordless'

urlpatterns = [
     path(api_settings.PASSWORDLESS_AUTH_PREFIX + 'email/', ObtainEmailCallbackToken.as_view(), name='auth_email'),
     path(api_settings.PASSWORDLESS_AUTH_PREFIX + 'mobile/', ObtainMobileCallbackToken.as_view(), name='auth_mobile'),
     path(api_settings.PASSWORDLESS_AUTH_PREFIX + 'token/', ObtainAuthTokenFromCallbackToken.as_view(), name='auth_token') 
]
