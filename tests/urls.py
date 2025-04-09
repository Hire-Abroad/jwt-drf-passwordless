from django.urls import path, include
from rest_framework.urlpatterns import format_suffix_patterns
from jwt_passwordless.settings import api_settings
from jwt_passwordless.views import (ObtainEmailCallbackToken,
                                   ObtainMobileCallbackToken,
                                   ObtainAuthTokenFromCallbackToken,
                                    )

app_name = 'jwt_passwordless'

urlpatterns = [
    path('', include('jwt_passwordless.urls')),
]

format_suffix_patterns(urlpatterns)
