# JWT Passwordless

[![PyPI version](https://badge.fury.io/py/jwt-passwordless.svg)](https://pypi.org/project/jwt-passwordless/)


A Django REST Framework package that makes implementing passwordless authentication with JWT tokens simple and secure.

This package is a fork of [django-rest-framework-passwordless](https://github.com/aaronn/django-rest-framework-passwordless) by Aaron Ng, which hasn't been maintained for a couple of years. This fork adds JWT support and several other improvements while maintaining the same core functionality.

### This package is actively maintained by the Hire Abroad tech team and is used in production across Hire Abroad projects.

## Why JWT Passwordless?

Passwordless authentication improves user experience and security by eliminating password management. Users receive a short-lived token via email or SMS, which they can exchange for a JWT token to authenticate in your application.

### Key Differences from Original Repository

This fork introduces several important improvements over the original repository:

1. **JWT Authentication**: Uses `djangorestframework-simplejwt` instead of DRF's TokenAuthentication for more flexible token-based auth with no server-side storage requirements
2. **Configurable Token Length**: Token length can be customized (3-6 digits) through settings
3. **Improved Test Coverage**: More comprehensive testing for better reliability
4. **Fixed Custom Field Bug**: The original repository had a bug where custom email field names worked only in signals but not in other parts of the code (it used hardcoded "email" field in many places). This fork ensures that custom field names work consistently throughout the codebase

### Key Benefits

- 🔒 **Enhanced Security**: No passwords to be hacked, phished, or forgotten
- 🌐 **Better User Experience**: Frictionless sign-in experience without password frustrations
- 🔄 **Seamless JWT Integration**: Works with Django REST Framework's JWT authentication
- 📱 **Multiple Channels**: Support for both email and mobile authentication
- ✅ **Verification Tracking**: Built-in support for tracking verified emails/phones


## Installation

### From PyPI

```bash
pip install jwt-passwordless
```

### From Source

```bash
git clone https://github.com/Hire-Abroad/jwt-drf-passwordless.git
cd jwt-drf-passwordless
pip install -e .
```

> **Note**: If you're familiar with the original `drfpasswordless` package, note that this package uses different import names (`jwt_passwordless` instead of `drfpasswordless`)

## Quick Start

### 1. Add to INSTALLED_APPS in settings.py

```python
INSTALLED_APPS = [
    # ...
    'rest_framework',
    'rest_framework_simplejwt',  # Required for JWT functionality
    'jwt_passwordless',
    # ...
]
```

### 2. Include the URLs in your project

```python
from django.urls import path, include

urlpatterns = [
    # ...
    path('api/', include('jwt_passwordless.urls', namespace='jwt_passwordless')),
    # ...
]
```

### 3. Configure Settings in settings.py

```python
PASSWORDLESS_AUTH = {
    # Authentication types - 'EMAIL', 'MOBILE', or both
    'PASSWORDLESS_AUTH_TYPES': ['EMAIL'],
    
    # Token expiry time in seconds (default: 15 minutes)
    'PASSWORDLESS_TOKEN_EXPIRE_TIME': 15 * 60,
    
    # Email settings
    'PASSWORDLESS_EMAIL_NOREPLY_ADDRESS': 'noreply@example.com',
    'PASSWORDLESS_EMAIL_SUBJECT': "Your Login Token",
    'PASSWORDLESS_EMAIL_PLAINTEXT_MESSAGE': "Enter this token to sign in: %s",
    
    # Optional: customize token length (3-6 digits)
    'PASSWORDLESS_TOKEN_LENGTH': 6,
    
    # Optional: Mark email as verified after successful authentication
    'PASSWORDLESS_USER_MARK_EMAIL_VERIFIED': True,
    'PASSWORDLESS_USER_EMAIL_VERIFIED_FIELD_NAME': 'email_verified',
    
    # Optional: For SMS authentication
    # 'PASSWORDLESS_AUTH_TYPES': ['EMAIL', 'MOBILE'],
    # 'PASSWORDLESS_MOBILE_NOREPLY_NUMBER': '+15551234567',
    # 'PASSWORDLESS_MOBILE_MESSAGE': "Your login code is: %s",
}

# Configure djangorestframework-simplejwt (optional but recommended)
from datetime import timedelta
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    # ... other JWT settings
}

# Required if using mobile authentication with Twilio
# import os
# os.environ['TWILIO_ACCOUNT_SID'] = 'your-account-sid'
# os.environ['TWILIO_AUTH_TOKEN'] = 'your-auth-token'
```

## Usage

### Email Authentication Flow

1. **Request a token**:
   ```http
   POST /api/auth/email/
   {"email": "user@example.com"}
   ```

2. **System sends a token to the user's email**

3. **Exchange token for JWT**:
   ```http
   POST /api/auth/token/
   {"email": "user@example.com", "token": "123456"}
   ```

4. **Receive JWT tokens**:
   ```json
   {
     "access": "eyJ0eXAiOiJKV1QiLCJhbGc...",
     "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc..."
   }
   ```

5. **Use the JWT token for authentication**:
   ```http
   GET /api/some-protected-endpoint/
   Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
   ```

### Mobile Authentication Flow

Similar to email flow but using mobile endpoints:

1. **Request a token**:
   ```http
   POST /api/auth/mobile/
   {"mobile": "+15551234567"}
   ```

2. **System sends a token to the user's mobile number**

3. **Exchange token for JWT**:
   ```http
   POST /api/auth/token/
   {"mobile": "+15551234567", "token": "123456"}
   ```

## Advanced Configuration



### Custom Field Names

You can customize the field names used for email and mobile authentication:

```python
PASSWORDLESS_AUTH = {
    # ...
    'PASSWORDLESS_USER_EMAIL_FIELD_NAME': 'email',  # Default is 'email'
    'PASSWORDLESS_USER_MOBILE_FIELD_NAME': 'phone',  # If your field is named 'phone' instead of 'mobile'
    # ...
}
```

### Custom Callbacks

You can customize how tokens are sent by providing your own callback functions:

```python
PASSWORDLESS_AUTH = {
    # ...
    'PASSWORDLESS_EMAIL_CALLBACK': 'myapp.utils.send_custom_email_with_callback_token',
    'PASSWORDLESS_SMS_CALLBACK': 'myapp.utils.send_custom_sms_with_callback_token',
    # ...
}
```

### Customizing Token Creation

You can customize how JWT tokens are created and serialized:

```python
PASSWORDLESS_AUTH = {
    # ...
    'PASSWORDLESS_AUTH_TOKEN_CREATOR': 'myapp.utils.create_custom_jwt_token_for_user',
    'PASSWORDLESS_AUTH_TOKEN_SERIALIZER': 'myapp.serializers.CustomJWTTokenResponseSerializer',
    # ...
}
```


## Security Considerations

- **Token Expiration**: Tokens are designed to expire quickly (default: 15 minutes)
- **Token Invalidation**: Creating a new token invalidates previous tokens
- **Verified Status**: Email/mobile verified status is tracked and updated

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request


## Contact

Hire Abroad - contact@hireabroad.com

Project Link: [https://github.com/Hire-Abroad/jwt-passwordless](https://github.com/Hire-Abroad/jwt-passwordless)  
Original Project: [https://github.com/aaronn/django-rest-framework-passwordless](https://github.com/aaronn/django-rest-framework-passwordless)

---

Made by [Hire Abroad tech team](https://github.com/Hire-Abroad)  
Original package by [Aaron Ng](https://github.com/aaronn)