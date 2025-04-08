# JWT Passwordless

A Django Rest Framework app that uses JWT tokens for passwordless authentication.

## Overview

JWT Passwordless provides a simple way to implement passwordless authentication in your Django application using JSON Web Tokens (JWT). It allows users to authenticate via email or mobile by receiving a time-limited token that can be exchanged for a JWT token.

## Features

- Email and mobile phone authentication
- JWT token-based authentication using django-rest-framework-simplejwt
- Customizable token expiry
- Email and mobile verification
- Multiple authentication types support
- Configurable token generation
- Automatic alias verification tracking

## Installation

```bash
pip install jwt-passwordless
```

Or install from source:

```bash
git clone https://github.com/Hire-Abroad/jwt-drf-passwordless.git
cd jwt-drf-passwordless
pip install -e .
```

## Quick Start

1. Add to your `INSTALLED_APPS` in settings.py:

```python
INSTALLED_APPS = [
    # ...
    'rest_framework',
    'jwt_passwordless',
    # ...
]
```

2. Include the URLs:

```python
urlpatterns = [
    # ...
    path('api/', include('jwt_passwordless.urls', namespace='jwt_passwordless')),
    # ...
]
```

3. Add settings to your settings.py:

```python
PASSWORDLESS_AUTH = {
    # Auth types allowed - EMAIL, MOBILE or both
    'PASSWORDLESS_AUTH_TYPES': ['EMAIL'],
    
    # Token expiry time in seconds
    'PASSWORDLESS_TOKEN_EXPIRE_TIME': 15 * 60,
    
    # Email settings
    'PASSWORDLESS_EMAIL_NOREPLY_ADDRESS': 'noreply@example.com',
    'PASSWORDLESS_EMAIL_SUBJECT': "Your Login Token",
    'PASSWORDLESS_EMAIL_PLAINTEXT_MESSAGE': "Enter this token to sign in: %s",
    
}
```

## Usage

### Email Authentication Flow

1. User requests a token:
   ```
   POST /api/auth/email/
   {"email": "user@example.com"}
   ```

2. System sends a token to the user's email.

3. User exchanges token for JWT:
   ```
   POST /api/auth/token/
   {"email": "user@example.com", "token": "123456"}
   ```

4. User receives JWT tokens:
   ```json
   {
     "access": "eyJ0eXAiOiJKV1QiLCJhbGc...",
     "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc..."
   }
   ```

### Mobile Authentication (Optional)

Similar to email flow but using mobile endpoints:
```
POST /api/auth/mobile/
{"mobile": "+1234567890"}
```

## Customization

The package is highly customizable through settings. See the `settings.py` file for all available options.

## License

MIT License
