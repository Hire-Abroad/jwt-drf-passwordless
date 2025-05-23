from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.models import BaseUserManager
from django.core.validators import RegexValidator
from django.db import models

phone_regex = RegexValidator(regex=r'^\+[1-9]\d{1,14}$',
                             message="Mobile number must be entered in the format:"
                                     " '+999999999'. Up to 15 digits allowed.")


class CustomUser(AbstractBaseUser):
    email = models.EmailField(max_length=255, unique=True, blank=True, null=True)
    # Added to test the custom email field name
    secondary_email = models.EmailField(max_length=255, unique=True, blank=True, null=True)
    email_verified = models.BooleanField(default=False)

    mobile = models.CharField(validators=[phone_regex], max_length=17, unique=True, blank=True, null=True)
    # Added to test the custom mobile field name
    secondary_mobile = models.CharField(validators=[phone_regex], max_length=17, unique=True, blank=True, null=True)
    mobile_verified = models.BooleanField(default=False)

    objects = BaseUserManager()

    USERNAME_FIELD = 'email'

    class Meta:
        app_label = 'tests'
