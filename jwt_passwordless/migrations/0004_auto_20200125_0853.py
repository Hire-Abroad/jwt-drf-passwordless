# Generated by Django 3.0.2 on 2020-01-25 08:53

from django.db import migrations, models
import jwt_passwordless.models


class Migration(migrations.Migration):

    dependencies = [
        ('jwt_passwordless', '0003_callbacktoken_type'),
    ]

    operations = [
        migrations.AlterField(
            model_name='callbacktoken',
            name='key',
            field=models.CharField(default=jwt_passwordless.models.generate_numeric_token, max_length=6),
        ),
        migrations.AlterUniqueTogether(
            name='callbacktoken',
            unique_together={('is_active', 'key', 'type')},
        ),
    ]
