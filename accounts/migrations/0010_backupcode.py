# Generated by Django 5.0.2 on 2025-06-13 12:31

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0009_customuser_two_factor_enabled'),
    ]

    operations = [
        migrations.CreateModel(
            name='BackupCode',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code', models.CharField(max_length=10)),
                ('used', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('used_at', models.DateTimeField(blank=True, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='backup_codes', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Backup Code',
                'verbose_name_plural': 'Backup Codes',
            },
        ),
    ]
