# Generated by Django 5.0.4 on 2024-05-05 11:38

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0005_users_groups_users_user_permissions'),
    ]

    operations = [
        migrations.RenameField(
            model_name='users',
            old_name='is_amdin',
            new_name='is_admin',
        ),
    ]
