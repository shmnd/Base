# Generated by Django 5.0.4 on 2024-05-04 10:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='users',
            name='id',
            field=models.BigAutoField(primary_key=True, serialize=False),
        ),
    ]