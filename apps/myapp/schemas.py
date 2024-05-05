from rest_framework import serializers
from apps.myapp.models import Users

class LoginResponseSchema(serializers.ModelSerializer):
    class Meta:
        model=Users
        fields=[
            'id',
            'email',
            'name',
            'username',
            'is_active',
        ]