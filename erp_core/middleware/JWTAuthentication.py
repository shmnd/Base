from typing import Tuple
from rest_framework.request import Request
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import Token
from apps.myapp.models import GeneratedAccessToken


class BlacklistedJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        token = super().authenticate(request)

        '''checking the token is blacklisted or not'''
        if token and GeneratedAccessToken.objects.filter(token=str(token[1])).exists():
            return token
        return None