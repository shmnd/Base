from django.shortcuts import render

# Create your views here.
from typing import Any
from django.shortcuts import render
from rest_framework import status,generics,filters
from erp_core.helpers.helpers import get_object_or_none,update_last_logout
from rest_framework.views import APIView
import sys

from apps.myapp.serializers import (
    CreateOrUpdateUserSerializer,
    LoginSerializer,
    LogoutSerializer,
)

from erp_core.helpers.response import ResponseInfo
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from erp_core.helpers.custom_messages import (
    _success,
    _record_not_found,
    _user_not_found,
    _account_tem_suspended,
    _invalid_credentials
)

from apps.myapp.models import Users,GeneratedAccessToken
from django.contrib import auth
from django.utils import timezone
from apps.myapp.schemas import LoginResponseSchema
from rest_framework_simplejwt.tokens import AccessToken,RefreshToken
from erp_core.middleware.JWTAuthentication import BlacklistedJWTAuthentication
from erp_core.helpers.helpers import get_token_or_none

# Create your views here.



class CreateOrUpdateUseApiView(generics.GenericAPIView):
    def __init__(self, **kwargs):
        self.response_format=ResponseInfo().response
        super(CreateOrUpdateUseApiView,self).__init__(**kwargs)

    serializer_class= CreateOrUpdateUserSerializer
    # permission_classes=(IsAuthenticated,)

    def post(self,request):
        try:
            serializer=self.serializer_class(data=request.data,context={'request':request})

            if  not serializer.is_valid():
                self.response_format['status_code']=status.HTTP_400_BAD_REQUEST
                self.response_format['status']=False
                self.response_format['errors']=serializer.errors
                return Response(self.response_format,status=status.HTTP_400_BAD_REQUEST)
            
            user_instance=get_object_or_none(Users,pk=serializer.validated_data.get('user',None))

            serializer=self.serializer_class(user_instance,data=request.data,context={'request':request})
            
            if not serializer.is_valid():
                self.response_format['status_code']=status.HTTP_400_BAD_REQUEST
                self.response_format['status']=False
                self.response_format['errors']=serializer.errors
                return Response(self.response_format,status=status.HTTP_400_BAD_REQUEST)
            serializer.save()
            
            self.response_format['status_code']=status.HTTP_201_CREATED
            self.response_format['message']= _success
            self.response_format['status']=True
            return Response(self.response_format,status=status.HTTP_201_CREATED)
        except Exception as e:
            # exc_type,exc_obj,exc_tb=sys.exc_info()
            self.response_format['status_code']=status.HTTP_500_INTERNAL_SERVER_ERROR
            self.response_format['status']=False
            self.response_format['message']=str(e)
            return Response(self.response_format,status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # return Response({'error':f'{str(e)},{exc_type},{exc_obj}{exc_tb.tb_lineno}'},self.response_format,status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class LoginApiView(generics.GenericAPIView):
    def __init__(self, **kwargs: Any):
        self.response_format=ResponseInfo().response
        super(LoginApiView,self).__init__(**kwargs)

    serializer_class=LoginSerializer

    def post(self,request):
        
        try:
            serializer=self.serializer_class(data=request.data)

            if not serializer.is_valid():
                self.response_format['status']   = True
                self.response_format['error']    = serializer.errors
                return Response(self.response_format,status=status.HTTP_400_BAD_REQUEST)
            

            user = auth.authenticate(
                username=serializer.validated_data.get("username", ""),
                password=serializer.validated_data.get("password", ""),
            )

            if user:
                if not user.is_active:
                    data={'user':{},'token':'','refresh':''}
                    self.response_format['status_code']    = status.HTTP_406_NOT_ACCEPTABLE
                    self.response_format['status']         = False
                    self.response_format['data']           = data
                    self.response_format['message']        = _account_tem_suspended
                    return Response(self.response_format,status=status.HTTP_200_OK)
                else:
                    user.is_logged_in= True
                    user.last_login=timezone.now()
                    user.save(update_fields=['is_logged_in','last_login'])

                    serializer=LoginResponseSchema(user,context={'request':request})
                    refresh=RefreshToken.for_user(user)
                    token=str(refresh.access_token)
                    data={'user':serializer.data,'token':token,'refresh': str(refresh)}
                    GeneratedAccessToken.objects.create(user=user,token=token)

                    self.response_format['status_code']    = status.HTTP_200_OK
                    self.response_format['status']         = True
                    self.response_format['data']           = data

                    return Response(self.response_format,status=status.HTTP_200_OK)
            else:
                self.response_format['status_code']=status.HTTP_400_BAD_REQUEST
                self.response_format['status']=False
                self.response_format['message']=_invalid_credentials

                return Response(self.response_format,status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as es:
            
            self.response_format['status_code']=status.HTTP_500_INTERNAL_SERVER_ERROR
            self.response_format['status']=False
            self.response_format['message']= str(es)
            return Response(self.response_format,status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class LogoutApiView(generics.GenericAPIView):
    def __init__(self, **kwargs: Any):
        self.response_format=ResponseInfo().response
        super(LogoutApiView,self).__init__(**kwargs)

    serializer_class=LogoutSerializer
    permission_classes=(IsAuthenticated,)
    authentication_classes=[BlacklistedJWTAuthentication]

    def post(self,request):
        try:
            user=get_token_or_none(request)
            if user is not None:
                GeneratedAccessToken.objects.filter(user=user).delete()
                update_last_logout(None,user)

            self.response_format['status'] = True
            self.response_format['status_code'] = status.HTTP_200_OK
            return Response(self.response_format,status=status.HTTP_200_OK)
                
        except Exception as e:
            self.response_format['status']= False
            self.response_format['status_code']=status.HTTP_500_INTERNAL_SERVER_ERROR
            self.response_format['message']=str(e)
            return Response(self.response_format,status=status.HTTP_500_INTERNAL_SERVER_ERROR)