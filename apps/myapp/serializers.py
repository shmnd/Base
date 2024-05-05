from rest_framework import serializers
from apps.myapp.models import Users
from django.contrib.auth.models import User
from erp_core.helpers.helpers import get_object_or_none
import re
from django.contrib.auth.hashers import make_password
from rest_framework_simplejwt.tokens import RefreshToken,TokenError



class NullableDateField(serializers.DateField):
    def to_internal_value(self, data):
        if data == '':
            return None
        else:
            return super().to_internal_value(data)
    


class CreateOrUpdateUserSerializer(serializers.ModelSerializer):
    user        = serializers.IntegerField(allow_null=True,required=False)
    username    = serializers.CharField(required=False)
    email       = serializers.EmailField(required=False,allow_null=True,allow_blank=True)
    password    = serializers.CharField(write_only=True)

    # is_admin=serializers.BooleanField(default=False)
    # is_staff=serializers.BooleanField(default=False)
    # groups=serializers.PrimaryKeyRelatedField(read_only=True,many=True,required=True)  #,queryset=Group.object.all()


    class Meta:
        model=Users
        fields=['user','username','email','password']


    def validate(self, attrs):
        email             = attrs.get('email','')
        user              = attrs.get('user',None)
        username          = attrs.get('username',None)
        password          = attrs.get('password',None)

        user_query_set    = Users.objects.filter(email=email)
        user_object       = Users.objects.filter(username=username)

        if username is not None:
            if not re.match("^[a-zA-Z0-9._@]*$",username):
                raise serializers.ValidationError({'username':('Please enter a valid username,No numbers and special characters are allowed')})

        if user is not None:
            user_instance   = get_object_or_none(Users,pk=user)
            user_query_set  = user_query_set.exclude(pk=user_instance.pk)
            user_object     = user_object.exclude(pk=user_instance.pk)

        if user_object.exists():
            raise serializers.ValidationError({'username':('Username already exist')})
        
        if user_query_set.exists():
            raise serializers.ValidationError({'email':('Email already exist')})
        
        if password is not None and (len(password)<8 or not any(char.isupper() for char in password) or not any(char.islower() for char in password) or not any(char.isdigit() for char in password) or not any(char in '!@#$%^&*()_+-=[]{}|;:,.<>?\'\"\\/~`' for char in password)):
            raise serializers.ValidationError({'password':("Password must have 8 character and must contain one Uppercase,Lowercase,Special character and Number")})
        
        return super().validate(attrs)
    

    def create(self, validated_data):
        password = validated_data.get('password')

        instance=Users()
        instance.username=validated_data.get('username')
        instance.email=validated_data.get('email')
        instance.set_password(password)
        instance.is_active  = validated_data.get('is_active',True)
        instance.is_amdin=validated_data.get("is_admin")
        # instance._staff=True
        # instance.is_password_reset_required   = True
        instance.save()
        # groups=validated_data.pop('groups')

        # for group_instance in groups:
        #     if group_instance is not None:
        #         group_instance.user_set.add(instance)
        return instance

    



    # def update(self, instance, validated_data):
    #     return super().update(instance, validated_data)




class LoginSerializer(serializers.ModelSerializer):
    username=serializers.CharField()
    password=serializers.CharField()

    class Meta:
        model=Users
        fields=['username','password']


class LogoutSerializer(serializers.ModelSerializer):
    refresh=serializers.CharField()

    default_error_messages={
        'bad_token':('Token is expired or Invalid')
    }

    def validate(self, attrs):
        self.token=attrs['refresh']
        return attrs
    
    def save(self,**kwargs):
        try:
            RefreshToken(self.token).blacklist()

        except TokenError:
            self.fail('bad_token')