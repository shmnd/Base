from django.db import models

# Create your models here.
from typing import Any
from django.db import models

from django.contrib.auth.models import AbstractBaseUser,BaseUserManager,PermissionsMixin

from django.utils.translation import gettext_lazy as _


# Create your models here.


class AbstractDateFieldMix(models.Model):
    created_date=models.DateTimeField(_('Created_dates'),auto_now_add=True,editable=False,null=True,blank=True)
    updated_date=models.DateTimeField(_('updated_date'),auto_now=True,null=True,blank=True,editable=False)

    class Meta:
        abstract = True

class UserManager(BaseUserManager):
    def create_user(self,username,password=None,**extra_fields):
        if not username:
            raise ValueError(_('Username must be set'))
        
        user=self.model(username=username,**extra_fields)
        if password:
            user.set_password(password.strip())
        user.save()
        return user
    

    def create_superuser(self,username,password,**extra_fields):
        extra_fields.setdefault('is_superuser',True)
        extra_fields.setdefault('is_active',True)
        extra_fields.setdefault('is_staff',True)
        extra_fields.setdefault('is_verified',True)
        # extra_fields.setdefault('is_admin',True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('super user must have is_staff=True'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('super user must have is_superuser=True'))
        
        return self.create_user(username,password,**extra_fields)
    


class Users(AbstractBaseUser,AbstractDateFieldMix,PermissionsMixin):
    id                           = models.BigAutoField(primary_key=True)

    email                         = models.EmailField(_('Email'),unique=True,max_length=225,blank=True,null=True)

    name                          = models.CharField(_('Name'),unique=False,max_length=225,blank=True,null=True)
    username                      = models.CharField(_('Username'),unique=True,max_length=225,blank=True,null=True)
    password                      = models.CharField(_('Password'),max_length=225,blank=True,null=True)

    date_joined                   = models.DateTimeField(_('Date_joined'),auto_now_add=True,null=True,blank=True)
    last_login                    = models.DateTimeField(_('Last_login'),null=True,blank=True)
    last_logout                   = models.DateTimeField(_('Last_logout'),null=True,blank=True)
    last_active                   = models.DateTimeField(_('Last_active'),null=True,blank=True)
    # last_password_reset           = models.DateField(_('Last_password_reset'),null=True,blank=True)

    is_verified                   = models.BooleanField(default=False)
    is_admin                      = models.BooleanField(default=False)
    is_staff                      = models.BooleanField(default=False)
    is_superuser                  = models.BooleanField(default=False)
    is_logged_in                  = models.BooleanField(default=False)
    # is_password_reset_required    = models.BooleanField(default=False)
    is_active                     = models.BooleanField(_('Is_active'),default=True)

    # failed_login_attempts         = models.IntegerField(_('Failed_login_attempts'),blank=True,null=True)

    USERNAME_FIELD    = 'username'

    REQUIRED_FIELDS   = ['email']

    objects=UserManager()

    class Meta:
        verbose_name='user'
        verbose_name_plural='users'
    
    def __str__(self):
        return "{username}".format(username=self.username)
    

class GeneratedAccessToken(AbstractDateFieldMix):
    token= models.TextField()
    user=models.ForeignKey(Users, on_delete=models.CASCADE, null=True,blank=True)

    def __str__(self):
        return self.token
    


    class Group:
        pass