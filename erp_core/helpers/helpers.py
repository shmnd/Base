from django.contrib.auth import get_user_model
from django.utils import timezone

def get_object_or_none(classmodel,**kwargs):
    try:
        return classmodel.objects.get(**kwargs)
    except classmodel.DoesNotExist:
        return None
    


def get_token_or_none(request):
    User=get_user_model()
    try:
        instance=User.objects.get(id=request.user.id)
    except Exception:
        instance=None
    finally:
        return instance
    

def update_last_logout(sender,user,**kwargs):
    '''It'a signal reciver which update the last_logout date for the user logging out'''

    user.last_logout=timezone.now()
    user.last_active=timezone.now()
    user.is_logged_in=False
    user.save(update_fields=['last_logout','last_active','is_logged_in'])