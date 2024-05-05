from django.urls import path
from . import views


urlpatterns = [
    path('register/', views.CreateOrUpdateUseApiView.as_view()),
    path('login/',views.LoginApiView.as_view()),
    path('logout/',views.LogoutApiView.as_view()),
]