from django.urls import path
from . import views

urlpatterns = [
    path('student/sign-in/', views.signin, name="signin"),
    path('student/sign-up/', views.signup, name="signup"),
    path('student/forgot-password/', views.forgot_password, name="forgotpassword"),
]