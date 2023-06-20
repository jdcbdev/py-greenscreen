from django.urls import path
from . import views

urlpatterns = [
    path('student/signin/', views.signin, name="signin"),
    path('student/signup/', views.signup, name="signup"),
    path('student/forgotpassword/', views.forgot_password, name="forgotpassword"),
]