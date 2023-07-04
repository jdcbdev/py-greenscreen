from django.urls import path
from . import views

urlpatterns = [
    path('', views.signin, name="login"),
    path('login/', views.signin, name="login"),
    path('logout/', views.signout, name="logout"),
    path('forgot-password/', views.forgot_password, name="admin_forgot_password"),
    path('password-reset/<uidb64>/<token>', views.password_reset, name='admin_password_reset'),
    path('dashboard/', views.admission, name="admission"),
]