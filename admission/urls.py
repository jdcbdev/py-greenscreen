from django.urls import path
from . import views

urlpatterns = [
    path('', views.signin, name="login"),
    path('login/', views.signin, name="login"),
    path('logout/', views.signout, name="logout"),
    path('dashboard/', views.admission, name="admission"),
]