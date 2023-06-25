from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name="home"),
    path('student/complete-profile/select-address/', views.ph_address, name="ph_address"),
]