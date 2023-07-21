from django.urls import path
from . import views
from student import views as student

urlpatterns = [
    path('', views.home, name="home"),
    path('home/', views.home, name="home_home"),
    path('academics/', views.home, name="home_academics"),
    path('how-it-works/', views.home, name="home_admissions"),
    path('faculty/', views.home, name="home_faculty"),
    path('student/complete-profile/select-address/', views.ph_address, name="ph_address"),
    path('data-privacy/', views.view_privacy, name="view_privacy"),
]