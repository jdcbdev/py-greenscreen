from django.urls import path
from . import views

urlpatterns = [
    path('student/signin', views.signin, name="signin"),
]