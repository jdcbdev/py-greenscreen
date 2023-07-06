from django.urls import path
from . import views

urlpatterns = [
    path('', views.signin, name="login"),
    path('sign-in/', views.signin, name="login"),
    path('sign-out/', views.signout, name="logout"),
    path('forgot-password/', views.forgot_password, name="admin_forgot_password"),
    path('password-reset/<uidb64>/<token>', views.password_reset, name='admin_password_reset'),
    path('dashboard/', views.dashboard, name="dashboard"),
    path('settings/', views.settings, name="settings"),
    path('settings/add-school-year/', views.add_school_year, name="add_school_year"),
    path('settings/add-admission-period/', views.add_admission_period, name="add_admission_period"),
    path('settings/add-program-quota/', views.add_quota, name="add_quota"),
    path('settings/view-program-quota/', views.view_quota, name="view_quota"),
    path('settings/view-admission-period/', views.view_period, name="view_period"),
    path('settings/add-automation/', views.add_auto, name="add_auto"),
    path('settings/view-program-criteria/', views.view_criteria, name="view_criteria"),
    path('settings/add-program-criteria/', views.add_criteria, name="add_criteria"),
    path('faculty/', views.faculty, name="faculty"),
    path('add-faculty/', views.add_faculty, name="add_faculty"),
]