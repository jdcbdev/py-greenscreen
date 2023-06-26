from django.urls import path
from . import views

urlpatterns = [
    path('student/sign-in/', views.signin, name="signin"),
    path('student/signup-choose/', views.signup_choose, name="signup-choose"),
    path('student/signup-new/', views.signup_new, name="signup-new"),
    path('student/signup-old/', views.signup_old, name="signup-old"),
    path('student/forgot-password/', views.forgot_password, name="forgotpassword"),
    path('student/sign-out/', views.signout, name="signout"),
    path('student/social/signup/', views.social_signup, name="social_signup"),
    path('student/activate/<uidb64>/<token>', views.activate, name='student_activate'),
    path('student/password-reset/<uidb64>/<token>', views.password_reset, name='password_reset'),
    path('student/complete-profile/personal-information/', views.complete_personal_information, name='complete_personal_information'),
    path('student/complete-profile/college-entrance-test/', views.complete_college_entrance_test, name='complete_college_entrance_test')
]