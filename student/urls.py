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
    path('student/complete-profile/', views.complete_profile, name='complete_profile'),
    path('student/my-profile/', views.my_profile, name='my_profile'),
    path('student/complete-profile/personal-information/', views.complete_personal_information, name='complete_personal_information'),
    path('student/complete-profile/college-entrance-test/', views.complete_college_entrance_test, name='complete_college_entrance_test'),
    path('student/complete-profile/school-background/', views.complete_school_background, name='complete_school_background'),
    path('student/complete-profile/economic-status/', views.complete_economic_status, name='complete_economic_status'),
    path('student/complete-profile/personality-test-1/', views.complete_personality_test_1, name='complete_personality_test_1'),
    path('student/complete-profile/personality-test-2/', views.complete_personality_test_2, name='complete_personality_test_2'),
    path('student/complete-profile/personality-test-3/', views.complete_personality_test_3, name='complete_personality_test_3'),
    path('student/complete-profile/personality-test-4/', views.complete_personality_test_4, name='complete_personality_test_4'),
    path('student/complete-profile/complete-study-habit-1/', views.complete_study_habit_1, name='complete_study_habit_1'),
    path('student/complete-profile/complete-study-habit-2/', views.complete_study_habit_2, name='complete_study_habit_2'),
    path('student/complete-profile/complete-study-habit-3/', views.complete_study_habit_3, name='complete_study_habit_3')
]