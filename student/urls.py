from django.urls import path
from . import views

urlpatterns = [
    path('sign-in/', views.signin, name="signin"),
    path('signup-choose/', views.signup_choose, name="signup-choose"),
    path('signup-new/', views.signup_new, name="signup-new"),
    path('signup-old/', views.signup_old, name="signup-old"),
    path('forgot-password/', views.forgot_password, name="forgotpassword"),
    path('sign-out/', views.signout, name="signout"),
    path('social/signup/', views.social_signup, name="social_signup"),
    path('activate/<uidb64>/<token>', views.activate, name='student_activate'),
    path('password-reset/<uidb64>/<token>', views.password_reset, name='password_reset'),
    path('complete-profile/', views.complete_profile, name='complete_profile'),
    path('my-profile/', views.my_profile, name='my_profile'),
    path('complete-profile/personal-information/', views.complete_personal_information, name='complete_personal_information'),
    path('complete-profile/college-entrance-test/', views.complete_college_entrance_test, name='complete_college_entrance_test'),
    path('complete-profile/school-background/', views.complete_school_background, name='complete_school_background'),
    path('complete-profile/economic-status/', views.complete_economic_status, name='complete_economic_status'),
    path('complete-profile/personality-test-1/', views.complete_personality_test_1, name='complete_personality_test_1'),
    path('complete-profile/personality-test-2/', views.complete_personality_test_2, name='complete_personality_test_2'),
    path('complete-profile/personality-test-3/', views.complete_personality_test_3, name='complete_personality_test_3'),
    path('complete-profile/personality-test-4/', views.complete_personality_test_4, name='complete_personality_test_4'),
    path('complete-profile/complete-study-habit-1/', views.complete_study_habit_1, name='complete_study_habit_1'),
    path('complete-profile/complete-study-habit-2/', views.complete_study_habit_2, name='complete_study_habit_2'),
    path('complete-profile/complete-study-habit-3/', views.complete_study_habit_3, name='complete_study_habit_3')
]