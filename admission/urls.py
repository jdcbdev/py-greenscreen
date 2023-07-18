from django.urls import path
from . import views

urlpatterns = [
    path('', views.signin, name="login"),
    path('sign-in/', views.signin, name="login"),
    path('sign-out/', views.signout, name="logout"),
    path('forgot-password/', views.forgot_password, name="admin_forgot_password"),
    path('password-reset/<uidb64>/<token>', views.password_reset, name='admin_password_reset'),
    path('dashboard/', views.dashboard, name="dashboard"),
    path('settings/', views.view_settings, name="settings"),
    path('settings/add-school-year/', views.add_school_year, name="add_school_year"),
    path('settings/add-admission-period/', views.add_admission_period, name="add_admission_period"),
    path('settings/add-program-quota/', views.add_quota, name="add_quota"),
    path('settings/view-program-quota/', views.view_quota, name="view_quota"),
    path('settings/view-admission-period/', views.view_period, name="view_period"),
    path('settings/add-automation/', views.add_auto, name="add_auto"),
    path('settings/view-program-criteria/', views.view_criteria, name="view_criteria"),
    path('settings/add-program-criteria/', views.add_criteria, name="add_criteria"),
    path('settings/view-program-interview/', views.view_interview_slot, name="view_interview_slot"),
    path('faculty/', views.faculty, name="faculty"),
    path('view-faculty/', views.view_faculty, name="view_faculty"),
    path('add-faculty/', views.add_faculty, name="add_faculty"),
    path('edit-faculty/', views.edit_faculty, name="edit_faculty"),
    path('view-edit-faculty/', views.view_edit_faculty_modal, name="view_edit_faculty_modal"),
    path('view-delete-faculty/', views.view_delete_faculty_modal, name="view_delete_faculty_modal"),
    path('delete-faculty/', views.delete_faculty, name="delete_faculty"),
    path('view-applications/', views.view_application, name="view_application"),
    path('all-applications/', views.all_application, name="all_application"),
    path('pending-applications/', views.pending_application, name="pending_application"),
    path('view-verify-student/', views.view_verify_student_modal, name="view_verify_student_modal"),
    path('accept-application/', views.accept_application, name="accept_application"),
    path('return-application/', views.return_application, name="return_application"),
    path('view-add-interview-slot/', views.view_interview_slot_modal, name="view_interview_slot_modal"),
    path('settings/add-interview-slot/', views.add_interview_slot, name="add_interview_slot"),
    path('interview-applications/', views.interview_application, name="interview_application"),
    path('student-profile/<int:id>', views.view_student_profile, name="view_student_profile"),
    path('view-interview-student/', views.view_rate_interview_modal, name="view_rate_interview_modal"),
    path('rate-student-interview/', views.rate_interview, name="rate_interview"),
    path('ranking-applications/', views.ranking_application, name="ranking_application"),
    path('view-process-applications/', views.view_process_student_modal, name="view_process_student_modal"),
    path('process-student-application/', views.process_application, name="process_application"),
    path('waiting-applications/', views.waiting_application, name="waiting_application"),
    path('view-process-waiting-applications/', views.view_process_waitingstudent_modal, name="view_process_waitingstudent_modal"),
    path('qualified-applications/', views.qualified_application, name="qualified_application"),
    path('view-withdraw-applications/', views.view_withdraw_modal, name="view_withdraw_modal"),
    path('withdraw-student-application/', views.withdraw_application, name="admin_withdraw_application"),
    path('decline-application/', views.decline_application, name="decline_application"),
    path('withdrawn-applications/', views.withdrawn_application, name="withdrawn_application"),
    path('monitoring/', views.monitoring, name="monitoring"),
    path('monitoring/view/', views.view_monitoring, name="view_monitoring"),
    path('monitoring/view/modal', views.view_monitoring_modal, name="view_monitoring_modal"),
    path('monitoring/save-monitoring/', views.save_monitoring, name="save_monitoring"),
]