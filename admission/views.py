from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.conf import settings
from django.contrib.auth import get_user_model
from base.custom_apis import load_settings
from django.contrib.auth import authenticate, login, logout
from django.db import transaction
from student.forms import SignInForm, ForgotPasswordForm, SetPasswordForm
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from student.tokens import reset_password_token
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.contrib import messages
from django.utils.safestring import mark_safe
from django.db.models.query_utils import Q
from django.urls import reverse
from student.views import grecaptcha_verify
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_POST
from .models import SchoolYear, AdmissionPeriod, Program, Quota, AutoAdmission, Criteria, Department, AcademicRank, AdmissionRole, Faculty, InterviewSlot
from .forms import SchoolYearForm, AdmissionPeriodForm, QuotaForm, CriteriaForm, AddFacultyForm, ReturnApplicationForm, InterviewSlotForm, RateInterviewForm, ProcessApplicationForm, MonitoringForm, UpdateUserProfileForm
from django.http import JsonResponse
from django.db.models import Prefetch
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils.crypto import get_random_string
from .tasks import send_faculty_email_task
from django.shortcuts import get_object_or_404
from student.models import AdmissionApplication, CollegeEntranceTest, SchoolBackground, ContactPoint, Student, ApplicationStatusLogs, InterviewLogs, PersonalAddress, EconomicStatus, PersonalityTest, StudyHabit, CCGrade
from django.db.models import Exists, OuterRef
from django.utils import timezone
from datetime import datetime
import datetime
from base.models import SHSStrand, ClassRoomOrganization, StudentSupremeGovernment, ClassRank, AcademicAwards, AcademicDegree, EmploymentStatus
from decimal import Decimal
from student.forms import WithdrawApplicationForm
from student.views import student_send_email
import pickle

# Create your views here.

load_settings()

User = get_user_model()

def signin(request):
    
    if request.user.is_authenticated:
        return redirect('home')
        
    page_title = "Sign in"
    success_message = None
    
    if request.method == 'POST':
        form = SignInForm(request.POST)
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = authenticate(request, username=email, password=password)
            
            if user is not None and user.is_active and user.is_staff:
                login(request, user)
                return redirect('dashboard')
            else:
                success_message = {
                    'level': 'danger',
                    'message': 'Invalid email or password.'
                }
    else:
        form = SignInForm()
    
    context = {
        'page_title': page_title,
        'form': form,
        'success_message': success_message,
    }
    return render(request, 'admission/login.html', context)

def signout(request):
    request.session.flush()
    logout(request)
    return redirect('login')

def forgot_password(request, reset=None):
    if request.user.is_authenticated:
        return redirect('home')
    
    page_title = "Forgot Password"
    reset = True
    success_message = None
    
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            
            response=grecaptcha_verify(request)
            if response['success']:
        
                user_email = form.cleaned_data['email']
                associated_user = get_user_model().objects.filter(Q(email=user_email, is_staff=True)).first()
                if associated_user:
                    if associated_user.is_active:
                        mail_subject = "Password Reset Request - GreenScreen Admission System"
                        domain = get_current_site(request).domain
                        uid = urlsafe_base64_encode(force_bytes(associated_user.pk))
                        token = reset_password_token.make_token(associated_user)
                        protocol = 'https' if request.is_secure() else 'http'

                        html_message  = mark_safe(render_to_string("email_admin_forgot_password.html", {
                            'user': associated_user.first_name,
                            'domain': domain,
                            'uid': uid,
                            'token': token,
                            "protocol": protocol
                        }))
                        
                        from_email = settings.DEFAULT_FROM_EMAIL
                        email = EmailMessage(mail_subject, html_message, from_email, to=[user_email])
                        email.content_subtype = 'html'
                        
                        if email.send():
                            msg = mark_safe(f'<b>Password reset sent!</b> We have emailed you instructions for setting your password.')
                            success_message = {
                                'level': 'success',
                                'message': msg
                            }
                            form = ForgotPasswordForm()
                        else:
                            success_message = {
                                'level': 'danger',
                                'message': mark_safe('Problem sending reset password email, <b>SERVER PROBLEM</b>')
                            }
                            
                    else:
                        success_message = {
                            'level': 'danger',
                            'message': 'Account associated with this email is not yet verified.'
                        }
                            
                else:
                    success_message = {
                        'level': 'danger',
                        'message': 'Email not found. Please make sure you have entered the email address for faculty or admission officer.'
                    }
            else:
                success_message = {
                        'level': 'danger',
                        'message': 'Invalid reCAPTCHA. Please try again.'
                    }
                
        else:
            form = ForgotPasswordForm()
    else:
        form = ForgotPasswordForm()

    context = {
        'page_title': page_title,
        'form': form,
        'reset': reset,
        'success_message': success_message,
        'settings': settings
    }

    return render(request, 'admission/forgot_password.html', context)

def password_reset(request, uidb64, token):
    if request.user.is_authenticated:
        return redirect('home')
    
    page_title = "Password Reset"
    success_message = None
    
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except:
        user = None

    if not user:
        return redirect('login')
    
    form = SetPasswordForm()
    
    if user is not None and reset_password_token.check_token(user, token):
        if request.method == 'POST':
            form = SetPasswordForm(request.POST)
            if form.is_valid():
                response=grecaptcha_verify(request)
                
                if response['success']:
                    try:
                        password = form.cleaned_data['password']
                        user.set_password(password)
                        user.save()
                        
                        form = SetPasswordForm()  # clear form
                        
                        success_message = {
                            'level': 'success',
                            'message': mark_safe('Your password has been set. You may go ahead and <a class="green" href="{}">Sign in</a> now.'.format(reverse('login')))
                        }

                    except Exception as e:
                        success_message = {
                            'level': 'danger',
                            'message': str(e)
                        }
                else:
                    success_message = {
                        'level': 'danger',
                        'message': 'Invalid reCAPTCHA. Please try again.'
                    }

        else:
            form = SetPasswordForm()
            
    else:
        success_message = {
            'level': 'danger',
            'message': mark_safe('Link has expired. Try requesting it again.')
        }

    context = {
        'page_title': page_title,
        'form': form,
        'success_message': success_message,
        'settings': settings
    }

    return render(request, 'admission/password_reset_confirm.html', context)

@login_required(login_url='/admin/sign-in/')
def dashboard(request):
    
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    page_title = 'Dashboard'
    page_active = 'dashboard'
    
    context = {
        'page_title': page_title,
        'page_active': page_active
    }
    
    return render(request, 'admission/dashboard.html', context)

@login_required(login_url='/admin/sign-in/')
def view_settings(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    page_title = 'Settings'
    page_active = 'settings'
    current_year = datetime.datetime.now().year
    
    sy = SchoolYear.objects.filter(is_active=True).first()
    autos = Program.objects.filter(is_active=True).prefetch_related(
        Prefetch(
            'autoadmission_set',
            queryset=AutoAdmission.objects.select_related('school_year').filter(school_year=sy),
            to_attr='autoadmissions'
        )
    )
    
    faculty_user = Faculty.objects.filter(user=request.user).first()
    
    context = {
        'page_title': page_title,
        'page_active': page_active,
        'sy': sy,
        'autos': autos,
        'current_year': current_year,
        'faculty_user': faculty_user,
    }
    
    return render(request, 'admission/settings.html', context)

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def add_school_year(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    form = SchoolYearForm(request.POST)
    if form.is_valid():
        # Create or update the new school year
        
        sy, _ = SchoolYear.objects.get_or_create(start_year=form.cleaned_data['start_year'])
        sy.start_year = form.cleaned_data['start_year']
        sy.end_year = form.cleaned_data['end_year']
        sy.concat_year = str(sy.start_year) + ' - ' + str(sy.end_year)
        sy.is_active = True
        sy.save()
        # Deactivate the previous school year
        old_sy = SchoolYear.objects.exclude(start_year=form.cleaned_data['start_year'])
        if old_sy:
            old_sy.update(is_active=False)
        
    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def add_admission_period(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    form = AdmissionPeriodForm(request.POST)
    if form.is_valid():
        # Create or update
        sy = SchoolYear.objects.filter(is_active=True).first()
        program = Program.objects.filter(is_active=True)
        if program:
            for prog in program:
                period, _ = AdmissionPeriod.objects.get_or_create(school_year=sy, program=prog)
        
                start_date = form.cleaned_data['start_date']
                end_date = form.cleaned_data['end_date']
                period.start_date = start_date
                period.end_date = end_date
                period.concat_date = start_date.strftime("%b. %d") + ' - ' + end_date.strftime("%b. %d")
                period.is_active = True
                period.save()  
                
                # Deactivate
                AdmissionPeriod.objects.exclude(school_year=sy).update(is_active=False)
        
    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def add_quota(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    form = QuotaForm(request.POST)
    if form.is_valid():
        # Create or update
        sy = SchoolYear.objects.filter(is_active=True).first()
        program = Program.objects.filter(code=form.cleaned_data['program_code']).first()
        quota, _ = Quota.objects.get_or_create(school_year=sy, program=program)
        quota.school_year = sy
        quota.program = program
        quota.number = form.cleaned_data['number']
        quota.save()  
        
    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
def view_quota(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    sy = SchoolYear.objects.filter(is_active=True).first()
    faculty_user = Faculty.objects.filter(user=request.user).first()
    programs = Program.objects.filter(is_active=True).prefetch_related(
        Prefetch(
            'quota_set',
            queryset=Quota.objects.select_related('school_year').filter(school_year=sy),
            to_attr='quotas'
        )
    )
    context = {
        'programs': programs,
        'faculty_user': faculty_user,
    }
    
    rendered_html = render(request, 'admission/partials/view_quota.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
def view_period(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    sy = SchoolYear.objects.filter(is_active=True).first()
    period = AdmissionPeriod.objects.filter(school_year=sy).first()
    faculty_user = Faculty.objects.filter(user=request.user).first()
    if period.start_date:
        period_start_date = period.start_date
        formatted_date = period_start_date.strftime('%Y-%m-%d')
        period.start_date = formatted_date
    if period.end_date:
        period_end_date = period.end_date
        formatted_date = period_end_date.strftime('%Y-%m-%d')
        period.end_date = formatted_date
    context = {
        'period': period,
        'faculty_user': faculty_user,
    }
    
    rendered_html = render(request, 'admission/partials/view_period.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def add_auto(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    # Create or update
    sy = SchoolYear.objects.filter(is_active=True).first()
    program = Program.objects.filter(code=request.POST.get('program_code')).first()
    auto, _ = AutoAdmission.objects.get_or_create(school_year=sy, program=program)
    auto.school_year = sy
    auto.program = program
    if request.POST.get('automate'):
        auto.automate = True
    else:
        auto.automate = False
    auto.save()  
    
    response = {
            'status': 'success',
            'message': 'Auto admission information saved.'
    }
    return JsonResponse(response)

@ensure_csrf_cookie
@require_POST
def view_criteria(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    sy = SchoolYear.objects.filter(is_active=True).first()
    criteria = Program.objects.filter(is_active=True).prefetch_related(
        Prefetch(
            'criteria_set',
            queryset=Criteria.objects.select_related('school_year').filter(school_year=sy),
            to_attr='criterias'
        )
    )
    
    faculty_user = Faculty.objects.filter(user=request.user).first()
    
    context = {
        'criteria': criteria,
        'faculty_user': faculty_user,
    }
    
    rendered_html = render(request, 'admission/partials/view_criteria.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def add_criteria(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    form = CriteriaForm(request.POST)
    
    if form.is_valid():
        criteria = Criteria.objects.get(pk=form.cleaned_data['criteria_id'])
        criteria.score = form.cleaned_data['score']
        criteria.weight = form.cleaned_data['weights']
        criteria.save()  
        
    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@login_required(login_url='/admin/sign-in/')
def faculty(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    page_title = 'Faculty'
    page_active = 'faculty'
    current_year = datetime.datetime.now().year
    
    departments = Program.objects.filter(is_active=True).order_by('code')
    roles = AdmissionRole.objects.all()
    ranks = AcademicRank.objects.all()
    
    faculty_user = Faculty.objects.filter(user=request.user).first()

    context = {
        'page_title': page_title,
        'page_active': page_active,
        'current_year': current_year,
        'departments': departments,
        'roles': roles,
        'ranks': ranks,
        'faculty_user': faculty_user,
    }
    
    return render(request, 'admission/faculty.html', context)

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
def view_faculty(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    faculties = Faculty.objects.all().order_by('last_name', 'first_name')
    departments = Program.objects.filter(is_active=True).order_by('code')
    roles = AdmissionRole.objects.all()
    ranks = AcademicRank.objects.all()
    
    faculty_user = Faculty.objects.filter(user=request.user).first()

    context = {
        'faculties': faculties,
        'departments': departments,
        'roles': roles,
        'ranks': ranks,
        'faculty_user': faculty_user,
    }
    
    rendered_html = render(request, 'admission/partials/view_faculty.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

def generate_strong_password():
    password = get_random_string(length=8)  # Generates a random string of length 12
    try:
        validate_password(password)  # Validate the generated password
    except ValidationError as e:
        # If the generated password does not meet the password requirements, generate a new one
        return generate_strong_password()
    return password

@login_required(login_url='/admin/sign-in/')
def send_faculty_email(first_name, to_email, password, domain, protocol):
    
    mail_subject = "New Faculty Account - GreenScreen Admission System"

    html_message  = mark_safe(render_to_string("email_add_faculty.html", {
        'user': first_name,
        'domain': domain,
        'email': to_email,
        'password': password,
        "protocol": protocol
    }))
    
    from_email = settings.DEFAULT_FROM_EMAIL
    email = EmailMessage(mail_subject, html_message, from_email, to=[to_email])
    email.content_subtype = 'html'
    email.send()

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def add_faculty(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    form = AddFacultyForm(request.POST)
    if form.is_valid():
        email = form.cleaned_data['email']
        user, _ = get_user_model().objects.get_or_create(email=email)
        password = generate_strong_password()
        user.email = form.cleaned_data['email']
        user.first_name = form.cleaned_data['first_name']
        user.last_name = form.cleaned_data['last_name']
        user.is_active = True
        user.is_staff = True
        user.set_password(password)
        faculty = form.save(commit=False)
        user.save()
        faculty.user = user
        faculty.save()
        
        domain = get_current_site(request).domain
        protocol = 'https' if request.is_secure() else 'http'
        
        send_faculty_email(user.first_name, email, password, domain, protocol)
        
    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
def view_edit_faculty_modal(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    faculty = Faculty.objects.get(pk=request.POST.get('faculty_id'))
    departments = Program.objects.filter(is_active=True).order_by('code')
    roles = AdmissionRole.objects.all()
    ranks = AcademicRank.objects.all()
    
    faculty_user = Faculty.objects.filter(user=request.user).first()

    context = {
        'faculty': faculty,
        'departments': departments,
        'roles': roles,
        'ranks': ranks,
        'faculty_user': faculty_user,
    }
    
    rendered_html = render(request, 'admission/partials/edit_faculty.modal.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def edit_faculty(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    pk=request.POST.get('faculty_id')
    faculty = Faculty.objects.get(pk=pk)
    form = AddFacultyForm(request.POST, instance=faculty)
    if form.is_valid():
        user = faculty.user
        user.email = form.cleaned_data['email']
        user.first_name = form.cleaned_data['first_name']
        user.last_name = form.cleaned_data['last_name']
        user.is_active = True
        user.is_staff = True
        faculty = form.save(commit=False)
        user.save()
        faculty.user = user
        faculty.save()
        
    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
def view_delete_faculty_modal(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    faculty = Faculty.objects.get(pk=request.POST.get('faculty_id'))

    context = {
        'faculty': faculty,
    }
    
    rendered_html = render(request, 'admission/partials/delete_faculty.modal.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def delete_faculty(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    if request.method == 'POST':
        pk=request.POST.get('faculty_id')
        faculty = Faculty.objects.get(pk=pk)
        if faculty:
            user = faculty.user
            faculty.delete()
            user.delete()
        
        return JsonResponse({'message': 'Object deleted successfully'})
    
    return JsonResponse({'error': 'Invalid request method'}, status=400)

@login_required(login_url='/admin/sign-in/')
def view_application(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    page_title = 'Applications'
    page_active = 'applications'
    current_year = datetime.datetime.now().year

    school_year = SchoolYear.objects.filter(is_active=True).first()
    faculty_user = Faculty.objects.filter(user=request.user).first()
    
    if request.user.is_superuser:
        pending_counter = AdmissionApplication.objects.filter(school_year=school_year, status='pending').count()
        interview_counter = AdmissionApplication.objects.filter(school_year=school_year, status='verified').count()
        ranking_counter = AdmissionApplication.objects.filter(school_year=school_year, status='interviewed').count()
        waiting_counter = AdmissionApplication.objects.filter(school_year=school_year, status='waiting-list').count()
        qualified_counter = AdmissionApplication.objects.filter(school_year=school_year, status='approved').count()
        withdrawn_counter = AdmissionApplication.objects.filter(school_year=school_year, status='withdrawn').count()
    else:
        pending_counter = AdmissionApplication.objects.filter(school_year=school_year, status='pending', program=faculty_user.department).count()
        interview_counter = AdmissionApplication.objects.filter(school_year=school_year, status='verified', program=faculty_user.department).count()
        ranking_counter = AdmissionApplication.objects.filter(school_year=school_year, status='interviewed', program=faculty_user.department).count()
        waiting_counter = AdmissionApplication.objects.filter(school_year=school_year, status='waiting-list', program=faculty_user.department).count()
        qualified_counter = AdmissionApplication.objects.filter(school_year=school_year, status='approved', program=faculty_user.department).count()
        withdrawn_counter = AdmissionApplication.objects.filter(school_year=school_year, status='withdrawn', program=faculty_user.department).count()  

    context = {
        'page_title': page_title,
        'page_active': page_active,
        'current_year': current_year,
        'pending_counter': pending_counter,
        'interview_counter': interview_counter,
        'ranking_counter': ranking_counter,
        'waiting_counter': waiting_counter,
        'qualified_counter': qualified_counter,
        'withdrawn_counter': withdrawn_counter,
        'faculty_user': faculty_user,
    }
    
    return render(request, 'admission/application.html', context)

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
def pending_application(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    school_year = SchoolYear.objects.filter(is_active=True).first()
    faculty_user = Faculty.objects.filter(user=request.user).first()
    
    if request.user.is_superuser:
        pending_counter = AdmissionApplication.objects.filter(school_year=school_year, status='pending').count()
        interview_counter = AdmissionApplication.objects.filter(school_year=school_year, status='verified').count()
        ranking_counter = AdmissionApplication.objects.filter(school_year=school_year, status='interviewed').count()
        waiting_counter = AdmissionApplication.objects.filter(school_year=school_year, status='waiting-list').count()
        qualified_counter = AdmissionApplication.objects.filter(school_year=school_year, status='approved').count()
        withdrawn_counter = AdmissionApplication.objects.filter(school_year=school_year, status='withdrawn').count()
        programs = Program.objects.filter(is_active=True)
        students = (
            Student.objects
            .annotate(has_admission_application=Exists(
                AdmissionApplication.objects
                .filter(student=OuterRef('pk'), status='pending', school_year=school_year)
            ))
            .filter(has_admission_application=True)
            .prefetch_related(
                Prefetch(
                    'admissionapplication_set',
                    queryset=AdmissionApplication.objects.select_related('student')
                    .filter(status='pending', school_year=school_year)
                ),
                Prefetch(
                    'collegeentrancetest_set',
                    queryset=CollegeEntranceTest.objects.select_related('student')
                ),
                Prefetch(
                    'schoolbackground_set',
                    queryset=SchoolBackground.objects.select_related('student')
                ),
                Prefetch(
                    'contactpoint_set',
                    queryset=ContactPoint.objects.select_related('student')
                ),
            )
        )
    else:
        pending_counter = AdmissionApplication.objects.filter(school_year=school_year, status='pending', program=faculty_user.department).count()
        interview_counter = AdmissionApplication.objects.filter(school_year=school_year, status='verified', program=faculty_user.department).count()
        ranking_counter = AdmissionApplication.objects.filter(school_year=school_year, status='interviewed', program=faculty_user.department).count()
        waiting_counter = AdmissionApplication.objects.filter(school_year=school_year, status='waiting-list', program=faculty_user.department).count()
        qualified_counter = AdmissionApplication.objects.filter(school_year=school_year, status='approved', program=faculty_user.department).count()
        withdrawn_counter = AdmissionApplication.objects.filter(school_year=school_year, status='withdrawn', program=faculty_user.department).count()  
        programs = Program.objects.filter(is_active=True, pk=faculty_user.department.id)
        students = (
            Student.objects
            .annotate(has_admission_application=Exists(
                AdmissionApplication.objects
                .filter(student=OuterRef('pk'), status='pending', school_year=school_year, program=faculty_user.department)
            ))
            .filter(has_admission_application=True)
            .prefetch_related(
                Prefetch(
                    'admissionapplication_set',
                    queryset=AdmissionApplication.objects.select_related('student')
                    .filter(status='pending', school_year=school_year, program=faculty_user.department)
                ),
                Prefetch(
                    'collegeentrancetest_set',
                    queryset=CollegeEntranceTest.objects.select_related('student')
                ),
                Prefetch(
                    'schoolbackground_set',
                    queryset=SchoolBackground.objects.select_related('student')
                ),
                Prefetch(
                    'contactpoint_set',
                    queryset=ContactPoint.objects.select_related('student')
                ),
            )
        )
    
    applications = students
    
    context = {
        'applications': applications,
        'programs': programs,
        'pending_counter': pending_counter,
        'interview_counter': interview_counter,
        'ranking_counter': ranking_counter,
        'waiting_counter': waiting_counter,
        'qualified_counter': qualified_counter,
        'withdrawn_counter': withdrawn_counter,
    }
    
    rendered_html = render(request, 'admission/applications/pending.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
def view_verify_student_modal(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    has_slot = False
    interview = None
    current_datetime = timezone.now()
    school_year = SchoolYear.objects.filter(is_active=True).first()
    program = Program.objects.get(pk=request.POST.get('program_id'))
    slots = InterviewSlot.objects.filter(
        school_year=school_year,
        program=program,
        interview_date__gt=current_datetime.date()
    )
    for slot in slots:
        logs = InterviewLogs.objects.filter(interview=slot, status='okay').count()
        if slot.slot > logs:
            has_slot = True
            interview = slot
    
    if has_slot:
        application = AdmissionApplication.objects.get(pk=request.POST.get('application_id'))
        if application:
            cet = CollegeEntranceTest.objects.filter(student=application.student).first()
            school = SchoolBackground.objects.filter(student=application.student).first()

        context = {
            'application': application,
            'cet': cet,
            'school': school,
            'interview': interview,
        }
        
        rendered_html = render(request, 'admission/applications/verify_student.modal.html', context)
        return HttpResponse(rendered_html, content_type='text/html')
    
    else:
        context = {
            'program': program,
        }
        
        rendered_html = render(request, 'admission/applications/need_interview_slot.modal.html', context)
        return HttpResponse(rendered_html, content_type='text/html')

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def accept_application(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    application = AdmissionApplication.objects.get(pk=request.POST.get('application_id'))
    slot = InterviewSlot.objects.get(pk=request.POST.get('interview_id'))
    if application:
        application.status = 'verified'
        application.save()
        
        ApplicationStatusLogs.objects.create(
            application=application,
            status=application.status,
            processed_by=request.user
        )
        
        score = 0
        status = 'okay'
        processed_by = None
        comments = ''
        
        auto = AutoAdmission.objects.filter(program=application.program, school_year=application.school_year).first()
        print(auto.automate)
        if auto.automate:
            #predict
            predict = predict_programming_success(application)
            if predict[0] == 1:
                score = 100
                status = 'interviewed'
                processed_by = request.user
                comments = 'Automated: skipped interview'
                application.status = 'interviewed'
                
                #send to student
                title = f"{application.program.code.upper()} Application Status - Ranking"
                receiver = application.student.first_name
                mail_subject = f"{application.program.code.upper()} Application Status (Ranking) - GreenScreen Admission System"
                domain = get_current_site(request).domain
                application_url = reverse('my_application')
                message = f"""Your application for the <b>{application.program.name}</b> program is now for ranking. 
                            You can view the status of your application <a class="color-green" href="{domain}{application_url}">here</a>.
                            <br><br>Thank you for choosing our program."""
                to_email = list(ContactPoint.objects.filter(student=application.student).values_list('contact_email', flat=True))
                student_send_email(title, receiver, mail_subject, message, to_email)
            else:
                #send to student
                title = f"{application.program.code.upper()} Application Status - Scheduled for Interview"
                receiver = application.student.first_name
                mail_subject = f"{application.program.code.upper()} Application Status (Scheduled for Interview) - GreenScreen Admission System"
                domain = get_current_site(request).domain
                application_url = reverse('my_application')
                message = f"""Your application for the <b>{application.program.name}</b> program is now scheduled for an interview. 
                            You can view the status of your application <a class="color-green" href="{domain}{application_url}">here</a>.
                            <br><br>Thank you for choosing our program."""
                to_email = list(ContactPoint.objects.filter(student=application.student).values_list('contact_email', flat=True))
                student_send_email(title, receiver, mail_subject, message, to_email)
                
            application.prediction = predict[0]
            application.save() 
        
        InterviewLogs.objects.create(
            application=application,
            interview=slot,
            score=score,
            status=status,
            processed_by=processed_by,
            comments = comments
        )
        
        return JsonResponse({'message': 'Successful.'})
    
    return JsonResponse({'error': 'Invalid request method'}, status=400)

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def return_application(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    pk=request.POST.get('application_id')
    application = AdmissionApplication.objects.get(pk=pk)
    form = ReturnApplicationForm(request.POST)
    if form.is_valid():
        if application:
            application.status = 'returned'
            application.save()
            
            ApplicationStatusLogs.objects.create(
                application=application,
                status=application.status,
                comments=form.cleaned_data['details'],
                processed_by=request.user
            )
            
            #send to student
            title = f"{application.program.code.upper()} Application Status - Returned"
            receiver = application.student.first_name
            mail_subject = f"{application.program.code.upper()} Application Status (Returned) - GreenScreen Admission System"
            domain = get_current_site(request).domain
            application_url = reverse('my_application')
            message = f"""Your application for the <b>{application.program.name}</b> program has been returned for correction. 
                        You can view the status of your application <a class="color-green" href="{domain}{application_url}">here</a>.
                        <br><br>Thank you for choosing our program."""
            to_email = list(ContactPoint.objects.filter(student=application.student).values_list('contact_email', flat=True))
            student_send_email(title, receiver, mail_subject, message, to_email)
        
    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
def view_interview_slot(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    sy = SchoolYear.objects.filter(is_active=True).first()
    slots = (
        Program.objects
        .filter(is_active=True)
        .prefetch_related(
            Prefetch(
                'interviewslot_set',
                queryset=InterviewSlot.objects.select_related('program')
                .order_by('-interview_date', '-interview_time')
                .filter(school_year=sy)
            ),
        )
    )
    
    faculty_user = Faculty.objects.filter(user=request.user).first()
    
    context = {
        'slots': slots,
        'faculty_user': faculty_user,
    }
    
    rendered_html = render(request, 'admission/partials/view_interview_slot.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
def view_interview_slot_modal(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    program = Program.objects.get(pk=request.POST.get('program_id'))

    context = {
        'program': program,
    }
    
    rendered_html = render(request, 'admission/partials/add_interview.modal.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def add_interview_slot(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    form = InterviewSlotForm(request.POST)
    if form.is_valid():
        school_year = SchoolYear.objects.filter(is_active=True).first()
        program = Program.objects.get(pk=request.POST.get('program_id'))
        interview = form.save(commit=False)
        interview.school_year = school_year
        interview.program = program
        interview.save()
        
    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
def interview_application(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    school_year = SchoolYear.objects.filter(is_active=True).first()
    faculty_user = Faculty.objects.filter(user=request.user).first()
    if request.user.is_superuser:
        pending_counter = AdmissionApplication.objects.filter(school_year=school_year, status='pending').count()
        interview_counter = AdmissionApplication.objects.filter(school_year=school_year, status='verified').count()
        ranking_counter = AdmissionApplication.objects.filter(school_year=school_year, status='interviewed').count()
        waiting_counter = AdmissionApplication.objects.filter(school_year=school_year, status='waiting-list').count()
        qualified_counter = AdmissionApplication.objects.filter(school_year=school_year, status='approved').count()
        withdrawn_counter = AdmissionApplication.objects.filter(school_year=school_year, status='withdrawn').count()
        programs = Program.objects.filter(is_active=True)
        students = (
            Student.objects
            .annotate(has_admission_application=Exists(
                AdmissionApplication.objects
                .filter(student=OuterRef('pk'), status='verified', school_year=school_year)
            ))
            .filter(has_admission_application=True)
            .prefetch_related(
                Prefetch(
                    'admissionapplication_set',
                    queryset=AdmissionApplication.objects.select_related('student')
                    .filter(status='verified', school_year=school_year)
                    .prefetch_related(
                        Prefetch(
                            'interviewlogs_set',
                            queryset=InterviewLogs.objects.select_related('application')
                            .order_by('-created_at')
                        )
                    )
                ),
                Prefetch(
                    'collegeentrancetest_set',
                    queryset=CollegeEntranceTest.objects.select_related('student')
                ),
                Prefetch(
                    'schoolbackground_set',
                    queryset=SchoolBackground.objects.select_related('student')
                ),
                Prefetch(
                    'contactpoint_set',
                    queryset=ContactPoint.objects.select_related('student')
                ),
            )
        )
    else:
        pending_counter = AdmissionApplication.objects.filter(school_year=school_year, status='pending', program=faculty_user.department).count()
        interview_counter = AdmissionApplication.objects.filter(school_year=school_year, status='verified', program=faculty_user.department).count()
        ranking_counter = AdmissionApplication.objects.filter(school_year=school_year, status='interviewed', program=faculty_user.department).count()
        waiting_counter = AdmissionApplication.objects.filter(school_year=school_year, status='waiting-list', program=faculty_user.department).count()
        qualified_counter = AdmissionApplication.objects.filter(school_year=school_year, status='approved', program=faculty_user.department).count()
        withdrawn_counter = AdmissionApplication.objects.filter(school_year=school_year, status='withdrawn', program=faculty_user.department).count()
        programs = Program.objects.filter(is_active=True, pk=faculty_user.department.id)
        students = (
            Student.objects
            .annotate(has_admission_application=Exists(
                AdmissionApplication.objects
                .filter(student=OuterRef('pk'), status='verified', school_year=school_year, program=faculty_user.department)
            ))
            .filter(has_admission_application=True)
            .prefetch_related(
                Prefetch(
                    'admissionapplication_set',
                    queryset=AdmissionApplication.objects.select_related('student')
                    .filter(status='verified', school_year=school_year, program=faculty_user.department)
                    .prefetch_related(
                        Prefetch(
                            'interviewlogs_set',
                            queryset=InterviewLogs.objects.select_related('application')
                            .order_by('-created_at')
                        )
                    )
                ),
                Prefetch(
                    'collegeentrancetest_set',
                    queryset=CollegeEntranceTest.objects.select_related('student')
                ),
                Prefetch(
                    'schoolbackground_set',
                    queryset=SchoolBackground.objects.select_related('student')
                ),
                Prefetch(
                    'contactpoint_set',
                    queryset=ContactPoint.objects.select_related('student')
                ),
            )
        )

    applications = students
    
    context = {
        'applications': applications,
        'programs': programs,
        'pending_counter': pending_counter,
        'interview_counter': interview_counter,
        'ranking_counter': ranking_counter,
        'waiting_counter': waiting_counter,
        'qualified_counter': qualified_counter,
        'withdrawn_counter': withdrawn_counter,
    }
    
    rendered_html = render(request, 'admission/applications/interview.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@login_required(login_url='/admin/sign-in/')
def view_student_profile(request, id):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    student = Student.objects.filter(pk=id, is_profile_complete=True).first()
    
    if not student:
        return redirect('view_application')
    
    if student.birth_date is not None:
        student_birth_date = student.birth_date
        formatted_date = student_birth_date.strftime('%Y-%m-%d')
        student.birth_date = formatted_date
    contact = ContactPoint.objects.filter(student=student).first()
    address = PersonalAddress.objects.filter(student=student).first()
    cet = CollegeEntranceTest.objects.filter(student=student).first()
    strands = SHSStrand.objects.all()
    class_positions = ClassRoomOrganization.objects.all()
    ssg = StudentSupremeGovernment.objects.all()
    ranks = ClassRank.objects.all()
    awards = AcademicAwards.objects.all()
    school = SchoolBackground.objects.filter(student=student).first()
    degrees = AcademicDegree.objects.all()
    employment = EmploymentStatus.objects.all()
    economic = EconomicStatus.objects.filter(student=student).first()
    pt = PersonalityTest.objects.filter(student=student).first()
    sh = StudyHabit.objects.filter(student=student).first()
    
    page_title = 'View Student Profile'
    context = {
        'page_title': page_title,
        'student': student,
        'contact': contact,
        'address': address,
        'cet': cet,
        'strands': strands,
        'class_positions': class_positions,
        'ssg': ssg,
        'ranks': ranks,
        'awards': awards,
        'school': school,
        'degrees': degrees,
        'employment': employment,
        'economic': economic,
        'pt': pt,
        'sh': sh,
        'settings': settings
    }
    
    return render(request, 'admission/student/main.html', context)

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
def view_rate_interview_modal(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    application = AdmissionApplication.objects.get(pk=request.POST.get('application_id'))
    
    context = {
        'application': application,
    }
    
    rendered_html = render(request, 'admission/applications/interview_student.modal.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def rate_interview(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    application = AdmissionApplication.objects.get(pk=request.POST.get('application_id'))
    form = RateInterviewForm(request.POST)
    if form.is_valid():
        if application:
            log = InterviewLogs.objects.filter(application=application).order_by('-created_at').first()
            if log:
                status = form.cleaned_data.get('student_status')
                log.status = status
                log.score = form.cleaned_data.get('score')
                log.comments = form.cleaned_data.get('comments')
                log.processed_by = request.user
                log.save()
                
                application = log.application
                if status == 'interviewed':
                    application.status = status
                else:
                    application.status = 'declined'
                application.save()
                
                ApplicationStatusLogs.objects.create(
                    status = application.status,
                    comments = form.cleaned_data.get('comments'),
                    application = application,
                    processed_by = request.user
                )
                
                #send to student
                title = f"{application.program.code.upper()} Application Status - Ranking"
                receiver = application.student.first_name
                mail_subject = f"{application.program.code.upper()} Application Status (Ranking) - GreenScreen Admission System"
                domain = get_current_site(request).domain
                application_url = reverse('my_application')
                message = f"""Your application for the <b>{application.program.name}</b> program is now for ranking. 
                            You can view the status of your application <a class="color-green" href="{domain}{application_url}">here</a>.
                            <br><br>Thank you for choosing our program."""
                to_email = list(ContactPoint.objects.filter(student=application.student).values_list('contact_email', flat=True))
                student_send_email(title, receiver, mail_subject, message, to_email)
        
    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
def ranking_application(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    school_year = SchoolYear.objects.filter(is_active=True).first()
    faculty_user = Faculty.objects.filter(user=request.user).first()
    if request.user.is_superuser:
        pending_counter = AdmissionApplication.objects.filter(school_year=school_year, status='pending').count()
        interview_counter = AdmissionApplication.objects.filter(school_year=school_year, status='verified').count()
        ranking_counter = AdmissionApplication.objects.filter(school_year=school_year, status='interviewed').count()
        waiting_counter = AdmissionApplication.objects.filter(school_year=school_year, status='waiting-list').count()
        qualified_counter = AdmissionApplication.objects.filter(school_year=school_year, status='approved').count()
        withdrawn_counter = AdmissionApplication.objects.filter(school_year=school_year, status='withdrawn').count()
        programs = Program.objects.filter(is_active=True)
        students = (
            Student.objects
            .annotate(has_admission_application=Exists(
                AdmissionApplication.objects
                .filter(student=OuterRef('pk'), status='interviewed', school_year=school_year)
            ))
            .filter(has_admission_application=True)
            .prefetch_related(
                Prefetch(
                    'admissionapplication_set',
                    queryset=AdmissionApplication.objects.select_related('student')
                    .filter(status='interviewed', school_year=school_year)
                    .prefetch_related(
                        Prefetch(
                            'interviewlogs_set',
                            queryset=InterviewLogs.objects.select_related('application')
                            .filter(status='interviewed')
                            .order_by('-created_at')
                        )
                    )
                ),
                Prefetch(
                    'collegeentrancetest_set',
                    queryset=CollegeEntranceTest.objects.select_related('student')
                ),
                Prefetch(
                    'schoolbackground_set',
                    queryset=SchoolBackground.objects.select_related('student')
                ),
                Prefetch(
                    'contactpoint_set',
                    queryset=ContactPoint.objects.select_related('student')
                ),
            )
        )
    else:
        pending_counter = AdmissionApplication.objects.filter(school_year=school_year, status='pending', program=faculty_user.department).count()
        interview_counter = AdmissionApplication.objects.filter(school_year=school_year, status='verified', program=faculty_user.department).count()
        ranking_counter = AdmissionApplication.objects.filter(school_year=school_year, status='interviewed', program=faculty_user.department).count()
        waiting_counter = AdmissionApplication.objects.filter(school_year=school_year, status='waiting-list', program=faculty_user.department).count()
        qualified_counter = AdmissionApplication.objects.filter(school_year=school_year, status='approved', program=faculty_user.department).count()
        withdrawn_counter = AdmissionApplication.objects.filter(school_year=school_year, status='withdrawn', program=faculty_user.department).count()
        programs = Program.objects.filter(is_active=True, pk=faculty_user.department.id)
        students = (
            Student.objects
            .annotate(has_admission_application=Exists(
                AdmissionApplication.objects
                .filter(student=OuterRef('pk'), status='interviewed', school_year=school_year, program=faculty_user.department)
            ))
            .filter(has_admission_application=True)
            .prefetch_related(
                Prefetch(
                    'admissionapplication_set',
                    queryset=AdmissionApplication.objects.select_related('student')
                    .filter(status='interviewed', school_year=school_year, program=faculty_user.department)
                    .prefetch_related(
                        Prefetch(
                            'interviewlogs_set',
                            queryset=InterviewLogs.objects.select_related('application')
                            .filter(status='interviewed')
                            .order_by('-created_at')
                        )
                    )
                ),
                Prefetch(
                    'collegeentrancetest_set',
                    queryset=CollegeEntranceTest.objects.select_related('student')
                ),
                Prefetch(
                    'schoolbackground_set',
                    queryset=SchoolBackground.objects.select_related('student')
                ),
                Prefetch(
                    'contactpoint_set',
                    queryset=ContactPoint.objects.select_related('student')
                ),
            )
        )
    
    # Calculate total for each student
    students_with_total = []
    for student in students:
        cet = student.collegeentrancetest_set.first()
        shs = student.schoolbackground_set.first()
        admission_application = student.admissionapplication_set.first()
        
        cet_crt = Criteria.objects.filter(program=admission_application.program, school_year=school_year, code='cet').first()
        shs_crt = Criteria.objects.filter(program=admission_application.program, school_year=school_year, code='shs').first()
        int_crt = Criteria.objects.filter(program=admission_application.program, school_year=school_year, code='interview').first()
        
        total = ((Decimal(cet_crt.weight)/100 * Decimal(cet.overall_percentile_rank))
                + (Decimal(shs_crt.weight)/100 * Decimal(shs.combined_gpa))
                + (Decimal(int_crt.weight)/100 * Decimal(admission_application.interviewlogs_set.first().score)))
        total = round(total, 2)
        
        admission_application.total = total
        admission_application.save()
        students_with_total.append((student, total))

    students_with_total = sorted(students_with_total, key=lambda x: x[1], reverse=True)
    sorted_students = [student for student, _ in students_with_total]
    
    applications = sorted_students
    
    context = {
        'applications': applications,
        'programs': programs,
        'pending_counter': pending_counter,
        'interview_counter': interview_counter,
        'ranking_counter': ranking_counter,
        'waiting_counter': waiting_counter,
        'qualified_counter': qualified_counter,
        'withdrawn_counter': withdrawn_counter,
    }
    
    rendered_html = render(request, 'admission/applications/ranking.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
def view_process_student_modal(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    application = AdmissionApplication.objects.get(pk=request.POST.get('application_id'))
    
    context = {
        'application': application,
    }
    
    rendered_html = render(request, 'admission/applications/process_student.modal.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def process_application(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    application = AdmissionApplication.objects.get(pk=request.POST.get('application_id'))
    form = ProcessApplicationForm(request.POST)
    if form.is_valid():
        if application:
            application.status = form.cleaned_data.get('student_status')
            application.save()
            
            ApplicationStatusLogs.objects.create(
                status = application.status,
                comments = form.cleaned_data.get('comments'),
                application = application,
                processed_by = request.user
            )
            
            #send to student
            status = application.status.lower()
            if status == "waiting-list":
                status = "moved to waiting list"
            last_msg = "Thank you for choosing our program."
            if status == "declined":
                last_msg = "We wish you good luck on your academic journey."
            title = f"{application.program.code.upper()} Application Status - {status.capitalize()}"
            receiver = application.student.first_name
            mail_subject = f"{application.program.code.upper()} Application Status ({status.capitalize()}) - GreenScreen Admission System"
            domain = get_current_site(request).domain
            application_url = reverse('my_application')
            message = f"""Your application for the <b>{application.program.name}</b> program has been {status}. 
                        You can view the status of your application <a class="color-green" href="{domain}{application_url}">here</a>.
                        <br><br>{last_msg}"""
            to_email = list(ContactPoint.objects.filter(student=application.student).values_list('contact_email', flat=True))
            student_send_email(title, receiver, mail_subject, message, to_email)
        
    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
def waiting_application(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    school_year = SchoolYear.objects.filter(is_active=True).first()
    faculty_user = Faculty.objects.filter(user=request.user).first()
    if request.user.is_superuser:
        pending_counter = AdmissionApplication.objects.filter(school_year=school_year, status='pending').count()
        interview_counter = AdmissionApplication.objects.filter(school_year=school_year, status='verified').count()
        ranking_counter = AdmissionApplication.objects.filter(school_year=school_year, status='interviewed').count()
        waiting_counter = AdmissionApplication.objects.filter(school_year=school_year, status='waiting-list').count()
        qualified_counter = AdmissionApplication.objects.filter(school_year=school_year, status='approved').count()
        withdrawn_counter = AdmissionApplication.objects.filter(school_year=school_year, status='withdrawn').count()
        programs = Program.objects.filter(is_active=True)
        students = (
            Student.objects
            .annotate(has_admission_application=Exists(
                AdmissionApplication.objects
                .filter(student=OuterRef('pk'), status='waiting-list', school_year=school_year)
            ))
            .filter(has_admission_application=True)
            .prefetch_related(
                Prefetch(
                    'admissionapplication_set',
                    queryset=AdmissionApplication.objects.select_related('student')
                    .filter(status='waiting-list', school_year=school_year)
                    .prefetch_related(
                        Prefetch(
                            'interviewlogs_set',
                            queryset=InterviewLogs.objects.select_related('application')
                            .filter(status='interviewed')
                            .order_by('-created_at')
                        )
                    )
                ),
                Prefetch(
                    'collegeentrancetest_set',
                    queryset=CollegeEntranceTest.objects.select_related('student')
                ),
                Prefetch(
                    'schoolbackground_set',
                    queryset=SchoolBackground.objects.select_related('student')
                ),
                Prefetch(
                    'contactpoint_set',
                    queryset=ContactPoint.objects.select_related('student')
                ),
            )
        )
    else:
        pending_counter = AdmissionApplication.objects.filter(school_year=school_year, status='pending', program=faculty_user.department).count()
        interview_counter = AdmissionApplication.objects.filter(school_year=school_year, status='verified', program=faculty_user.department).count()
        ranking_counter = AdmissionApplication.objects.filter(school_year=school_year, status='interviewed', program=faculty_user.department).count()
        waiting_counter = AdmissionApplication.objects.filter(school_year=school_year, status='waiting-list', program=faculty_user.department).count()
        qualified_counter = AdmissionApplication.objects.filter(school_year=school_year, status='approved', program=faculty_user.department).count()
        withdrawn_counter = AdmissionApplication.objects.filter(school_year=school_year, status='withdrawn', program=faculty_user.department).count()
        programs = Program.objects.filter(is_active=True, pk=faculty_user.department.id)
        students = (
            Student.objects
            .annotate(has_admission_application=Exists(
                AdmissionApplication.objects
                .filter(student=OuterRef('pk'), status='waiting-list', school_year=school_year, program=faculty_user.department)
            ))
            .filter(has_admission_application=True)
            .prefetch_related(
                Prefetch(
                    'admissionapplication_set',
                    queryset=AdmissionApplication.objects.select_related('student')
                    .filter(status='waiting-list', school_year=school_year, program=faculty_user.department)
                    .prefetch_related(
                        Prefetch(
                            'interviewlogs_set',
                            queryset=InterviewLogs.objects.select_related('application')
                            .filter(status='interviewed')
                            .order_by('-created_at')
                        )
                    )
                ),
                Prefetch(
                    'collegeentrancetest_set',
                    queryset=CollegeEntranceTest.objects.select_related('student')
                ),
                Prefetch(
                    'schoolbackground_set',
                    queryset=SchoolBackground.objects.select_related('student')
                ),
                Prefetch(
                    'contactpoint_set',
                    queryset=ContactPoint.objects.select_related('student')
                ),
            )
        )
    
    # Calculate total for each student
    students_with_total = []
    for student in students:
        cet = student.collegeentrancetest_set.first()
        shs = student.schoolbackground_set.first()
        admission_application = student.admissionapplication_set.first()
        
        cet_crt = Criteria.objects.filter(program=admission_application.program, school_year=school_year, code='cet').first()
        shs_crt = Criteria.objects.filter(program=admission_application.program, school_year=school_year, code='shs').first()
        int_crt = Criteria.objects.filter(program=admission_application.program, school_year=school_year, code='interview').first()
        
        total = ((Decimal(cet_crt.weight)/100 * Decimal(cet.overall_percentile_rank))
                + (Decimal(shs_crt.weight)/100 * Decimal(shs.combined_gpa))
                + (Decimal(int_crt.weight)/100 * Decimal(admission_application.interviewlogs_set.first().score)))
        total = round(total, 2)
        
        admission_application.total = total
        admission_application.save()
        students_with_total.append((student, total))

    students_with_total = sorted(students_with_total, key=lambda x: x[1], reverse=True)
    sorted_students = [student for student, _ in students_with_total]
    
    applications = sorted_students
    
    context = {
        'applications': applications,
        'programs': programs,
        'pending_counter': pending_counter,
        'interview_counter': interview_counter,
        'ranking_counter': ranking_counter,
        'waiting_counter': waiting_counter,
        'qualified_counter': qualified_counter,
        'withdrawn_counter': withdrawn_counter,
    }
    
    rendered_html = render(request, 'admission/applications/waiting.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
def view_process_waitingstudent_modal(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    application = AdmissionApplication.objects.get(pk=request.POST.get('application_id'))
    
    context = {
        'application': application,
    }
    
    rendered_html = render(request, 'admission/applications/process_waitingstudent.modal.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@ensure_csrf_cookie
@require_POST
def qualified_application(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    school_year = SchoolYear.objects.filter(is_active=True).first()
    faculty_user = Faculty.objects.filter(user=request.user).first()
    if request.user.is_superuser:
        pending_counter = AdmissionApplication.objects.filter(school_year=school_year, status='pending').count()
        interview_counter = AdmissionApplication.objects.filter(school_year=school_year, status='verified').count()
        ranking_counter = AdmissionApplication.objects.filter(school_year=school_year, status='interviewed').count()
        waiting_counter = AdmissionApplication.objects.filter(school_year=school_year, status='waiting-list').count()
        qualified_counter = AdmissionApplication.objects.filter(school_year=school_year, status='approved').count()
        withdrawn_counter = AdmissionApplication.objects.filter(school_year=school_year, status='withdrawn').count()
        programs = Program.objects.filter(is_active=True)
        students = (
            Student.objects
            .annotate(has_admission_application=Exists(
                AdmissionApplication.objects
                .filter(student=OuterRef('pk'), status='approved', school_year=school_year)
            ))
            .filter(has_admission_application=True)
            .prefetch_related(
                Prefetch(
                    'admissionapplication_set',
                    queryset=AdmissionApplication.objects.select_related('student')
                    .filter(status='approved', school_year=school_year)
                    .prefetch_related(
                        Prefetch(
                            'interviewlogs_set',
                            queryset=InterviewLogs.objects.select_related('application')
                            .filter(status='interviewed')
                            .order_by('-created_at')
                        )
                    )
                ),
                Prefetch(
                    'collegeentrancetest_set',
                    queryset=CollegeEntranceTest.objects.select_related('student')
                ),
                Prefetch(
                    'schoolbackground_set',
                    queryset=SchoolBackground.objects.select_related('student')
                ),
                Prefetch(
                    'contactpoint_set',
                    queryset=ContactPoint.objects.select_related('student')
                ),
            )
        )
    else:
        pending_counter = AdmissionApplication.objects.filter(school_year=school_year, status='pending', program=faculty_user.department).count()
        interview_counter = AdmissionApplication.objects.filter(school_year=school_year, status='verified', program=faculty_user.department).count()
        ranking_counter = AdmissionApplication.objects.filter(school_year=school_year, status='interviewed', program=faculty_user.department).count()
        waiting_counter = AdmissionApplication.objects.filter(school_year=school_year, status='waiting-list', program=faculty_user.department).count()
        qualified_counter = AdmissionApplication.objects.filter(school_year=school_year, status='approved', program=faculty_user.department).count()
        withdrawn_counter = AdmissionApplication.objects.filter(school_year=school_year, status='withdrawn', program=faculty_user.department).count()
        programs = Program.objects.filter(is_active=True, pk=faculty_user.department.id)
        students = (
            Student.objects
            .annotate(has_admission_application=Exists(
                AdmissionApplication.objects
                .filter(student=OuterRef('pk'), status='approved', school_year=school_year, program=faculty_user.department)
            ))
            .filter(has_admission_application=True)
            .prefetch_related(
                Prefetch(
                    'admissionapplication_set',
                    queryset=AdmissionApplication.objects.select_related('student')
                    .filter(status='approved', school_year=school_year, program=faculty_user.department)
                    .prefetch_related(
                        Prefetch(
                            'interviewlogs_set',
                            queryset=InterviewLogs.objects.select_related('application')
                            .filter(status='interviewed')
                            .order_by('-created_at')
                        )
                    )
                ),
                Prefetch(
                    'collegeentrancetest_set',
                    queryset=CollegeEntranceTest.objects.select_related('student')
                ),
                Prefetch(
                    'schoolbackground_set',
                    queryset=SchoolBackground.objects.select_related('student')
                ),
                Prefetch(
                    'contactpoint_set',
                    queryset=ContactPoint.objects.select_related('student')
                ),
            )
        )
        
    # Calculate total for each student
    students_with_total = []
    for student in students:
        cet = student.collegeentrancetest_set.first()
        shs = student.schoolbackground_set.first()
        admission_application = student.admissionapplication_set.first()
        
        cet_crt = Criteria.objects.filter(program=admission_application.program, school_year=school_year, code='cet').first()
        shs_crt = Criteria.objects.filter(program=admission_application.program, school_year=school_year, code='shs').first()
        int_crt = Criteria.objects.filter(program=admission_application.program, school_year=school_year, code='interview').first()
        
        total = ((Decimal(cet_crt.weight)/100 * Decimal(cet.overall_percentile_rank))
                + (Decimal(shs_crt.weight)/100 * Decimal(shs.combined_gpa))
                + (Decimal(int_crt.weight)/100 * Decimal(admission_application.interviewlogs_set.first().score)))
        total = round(total, 2)
        
        admission_application.total = total
        admission_application.save()
        students_with_total.append((student, total))

    students_with_total = sorted(students_with_total, key=lambda x: x[1], reverse=True)
    sorted_students = [student for student, _ in students_with_total]
    
    applications = sorted_students
    
    context = {
        'applications': applications,
        'programs': programs,
        'pending_counter': pending_counter,
        'interview_counter': interview_counter,
        'ranking_counter': ranking_counter,
        'waiting_counter': waiting_counter,
        'qualified_counter': qualified_counter,
        'withdrawn_counter': withdrawn_counter,
    }
    
    rendered_html = render(request, 'admission/applications/qualified.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
def view_withdraw_modal(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    application = AdmissionApplication.objects.get(pk=request.POST.get('application_id'))
    program = Program.objects.get(pk=request.POST.get('program_id'))
    
    context = {
        'application': application,
        'program': program,
    }
    
    rendered_html = render(request, 'admission/applications/withdraw_student.modal.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def withdraw_application(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    application = AdmissionApplication.objects.get(pk=request.POST.get('application_id'))
    form = WithdrawApplicationForm(request.POST)
    if form.is_valid():
        if application:
            application.status = 'withdrawn'
            application.save()
            
            ApplicationStatusLogs.objects.create(
                status = application.status,
                comments = form.cleaned_data.get('reason'),
                application = application,
                processed_by = request.user
            )
            
            #send to student
            title = f"{application.program.code.upper()} Application Status - Withdrawn"
            receiver = application.student.first_name
            mail_subject = f"{application.program.code.upper()} Application Status (Withdrawn) - GreenScreen Admission System"
            domain = get_current_site(request).domain
            application_url = reverse('my_application')
            message = f"""Your application for the <b>{application.program.name}</b> program has been withdrawn. 
                        You can view the status of your application <a class="color-green" href="{domain}{application_url}">here</a>.
                        <br><br>We wish you good luck on your academic journey."""
            to_email = list(ContactPoint.objects.filter(student=application.student).values_list('contact_email', flat=True))
            student_send_email(title, receiver, mail_subject, message, to_email)
        
    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def decline_application(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    pk=request.POST.get('application_id')
    application = AdmissionApplication.objects.get(pk=pk)
    form = ReturnApplicationForm(request.POST)
    if form.is_valid():
        if application:
            application.status = 'declined'
            application.save()
            
            ApplicationStatusLogs.objects.create(
                application=application,
                status=application.status,
                comments=form.cleaned_data['details'],
                processed_by=request.user
            )
            
            #send to student
            title = f"{application.program.code.upper()} Application Status - Declined"
            receiver = application.student.first_name
            mail_subject = f"{application.program.code.upper()} Application Status (Declined) - GreenScreen Admission System"
            domain = get_current_site(request).domain
            application_url = reverse('my_application')
            message = f"""Your application for the <b>{application.program.name}</b> program has been declined. 
                        You can view the status of your application <a class="color-green" href="{domain}{application_url}">here</a>.
                        <br><br>We wish you good luck on your academic journey."""
            to_email = list(ContactPoint.objects.filter(student=application.student).values_list('contact_email', flat=True))
            student_send_email(title, receiver, mail_subject, message, to_email)
        
    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
def withdrawn_application(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    school_year = SchoolYear.objects.filter(is_active=True).first()
    faculty_user = Faculty.objects.filter(user=request.user).first()
    if request.user.is_superuser:
        pending_counter = AdmissionApplication.objects.filter(school_year=school_year, status='pending').count()
        interview_counter = AdmissionApplication.objects.filter(school_year=school_year, status='verified').count()
        ranking_counter = AdmissionApplication.objects.filter(school_year=school_year, status='interviewed').count()
        waiting_counter = AdmissionApplication.objects.filter(school_year=school_year, status='waiting-list').count()
        qualified_counter = AdmissionApplication.objects.filter(school_year=school_year, status='approved').count()
        withdrawn_counter = AdmissionApplication.objects.filter(school_year=school_year, status='withdrawn').count()
        programs = Program.objects.filter(is_active=True)
        students = (
            Student.objects
            .annotate(has_admission_application=Exists(
                AdmissionApplication.objects
                .filter(student=OuterRef('pk'), status='withdrawn', school_year=school_year)
            ))
            .filter(has_admission_application=True)
            .prefetch_related(
                Prefetch(
                    'admissionapplication_set',
                    queryset=AdmissionApplication.objects.select_related('student')
                    .filter(status='withdrawn', school_year=school_year)
                    .prefetch_related(
                        Prefetch(
                            'interviewlogs_set',
                            queryset=InterviewLogs.objects.select_related('application')
                            .filter(status='interviewed')
                            .order_by('-created_at')
                        ),
                        Prefetch(
                            'applicationstatuslogs_set',
                            queryset=ApplicationStatusLogs.objects.select_related('application')
                            .filter(status='withdrawn')
                            .order_by('-created_at')
                        )
                    )
                ),
                Prefetch(
                    'collegeentrancetest_set',
                    queryset=CollegeEntranceTest.objects.select_related('student')
                ),
                Prefetch(
                    'schoolbackground_set',
                    queryset=SchoolBackground.objects.select_related('student')
                ),
                Prefetch(
                    'contactpoint_set',
                    queryset=ContactPoint.objects.select_related('student')
                ),
            )
        )
    else:
        pending_counter = AdmissionApplication.objects.filter(school_year=school_year, status='pending', program=faculty_user.department).count()
        interview_counter = AdmissionApplication.objects.filter(school_year=school_year, status='verified', program=faculty_user.department).count()
        ranking_counter = AdmissionApplication.objects.filter(school_year=school_year, status='interviewed', program=faculty_user.department).count()
        waiting_counter = AdmissionApplication.objects.filter(school_year=school_year, status='waiting-list', program=faculty_user.department).count()
        qualified_counter = AdmissionApplication.objects.filter(school_year=school_year, status='approved', program=faculty_user.department).count()
        withdrawn_counter = AdmissionApplication.objects.filter(school_year=school_year, status='withdrawn', program=faculty_user.department).count()
        programs = Program.objects.filter(is_active=True, pk=faculty_user.department.id)
        students = (
            Student.objects
            .annotate(has_admission_application=Exists(
                AdmissionApplication.objects
                .filter(student=OuterRef('pk'), status='withdrawn', school_year=school_year, program=faculty_user.department)
            ))
            .filter(has_admission_application=True)
            .prefetch_related(
                Prefetch(
                    'admissionapplication_set',
                    queryset=AdmissionApplication.objects.select_related('student')
                    .filter(status='withdrawn', school_year=school_year, program=faculty_user.department)
                    .prefetch_related(
                        Prefetch(
                            'interviewlogs_set',
                            queryset=InterviewLogs.objects.select_related('application')
                            .filter(status='interviewed')
                            .order_by('-created_at')
                        ),
                        Prefetch(
                            'applicationstatuslogs_set',
                            queryset=ApplicationStatusLogs.objects.select_related('application')
                            .filter(status='withdrawn')
                            .order_by('-created_at')
                        )
                    )
                ),
                Prefetch(
                    'collegeentrancetest_set',
                    queryset=CollegeEntranceTest.objects.select_related('student')
                ),
                Prefetch(
                    'schoolbackground_set',
                    queryset=SchoolBackground.objects.select_related('student')
                ),
                Prefetch(
                    'contactpoint_set',
                    queryset=ContactPoint.objects.select_related('student')
                ),
            )
        )
    
    applications = students
    
    context = {
        'applications': applications,
        'programs': programs,
        'pending_counter': pending_counter,
        'interview_counter': interview_counter,
        'ranking_counter': ranking_counter,
        'waiting_counter': waiting_counter,
        'qualified_counter': qualified_counter,
        'withdrawn_counter': withdrawn_counter,
    }
    
    rendered_html = render(request, 'admission/applications/withdrawn.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
def all_application(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    school_year = SchoolYear.objects.filter(is_active=True).first()
    faculty_user = Faculty.objects.filter(user=request.user).first()
    if request.user.is_superuser:
        pending_counter = AdmissionApplication.objects.filter(school_year=school_year, status='pending').count()
        interview_counter = AdmissionApplication.objects.filter(school_year=school_year, status='verified').count()
        ranking_counter = AdmissionApplication.objects.filter(school_year=school_year, status='interviewed').count()
        waiting_counter = AdmissionApplication.objects.filter(school_year=school_year, status='waiting-list').count()
        qualified_counter = AdmissionApplication.objects.filter(school_year=school_year, status='approved').count()
        withdrawn_counter = AdmissionApplication.objects.filter(school_year=school_year, status='withdrawn').count()
        programs = Program.objects.filter(is_active=True)
        students = (
            Student.objects
            .annotate(has_admission_application=Exists(
                AdmissionApplication.objects
                .filter(student=OuterRef('pk'), school_year=school_year)
            ))
            .filter(has_admission_application=True)
            .prefetch_related(
                Prefetch(
                    'admissionapplication_set',
                    queryset=AdmissionApplication.objects.select_related('student')
                    .filter(school_year=school_year)
                    .order_by('-created_at')
                ),
                Prefetch(
                    'collegeentrancetest_set',
                    queryset=CollegeEntranceTest.objects.select_related('student')
                ),
                Prefetch(
                    'schoolbackground_set',
                    queryset=SchoolBackground.objects.select_related('student')
                ),
                Prefetch(
                    'contactpoint_set',
                    queryset=ContactPoint.objects.select_related('student')
                ),
            )
        )
    else:
        pending_counter = AdmissionApplication.objects.filter(school_year=school_year, status='pending', program=faculty_user.department).count()
        interview_counter = AdmissionApplication.objects.filter(school_year=school_year, status='verified', program=faculty_user.department).count()
        ranking_counter = AdmissionApplication.objects.filter(school_year=school_year, status='interviewed', program=faculty_user.department).count()
        waiting_counter = AdmissionApplication.objects.filter(school_year=school_year, status='waiting-list', program=faculty_user.department).count()
        qualified_counter = AdmissionApplication.objects.filter(school_year=school_year, status='approved', program=faculty_user.department).count()
        withdrawn_counter = AdmissionApplication.objects.filter(school_year=school_year, status='withdrawn', program=faculty_user.department).count()
        programs = Program.objects.filter(is_active=True, pk=faculty_user.department.id)
        students = (
            Student.objects
            .annotate(has_admission_application=Exists(
                AdmissionApplication.objects
                .filter(student=OuterRef('pk'), school_year=school_year, program=faculty_user.department)
            ))
            .filter(has_admission_application=True)
            .prefetch_related(
                Prefetch(
                    'admissionapplication_set',
                    queryset=AdmissionApplication.objects.select_related('student')
                    .filter(school_year=school_year, program=faculty_user.department)
                    .order_by('-created_at')
                ),
                Prefetch(
                    'collegeentrancetest_set',
                    queryset=CollegeEntranceTest.objects.select_related('student')
                ),
                Prefetch(
                    'schoolbackground_set',
                    queryset=SchoolBackground.objects.select_related('student')
                ),
                Prefetch(
                    'contactpoint_set',
                    queryset=ContactPoint.objects.select_related('student')
                ),
            )
        )
    
    applications = students
    
    context = {
        'applications': applications,
        'programs': programs,
        'pending_counter': pending_counter,
        'interview_counter': interview_counter,
        'ranking_counter': ranking_counter,
        'waiting_counter': waiting_counter,
        'qualified_counter': qualified_counter,
        'withdrawn_counter': withdrawn_counter,
    }
    
    rendered_html = render(request, 'admission/applications/all.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@login_required(login_url='/admin/sign-in/')
def monitoring(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    page_title = 'Monitoring'
    page_active = 'monitoring'

    context = {
        'page_title': page_title,
        'page_active': page_active,
    }
    
    return render(request, 'admission/monitoring.html', context)

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
def view_monitoring(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    school_year = SchoolYear.objects.all()
    active_year = SchoolYear.objects.filter(is_active=True).first()
    faculty_user = Faculty.objects.filter(user=request.user).first()
    if request.user.is_superuser:
        programs = Program.objects.filter(is_active=True)
        students = (
            Student.objects
            .annotate(has_admission_application=Exists(
                AdmissionApplication.objects
                .filter(student=OuterRef('pk'), status='approved')
            ))
            .filter(has_admission_application=True)
            .prefetch_related(
                Prefetch(
                    'admissionapplication_set',
                    queryset=AdmissionApplication.objects.select_related('student')
                    .filter(status='approved')
                ),
                Prefetch(
                    'contactpoint_set',
                    queryset=ContactPoint.objects.select_related('student')
                ),
                Prefetch(
                    'ccgrade_set',
                    queryset=CCGrade.objects.select_related('student')
                ),
            )
            .order_by('last_name', 'first_name', 'middle_name')
        )
    else:
        programs = Program.objects.filter(is_active=True, pk=faculty_user.department.id)
        students = (
            Student.objects
            .annotate(has_admission_application=Exists(
                AdmissionApplication.objects
                .filter(student=OuterRef('pk'), status='approved', program=faculty_user.department)
            ))
            .filter(has_admission_application=True)
            .prefetch_related(
                Prefetch(
                    'admissionapplication_set',
                    queryset=AdmissionApplication.objects.select_related('student')
                    .filter(status='approved', program=faculty_user.department)
                ),
                Prefetch(
                    'contactpoint_set',
                    queryset=ContactPoint.objects.select_related('student')
                ),
                Prefetch(
                    'ccgrade_set',
                    queryset=CCGrade.objects.select_related('student')
                ),
            )
            .order_by('last_name', 'first_name', 'middle_name')
        )

    for student in students:
        is_none = True
        is_successful = False
        
        try:
            ccgrade = student.ccgrade_set.first()
            
            if ccgrade is not None:
                cc101 = ccgrade.cc101
                cc102 = ccgrade.cc102
                
                if cc101 is None or cc101 == "":
                    is_none = True
                elif cc102 is None or cc102 == "":
                    is_none = True
                else:
                    is_none = False
                    if cc101 == 'INC' or cc101 == 'AW' or cc101 == 'UW':
                        is_successful = False
                    elif cc102 == 'INC' or cc102 == 'AW' or cc102 == 'UW':
                        is_successful = False
                    else:
                        cc101 = float(ccgrade.cc101)
                        cc102 = float(ccgrade.cc102)
                        average = (cc101 + cc102) / 2
                        if average <= 2.0:
                            is_successful = True
                        else:
                            is_successful = False
        except CCGrade.DoesNotExist:
            is_none = True
        
        student.is_none = is_none
        student.is_successful = is_successful
    
    applications = students
    context = {
        'school_year': school_year,
        'active_year': active_year,
        'applications': applications,
        'programs': programs,
        'faculty_user': faculty_user,
    }
    
    rendered_html = render(request, 'admission/partials/view_monitoring.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
def view_monitoring_modal(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    student = Student.objects.get(pk=request.POST.get('student_id'))
    ccgrade = CCGrade.objects.filter(student=student).first()
    
    context = {
        'student': student,
        'ccgrade': ccgrade,
    }
    
    rendered_html = render(request, 'admission/partials/monitor_student.modal.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def save_monitoring(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    student = Student.objects.get(pk=request.POST.get('student_id'))
    form = MonitoringForm(request.POST)
    if form.is_valid():
        ccgrade, _ = CCGrade.objects.get_or_create(student=student)
        ccgrade.cc101 = form.cleaned_data.get('cc101')
        ccgrade.cc102 = form.cleaned_data.get('cc102')
        if form.cleaned_data.get('with_intervention') == '1':
            ccgrade.with_intervention = True
        else:
            ccgrade.with_intervention = False
        ccgrade.comments = form.cleaned_data.get('comments')
        ccgrade.save()
        
    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

def load_model():
    with open('model.pkl', 'rb') as file:
        model = pickle.load(file)
    return model

def predict_programming_success(application):
    model = load_model()

    #query
    cet = CollegeEntranceTest.objects.filter(student=application.student).first()
    shs = SchoolBackground.objects.filter(student=application.student).first()
    pt = PersonalityTest.objects.filter(student=application.student).first()
    ss = StudyHabit.objects.filter(student=application.student).first()
    econ = EconomicStatus.objects.filter(student=application.student).first()
       
    #load data
    cet_oapr = cet.overall_percentile_rank
    english = cet.english_proficiency_skills
    reading = cet.reading_comprehension_skills
    science = cet.science_process_skills
    quantitative = cet.quantitative_skills
    abstract = cet.quantitative_skills
    shs_gpa = shs.combined_gpa
    p1 = pt.p1
    p2 = pt.p2
    p3 = pt.p3
    p4 = pt.p4
    p5 = pt.p5
    p6 = pt.p6
    p7 = pt.p7
    p8 = pt.p8
    p9 = pt.p9
    p10 = pt.p10
    p11 = pt.p11
    p12 = pt.p12
    p13 = pt.p13
    p14 = pt.p14
    p15 = pt.p15
    p16 = pt.p16
    p17 = pt.p17
    p18 = pt.p18
    p19 = pt.p19
    p20 = pt.p20
    p21 = pt.p21
    p22 = pt.p22
    p23 = pt.p23
    p24 = pt.p24
    p25 = pt.p25
    p26 = pt.p26
    p27 = pt.p27
    p28 = pt.p28
    p29 = pt.p29
    p30 = pt.p30
    p31 = pt.p31
    p32 = pt.p32
    p33 = pt.p33
    p34 = pt.p34
    p35 = pt.p35
    p36 = pt.p36
    p37 = pt.p37
    p38 = pt.p38
    p39 = pt.p39
    p40 = pt.p40
    ptotal = p1 + p2 + p3 + p4 + p5 + p6 + p7 + p8 + p9 + p10 + p11 + p12 + p13 + p14 + p15 + p16 + p17 + p18 + p19 + p20 + p21 + p22 + p23 + p24 + p25 + p26 + p27 + p28 + p29 + p30 + p31 + p32 + p33 + p34 + p35 + p36 + p37 + p38 + p39 + p40
    s1 = ss.s1
    s2 = ss.s2
    s3 = ss.s3
    s4 = ss.s4
    s5 = ss.s5
    s6 = ss.s6
    s7 = ss.s7
    s8 = ss.s8
    s9 = ss.s9
    s10 = ss.s10
    s11 = ss.s11
    s12 = ss.s12
    s13 = ss.s13
    s14 = ss.s14
    s15 = ss.s15
    s16 = ss.s16
    s17 = ss.s17
    s18 = ss.s18
    s19 = ss.s19
    s20 = ss.s20
    s21 = ss.s21
    s22 = ss.s22
    s23 = ss.s23
    s24 = ss.s24
    stotal = s1 + s2 + s3 + s4 + s5 + s6 + s7 + s8 + s9 + s10 + s11 + s12 + s13 + s14 + s15 + s16 + s17 + s18 + s19 + s20 + s21 + s22 + s23 + s24
    bscs = 1 if application.program.code.lower() == "bscs" else 0
    bsit = 1 if application.program.code.lower() == "bsit" else 0
    female = 1 if application.student.sex.lower() == "female" else 0
    male = 1 if application.student.sex.lower() == "male" else 0
    abm = 1 if shs.strand.lower() == "abm" else 0
    gas = 1 if shs.strand.lower() == "gas" else 0
    humss = 1 if shs.strand.lower() == "humss" else 0
    stem = 1 if shs.strand.lower() == "stem" else 0
    he = 1 if shs.strand.lower() == "homeecon" else 0
    ict = 1 if shs.strand.lower() == "ict" else 0
    arts = 1 if shs.strand.lower() == "artsdesign" or shs.strand.lower() == "agri-fishery" or shs.strand.lower() == "indarts" else 0
    sports = 1 if shs.strand.lower() == "sports" else 0
    class_rank_5 = 1 if shs.class_rank.lower() == "top 5" else 0
    class_rank_10 = 1 if shs.class_rank.lower() == "top 10" else 0
    class_rank_20 = 1 if shs.class_rank.lower() == "top 20" else 0
    class_rank_none = 1 if shs.class_rank.lower() == "none" else 0
    highest_honor = 1 if shs.academic_awards_received.lower() == "highest honor" else 0
    high_honor = 1 if shs.academic_awards_received.lower() == "high honor" else 0
    with_honor = 1 if shs.academic_awards_received.lower() == "with honor" else 0
    awards_none = 1 if shs.academic_awards_received.lower() == "none" else 0
    class_president = 1 if shs.classroom_organization.lower() == "president" else 0
    class_vice_president = 1 if shs.classroom_organization.lower() == "vice president" else 0
    class_secretary = 1 if shs.classroom_organization.lower() == "secretary" else 0
    class_treasurer = 1 if shs.classroom_organization.lower() == "treasurer" else 0
    class_auditor = 1 if shs.classroom_organization.lower() == "auditor" else 0
    class_project_manager = 1 if shs.classroom_organization.lower() == "project manager" else 0
    class_pio = 1 if shs.classroom_organization.lower() == "pio (public information officer)" else 0
    class_peace_officer = 1 if shs.classroom_organization.lower() == "sgt. at arms" else 0
    class_none = 1 if shs.classroom_organization.lower() == "none" else 0
    school_president = 1 if shs.student_supreme_government.lower() == "president" else 0
    school_vice_president = 1 if "vice president" in shs.student_supreme_government.lower() else 0
    school_senator = 1 if shs.student_supreme_government.lower() == "senator" else 0
    school_board = 1 if shs.student_supreme_government.lower() == "board member" else 0
    school_secretary = 1 if shs.student_supreme_government.lower() == "secretary" else 0
    school_treasurer = 1 if shs.student_supreme_government.lower() == "treasurer" else 0
    school_auditor = 1 if shs.student_supreme_government.lower() == "auditor" else 0
    school_project_manager = 1 if shs.student_supreme_government.lower() == "project manager" else 0
    school_pio = 1 if shs.student_supreme_government.lower() == "pio (public information officer)" else 0
    school_peace_officer = 1 if "sgt. at arms" in shs.student_supreme_government.lower() else 0
    school_grade_level_rep = 1 if shs.student_supreme_government.lower() == "grade level representative" else 0
    school_volunteer = 1 if shs.student_supreme_government.lower() == "volunteer" else 0
    school_none = 1 if shs.student_supreme_government.lower() == "none" else 0
    father_college = 1 if econ.father_highest_academic_degree.lower() in ["doctorate degree", "master’s degree", "bachelor’s degree", "associate degree"] else 0
    father_highschool = 1 if econ.father_highest_academic_degree.lower() in ["trade/technical/vocational training", "some college credit, no degree", "high school graduate, diploma or the equivalent", "some high school, no diploma"] else 0
    father_no_school = 1 if econ.father_highest_academic_degree.lower() in ["nursery school to 8th grade", "no schooling completed"] else 0
    father_na = 1 if econ.father_highest_academic_degree.lower() == "not applicable (not known, deceased, etc.)" else 0
    father_fulltime = 1 if econ.father_employment_status.lower() == "employed, working 40 hours or more per week (fulltime)" else 0
    father_part_time = 1 if econ.father_employment_status.lower() == "employed, working 1 to 39 hours or more per week (part-time)" else 0
    father_self_employed = 1 if econ.father_employment_status.lower() == "self-employed (doing business, etc.)" else 0
    father_not_employed = 1 if econ.father_employment_status.lower() in ["not employed, looking for work", "not employed, not looking for work", "retired", "disabled, not able to work"] else 0
    father_emp_na = 1 if econ.father_employment_status.lower() == "not applicable (not known, deceased, etc.)" else 0
    mother_college = 1 if econ.mother_highest_academic_degree.lower() in ["doctorate degree", "master’s degree", "bachelor’s degree", "associate degree"] else 0
    mother_highschool = 1 if econ.mother_highest_academic_degree.lower() in ["trade/technical/vocational training", "some college credit, no degree", "high school graduate, diploma or the equivalent", "some high school, no diploma"] else 0
    mother_no_school = 1 if econ.mother_highest_academic_degree.lower() in ["nursery school to 8th grade", "no schooling completed"] else 0
    mother_na = 1 if econ.mother_highest_academic_degree.lower() == "not applicable (not known, deceased, etc.)" else 0
    mother_fulltime = 1 if econ.mother_employment_status.lower() == "employed, working 40 hours or more per week (fulltime)" else 0
    mother_part_time = 1 if econ.mother_employment_status.lower() == "employed, working 1 to 39 hours or more per week (part-time)" else 0
    mother_self_employed = 1 if econ.mother_employment_status.lower() == "self-employed (doing business, etc.)" else 0
    mother_not_employed = 1 if econ.mother_employment_status.lower() in ["not employed, looking for work", "not employed, not looking for work", "retired", "disabled, not able to work"] else 0
    mother_emp_na = 1 if econ.mother_employment_status.lower() == "not applicable (not known, deceased, etc.)" else 0
    income_100k = 1 if econ.family_income.lower() == "more than p100,000" else 0
    income_50k = 1 if econ.family_income.lower() == "p50,000 to p100,000" else 0
    income_20k = 1 if econ.family_income.lower() == "p20,000 to p50,000" else 0
    income_10k = 1 if econ.family_income.lower() == "p10,000 to p20,000" else 0
    income_below_10k = 1 if econ.family_income.lower() == "below p10,000" else 0
    income_na = 1 if econ.family_income.lower() == "prefer not to say" else 0
    laptop_no = 1 if econ.computer.lower() == "no" else 0
    laptop_yes = 1 if econ.computer.lower() == "yes" else 0
    internet_post_paid = 1 if econ.internet_connection.lower() == "post-paid plan(unlimited data subscription to pldt, globe, smart, sky, etc.)" else 0
    internet_pre_paid = 1 if econ.internet_connection.lower() == "pre-paid plan(limited data subscription)" else 0
    s25_teacher = 1 if ss.s25.lower() == "ask my teachers at school" else 0
    s25_tutor = 1 if ss.s25.lower() == "ask tutors at a private tutoring school" else 0
    s25_friends = 1 if ss.s25.lower() == "ask my friends" else 0
    s25_family = 1 if ss.s25.lower() == "ask my family" else 0
    s25_research = 1 if ss.s25.lower() in ["research from reference books on my own", "research online"] else 0
    s25_leave_it = 1 if ss.s25.lower() == "leave it" else 0
    
    # Prepare the input data
    input_data = [[
        cet_oapr,
        english,
        reading,
        science,
        quantitative,
        abstract,
        shs_gpa,
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        p17,
        p18,
        p19,
        p20,
        p21,
        p22,
        p23,
        p24,
        p25,
        p26,
        p27,
        p28,
        p29,
        p30,
        p31,
        p32,
        p33,
        p34,
        p35,
        p36,
        p37,
        p38,
        p39,
        p40,
        ptotal,
        s1,
        s2,
        s3,
        s4,
        s5,
        s6,
        s7,
        s8,
        s9,
        s10,
        s11,
        s12,
        s13,
        s14,
        s15,
        s16,
        s17,
        s18,
        s19,
        s20,
        s21,
        s22,
        s23,
        s24,
        stotal,
        bscs,
        bsit,
        female,
        male,
        abm,
        gas,
        humss,
        stem,
        he,
        ict,
        arts,
        sports,
        class_rank_5,
        class_rank_10,
        class_rank_20,
        class_rank_none,
        highest_honor,
        high_honor,
        with_honor,
        awards_none,
        class_president,
        class_vice_president,
        class_secretary,
        class_treasurer,
        class_auditor,
        class_project_manager,
        class_pio,
        class_peace_officer,
        class_none,
        school_president,
        school_vice_president,
        school_senator,
        school_board,
        school_secretary,
        school_treasurer,
        school_auditor,
        school_project_manager,
        school_pio,
        school_peace_officer,
        school_grade_level_rep,
        school_volunteer,
        school_none,
        father_college,
        father_highschool,
        father_no_school,
        father_na,
        father_fulltime,
        father_part_time,
        father_self_employed,
        father_not_employed,
        father_emp_na,
        mother_college,
        mother_highschool,
        mother_no_school,
        mother_na,
        mother_fulltime,
        mother_part_time,
        mother_self_employed,
        mother_not_employed,
        mother_emp_na,
        income_100k,
        income_50k,
        income_20k,
        income_10k,
        income_below_10k,
        income_na,
        laptop_no,
        laptop_yes,
        internet_post_paid,
        internet_pre_paid,
        s25_teacher,
        s25_tutor,
        s25_friends,
        s25_family,
        s25_research,
        s25_leave_it
    ]]

    # Make the prediction using the model
    prediction = model.predict(input_data)

    return prediction

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
def view_profile_modal(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    faculty = Faculty.objects.filter(user=request.user).first()

    if not faculty:
        faculty = request.user
            
    context = {
        'faculty': faculty,
    }
    
    rendered_html = render(request, 'admission/partials/user_profile.modal.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@login_required(login_url='/admin/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def update_user_profile(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    faculty = Faculty.objects.filter(user=request.user).first()
    form = UpdateUserProfileForm(request.POST, instance=request.user)
    print(form.is_valid())
    if form.is_valid():
        user = request.user
        user.email = form.cleaned_data['email']
        user.first_name = form.cleaned_data['first_name']
        user.last_name = form.cleaned_data['last_name']
        user.save()
        
        if faculty:
            faculty.first_name = user.first_name
            faculty.last_name = user.last_name
            faculty.email = user.email
            faculty.save()
        
    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)
