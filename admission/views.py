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
from .forms import SchoolYearForm, AdmissionPeriodForm, QuotaForm, CriteriaForm, AddFacultyForm, ReturnApplicationForm, InterviewSlotForm
from django.http import JsonResponse
from django.db.models import Prefetch
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils.crypto import get_random_string
from .tasks import send_faculty_email_task
from django.shortcuts import get_object_or_404
from student.models import AdmissionApplication, CollegeEntranceTest, SchoolBackground, ContactPoint, Student, ApplicationStatusLogs, InterviewLogs, PersonalAddress, EconomicStatus, PersonalityTest, StudyHabit
from django.db.models import Exists, OuterRef
from django.utils import timezone
from datetime import datetime
import datetime
from base.models import SHSStrand, ClassRoomOrganization, StudentSupremeGovernment, ClassRank, AcademicAwards, AcademicDegree, EmploymentStatus

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
    context = {
        'page_title': page_title,
        'page_active': page_active,
        'sy': sy,
        'autos': autos,
        'current_year': current_year
    }
    
    return render(request, 'admission/settings.html', context)

@ensure_csrf_cookie
@require_POST
@transaction.atomic
def add_school_year(request):
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

@ensure_csrf_cookie
@require_POST
@transaction.atomic
def add_admission_period(request):
    form = AdmissionPeriodForm(request.POST)
    if form.is_valid():
        # Create or update
        sy = SchoolYear.objects.filter(is_active=True).first()
        period, _ = AdmissionPeriod.objects.get_or_create(school_year=sy)
        
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

@ensure_csrf_cookie
@require_POST
@transaction.atomic
def add_quota(request):
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

@ensure_csrf_cookie
@require_POST
def view_quota(request):
    sy = SchoolYear.objects.filter(is_active=True).first()
    programs = Program.objects.filter(is_active=True).prefetch_related(
        Prefetch(
            'quota_set',
            queryset=Quota.objects.select_related('school_year').filter(school_year=sy),
            to_attr='quotas'
        )
    )
    context = {
        'programs': programs,
    }
    
    rendered_html = render(request, 'admission/partials/view_quota.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@ensure_csrf_cookie
@require_POST
def view_period(request):
    sy = SchoolYear.objects.filter(is_active=True).first()
    period = AdmissionPeriod.objects.filter(school_year=sy).first()
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
    }
    
    rendered_html = render(request, 'admission/partials/view_period.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@ensure_csrf_cookie
@require_POST
@transaction.atomic
def add_auto(request):
    
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
    sy = SchoolYear.objects.filter(is_active=True).first()
    criteria = Program.objects.filter(is_active=True).prefetch_related(
        Prefetch(
            'criteria_set',
            queryset=Criteria.objects.select_related('school_year').filter(school_year=sy),
            to_attr='criterias'
        )
    )
    context = {
        'criteria': criteria,
    }
    
    rendered_html = render(request, 'admission/partials/view_criteria.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@ensure_csrf_cookie
@require_POST
@transaction.atomic
def add_criteria(request):
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
    
    departments = Department.objects.all()
    roles = AdmissionRole.objects.all()
    ranks = AcademicRank.objects.all()

    context = {
        'page_title': page_title,
        'page_active': page_active,
        'current_year': current_year,
        'departments': departments,
        'roles': roles,
        'ranks': ranks,
    }
    
    return render(request, 'admission/faculty.html', context)

@ensure_csrf_cookie
@require_POST
def view_faculty(request):
    faculties = Faculty.objects.all().order_by('last_name', 'first_name')
    departments = Department.objects.all()
    roles = AdmissionRole.objects.all()
    ranks = AcademicRank.objects.all()

    context = {
        'faculties': faculties,
        'departments': departments,
        'roles': roles,
        'ranks': ranks,
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

@ensure_csrf_cookie
@require_POST
@transaction.atomic
def add_faculty(request):
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
        if faculty.admission_role.name == "Admission Officer":
            user.is_superuser = True
        user.save()
        faculty.user = user
        faculty.save()
        
        domain = get_current_site(request).domain
        protocol = 'https' if request.is_secure() else 'http'
        
        send_faculty_email(user.first_name, email, password, domain, protocol)
        
    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@ensure_csrf_cookie
@require_POST
def view_edit_faculty_modal(request):
    faculty = Faculty.objects.get(pk=request.POST.get('faculty_id'))
    departments = Department.objects.all()
    roles = AdmissionRole.objects.all()
    ranks = AcademicRank.objects.all()

    context = {
        'faculty': faculty,
        'departments': departments,
        'roles': roles,
        'ranks': ranks,
    }
    
    rendered_html = render(request, 'admission/partials/edit_faculty.modal.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@ensure_csrf_cookie
@require_POST
@transaction.atomic
def edit_faculty(request):
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
        if faculty.admission_role.name == "Admission Officer":
            user.is_superuser = True
        user.save()
        faculty.user = user
        faculty.save()
        
    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@ensure_csrf_cookie
@require_POST
def view_delete_faculty_modal(request):
    faculty = Faculty.objects.get(pk=request.POST.get('faculty_id'))

    context = {
        'faculty': faculty,
    }
    
    rendered_html = render(request, 'admission/partials/delete_faculty.modal.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@ensure_csrf_cookie
@require_POST
@transaction.atomic
def delete_faculty(request):
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
    pending_counter = AdmissionApplication.objects.filter(school_year=school_year, status='pending').count()
    interview_counter = AdmissionApplication.objects.filter(school_year=school_year, status='verified').count()

    context = {
        'page_title': page_title,
        'page_active': page_active,
        'current_year': current_year,
        'pending_counter': pending_counter,
        'interview_counter': interview_counter,
    }
    
    return render(request, 'admission/application.html', context)

@ensure_csrf_cookie
@require_POST
def all_application(request):
    school_year = SchoolYear.objects.filter(is_active=True).first()
    applications = AdmissionApplication.objects.filter(school_year=school_year).order_by('created_at')

    context = {
        'applications': applications,
    }
    
    rendered_html = render(request, 'admission/applications/all.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@ensure_csrf_cookie
@require_POST
def pending_application(request):
    school_year = SchoolYear.objects.filter(is_active=True).first()
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

    applications = students
    
    context = {
        'applications': applications,
        'programs': programs
    }
    
    rendered_html = render(request, 'admission/applications/pending.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@ensure_csrf_cookie
@require_POST
def view_verify_student_modal(request):
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

@ensure_csrf_cookie
@require_POST
@transaction.atomic
def accept_application(request):
    
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
        InterviewLogs.objects.create(
            application=application,
            interview=slot
        )
        
        return JsonResponse({'message': 'Successful.'})
    
    return JsonResponse({'error': 'Invalid request method'}, status=400)

@ensure_csrf_cookie
@require_POST
@transaction.atomic
def return_application(request):
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
        
    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@ensure_csrf_cookie
@require_POST
def view_interview_slot(request):
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
    
    context = {
        'slots': slots,
    }
    
    rendered_html = render(request, 'admission/partials/view_interview_slot.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@ensure_csrf_cookie
@require_POST
def view_interview_slot_modal(request):
    program = Program.objects.get(pk=request.POST.get('program_id'))

    context = {
        'program': program,
    }
    
    rendered_html = render(request, 'admission/partials/add_interview.modal.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@ensure_csrf_cookie
@require_POST
@transaction.atomic
def add_interview_slot(request):
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

@ensure_csrf_cookie
@require_POST
def interview_application(request):
    school_year = SchoolYear.objects.filter(is_active=True).first()
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
        'programs': programs
    }
    
    rendered_html = render(request, 'admission/applications/interview.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@login_required(login_url='/admin/sign-in/')
def view_student_profile(request, id):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    student = Student.objects.filter(pk=id).first()
    if student.birth_date:
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