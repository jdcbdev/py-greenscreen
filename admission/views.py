from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth import get_user_model
from base.custom_apis import load_settings
from django.contrib.auth import authenticate, login, logout
from django.db import transaction
from student.forms import SignInForm, ForgotPasswordForm, SetPasswordForm
from django.conf import settings
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
from .models import SchoolYear, AdmissionPeriod, Program, Quota, AutoAdmission, Criteria
from .forms import SchoolYearForm, AdmissionPeriodForm, QuotaForm, CriteriaForm
import datetime
from django.http import JsonResponse
from django.db.models import Prefetch

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
def settings(request):
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


