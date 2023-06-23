from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from .forms import SignUpForm, SignInForm, SignUpOldForm, ForgotPasswordForm, SetPasswordForm
from django.contrib.auth import authenticate, login, logout
from .models import Student, SchoolBackground
from django.db import transaction
from django.conf import settings
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from .tokens import account_activation_token
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.contrib import messages
from django.utils.safestring import mark_safe
from django.db.models.query_utils import Q
from django.urls import reverse
from django.apps import apps
import requests

from django.conf import settings

CustomAPI = apps.get_model('base', 'CustomAPI')
custom_api = CustomAPI.objects.get(name='google-email')

settings.EMAIL_HOST_USER = custom_api.username
settings.EMAIL_HOST_PASSWORD = custom_api.password

custom_api = CustomAPI.objects.get(name='g-recaptcha')
settings.RECAPTCHA_PUBLIC_KEY = custom_api.key
settings.RECAPTCHA_PRIVATE_KEY = custom_api.password

User = get_user_model()

def signin(request):
    
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
        
    page_title = "Sign in"
    success_message = None
    if 'google_error' in request.session:
        google_error = request.session['google_error']
        success_message = {
            'level': google_error.get('level'),
            'message': google_error.get('message')
        }
        del request.session['google_error']

    request.session['link'] = 'signin'
    
    if request.method == 'POST':
        form = SignInForm(request.POST)
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = authenticate(request, username=email, password=password)
            
            if user is not None and user.is_active and not user.is_staff:
                login(request, user)
                return redirect('home')
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
    return render(request, 'student/signin.html', context)

def signup_choose(request):
    
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    page_title = "Sign up"
    context = {
        'page_title': page_title,
    }
    return render(request, 'student/signup-choose.html', context)

@transaction.atomic
def signup_new(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')

    page_title = "Sign up"
    new = True
    success_message = None

    if 'google_error' in request.session:
        google_error = request.session['google_error']
        success_message = {
            'level': 'danger',
            'message': google_error.get('message')
        }
        del request.session['google_error']
        
    request.session['link'] = 'signup-new'

    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            response=grecaptcha_verify(request)
            if response['success']:
                try:
                    password = form.cleaned_data['password']
                    user = form.save(commit=False)
                    user.set_password(password)
                    user.is_active=False
                    user.save()
                    success_message = activate_email(request, user, form.cleaned_data.get('email'))

                    # Create and save the Student model
                    Student.objects.create(
                        account=user,
                        first_name=user.first_name,
                        last_name=user.last_name,
                    )
                    
                    form = SignUpForm()  # clear form

                except Exception as e:
                    # Handle the exception and rollback the transaction
                    transaction.set_rollback(True)
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
        form = SignUpForm()

    context = {
        'page_title': page_title,
        'form': form,
        'new': new,
        'success_message': success_message,
        'settings': settings
    }

    return render(request, 'student/signup-new.html', context)

@transaction.atomic
def signup_old(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')

    page_title = "Sign up"
    old = True
    success_message = None

    if 'google_error' in request.session:
        google_error = request.session['google_error']
        success_message = {
            'level': 'danger',
            'message': google_error.get('message')
        }
        del request.session['google_error']
        
    request.session['link'] = 'signup-old'
    
    if request.method == 'POST':
        form = SignUpOldForm(request.POST)
        if form.is_valid():
            response=grecaptcha_verify(request)
            if response['success']:
                try:
                    password = form.cleaned_data['password']
                    user = form.save(commit=False)
                    user.set_password(password)
                    user.is_active=False
                    user.save()
                    success_message = activate_email(request, user, form.cleaned_data.get('email'))

                    # Create and save the Student model
                    student = Student.objects.create(
                        account=user,
                        first_name=user.first_name,
                        last_name=user.last_name,
                        student_type='old',
                        student_type_name=form.cleaned_data['student_type_name'],
                    )

                    SchoolBackground.objects.create(
                        student=student,
                        last_school_attended=form.cleaned_data['last_school_attended'],
                        last_course_attended=form.cleaned_data['last_course_attended'],
                    )

                    form = SignUpOldForm()  # clear form

                except Exception as e:
                    # Handle the exception and rollback the transaction
                    transaction.set_rollback(True)
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
        form = SignUpOldForm()

    context = {
        'page_title': page_title,
        'form': form,
        'old': old,
        'success_message': success_message,
        'settings': settings
    }

    return render(request, 'student/signup-old.html', context)

def social_signup(request):
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
    
    request.session['google_error'] = {
        'level': 'danger',
        'message': 'Something wrong here, it may be that you already have an account. Sign in using your registered email and password.'
    }
    
    return redirect(request.session['link'])

def forgot_password(request, reset=None):
    if request.user.is_authenticated and not request.user.is_staff:
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
                associated_user = get_user_model().objects.filter(Q(email=user_email, is_staff=False)).first()
                if associated_user:
                    if associated_user.is_active:
                        mail_subject = "Password Reset Request - GreenScreen Admission System"
                        domain = get_current_site(request).domain
                        uid = urlsafe_base64_encode(force_bytes(associated_user.pk))
                        token = account_activation_token.make_token(associated_user)
                        protocol = 'https' if request.is_secure() else 'http'

                        html_message  = mark_safe(render_to_string("email_forgot_password.html", {
                            'user': associated_user.first_name,
                            'domain': domain,
                            'uid': uid,
                            'token': token,
                            "protocol": protocol
                        }))
                        
                        email = EmailMessage(mail_subject, html_message, to=[user_email])
                        email.content_subtype = 'html'
                        
                        if email.send():
                            msg = mark_safe(f'<b>Password reset sent!</b> We have emailed you instructions for setting your password.')
                            success_message = {
                                'level': 'success',
                                'message': msg
                            }
                            form = SignUpOldForm()
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
                        'message': 'Email not found. Please make sure you have entered the email address you signed up with.'
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

    return render(request, 'student/forgot_password.html', context)

def password_reset(request, uidb64, token):
    page_title = "Password Reset"
    success_message = None
    
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except:
        user = None

    form = SetPasswordForm()
    
    if user is not None and account_activation_token.check_token(user, token):
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
                        
                        account_activation_token.make_token(user)
                        
                        success_message = {
                            'level': 'success',
                            'message': mark_safe('Your password has been set. You may go ahead and <a class="green" href="{}">Sign in</a> now.'.format(reverse('signin')))
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

    return render(request, 'student/password_reset_confirm.html', context)

def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except:
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()

        request.session['google_error'] = {
            'level': 'success',
            'message': 'Thank you for your email confirmation. Now you can sign in to your account.'
        }
    
    else:
        request.session['google_error'] = {
            'level': 'danger',
            'message': 'Activation link is invalid or the email is already verified.'
        }

    return redirect('signin')

def activate_email(request, user, to_email):
    mail_subject = "Email Verification - GreenScreen Admission System"
    domain = get_current_site(request).domain
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = account_activation_token.make_token(user)
    protocol = 'https' if request.is_secure() else 'http'

    html_message  = mark_safe(render_to_string("email_activate_account.html", {
        'user': user.first_name,
        'domain': domain,
        'uid': uid,
        'token': token,
        "protocol": protocol
    }))
    
    email = EmailMessage(mail_subject, html_message, to=[to_email])
    email.content_subtype = 'html'
    
    if email.send():
        msg = mark_safe(f'Hi <b>{user.first_name}</b>, please go to your email <b>{to_email}</b> inbox and click on \
                Verify Email button to confirm and complete the sign up. <b>Note:</b> Check your spam folder.')
        success_message = {
            'level': 'success',
            'message': msg
        }
    else:
        success_message = {
            'level': 'danger',
            'message': f'Problem sending email to {to_email}, check if you typed it correctly.'
        }
        
    return success_message

def signout(request):
    logout(request)
    return redirect('signin')

def grecaptcha_verify(request):
    recaptcha_response = request.POST.get('g-recaptcha-response')
    data = {
        'secret': settings.RECAPTCHA_PRIVATE_KEY,
        'response': recaptcha_response
    }
    r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
    result = r.json()
    
    return result
