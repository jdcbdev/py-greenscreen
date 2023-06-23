from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from .forms import SignUpForm, SignInForm, SignUpOldForm
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
from django.utils.html import strip_tags

# Create your views here.

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
    page_title = "Forgot Password"
    reset = True
    context = {
        'page_title': page_title,
        'reset': reset,
        'settings': settings
    }
    return render(request, 'student/forgot_password.html', context)

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