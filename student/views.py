from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from .forms import SignUpForm, SignInForm, SignUpOldForm
from django.contrib.auth import authenticate, login, logout
from .models import Student, SchoolBackground
from django.db import transaction
from django.conf import settings

# Create your views here.

User = get_user_model()

def signin(request):
    
    if request.user.is_authenticated and not request.user.is_staff:
        return redirect('home')
        
    page_title = "Sign in"
    error_message = None
    
    if 'google_error' in request.session:
        google_error = request.session['google_error']
        error_message = google_error.get('message')
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
                error_message = 'Invalid email or password.'
    else:
        form = SignInForm()
    
    context = {
        'page_title': page_title,
        'form': form,
        'error_message': error_message,
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
                user.save()

                # Create and save the Student model
                Student.objects.create(
                    account=user,
                    first_name=user.first_name,
                    last_name=user.last_name,
                )
                
                success_message = {
                    'level': 'success',
                    'message': 'Account successfully created.'
                }
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
                user.save()

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

                success_message = {
                    'level': 'success',
                    'message': 'Account successfully created.'
                }
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

def signout(request):
    logout(request)
    return redirect('signin')