from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from .forms import SignUpForm, SignInForm
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout

# Create your views here.

User = get_user_model()

def signin(request):
    page_title = "Sign in"
    error_message = None
    logout(request)
    
    if request.method == 'POST':
        form = SignInForm(request.POST)
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = authenticate(request, username=email, password=password)
            
            if user is not None and user.is_active and user.type == 'student':
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
    page_title = "Sign up"
    context = {
        'page_title': page_title,
    }
    return render(request, 'student/signup-choose.html', context)

def signup_new(request):
    page_title = "Sign up"
    new = True
    success_message = None

    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']
            user = form.save(commit=False)
            user.set_password(password)
            user.type = 'student'
            user.save()
            success_message = 'Account successfully created.'
            form = SignUpForm() #clear form
    else:
        form = SignUpForm()
                
    context = {
        'page_title': page_title,
        'form': form,
        'new': new,
        'success_message': success_message
    }
    
    return render(request, 'student/signup-new.html', context)

def signup_old(request):
    page_title = "Sign up"
    old = True
    context = {
        'page_title': page_title,
        'old': old
    }
    return render(request, 'student/signup-old.html', context)

def forgot_password(request, reset=None):
    page_title = "Forgot Password"
    reset = True
    context = {
        'page_title': page_title,
        'reset': reset
    }
    return render(request, 'student/forgot_password.html', context)

def signout(request):
    page_title = "Sign in"
    context = {
        'page_title': page_title
    }
    logout(request)
    return render(request, 'base/home.html', context)