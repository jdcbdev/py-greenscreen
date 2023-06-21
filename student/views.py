from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from .forms import SignUpForm
from django.contrib import messages

# Create your views here.

User = get_user_model()

def signin(request):
    page_title = "Sign in"
    context = {
        'page_title': page_title
    }
    return render(request, 'student/signin.html', context)

def signup_choose(request):
    page_title = "Sign up"
    context = {
        'page_title': page_title
    }
    return render(request, 'student/signup-choose.html', context)

def signup_new(request):
    page_title = "Sign up"
    context = {
        'page_title': page_title
    }
    
    form = SignUpForm(request.POST or None)

    if request.method == 'POST':
        
        if form.is_valid():
            password = form.cleaned_data['password']
            user = form.save(commit=False)
            user.set_password(password)
            user.type = 'student'
            user.save()
            messages.success(request, 'Account successfully created.')
            return redirect('signup-new')
                
    context = {
        'page_title': page_title,
        'form': form,
    }
    
    return render(request, 'student/signup-new.html', context)

def signup_old(request):
    page_title = "Sign up"
    context = {
        'page_title': page_title
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