from django.shortcuts import render

# Create your views here.

def signin(request):
    page_title = "Sign in"
    context = {
        'page_title': page_title
    }
    return render(request, 'student/signin.html', context)

def signup(request):
    page_title = "Sign up"
    context = {
        'page_title': page_title
    }
    return render(request, 'student/signup.html', context)

def forgot_password(request, reset=None):
    page_title = "Forgot Password"
    reset = True
    context = {
        'page_title': page_title,
        'reset': reset
    }
    return render(request, 'student/forgot_password.html', context)