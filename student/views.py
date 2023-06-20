from django.shortcuts import render

# Create your views here.

def signin(request):
    page_title = "Sign in"
    context = {
        'page_title': page_title
    }
    return render(request, 'student/signin.html', context)

def signup(request):
    return render(request, 'student/signup.html')

def forgot_password(request):
    return render(request, 'student/forgot_password.html')