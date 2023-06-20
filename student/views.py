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
    
    student_param = request.GET.get('student')

    if student_param == 'new':
        template_name = 'student/partials/signup-new.html'
    elif student_param == 'old':
        template_name = 'student/partials/signup-old.html'
    else:
        template_name = 'student/partials/signup-choose.html'

    context = {
        'page_title': page_title,
        'template_name': template_name
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