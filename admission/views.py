from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from base.custom_apis import load_settings
from django.contrib.auth import authenticate, login, logout
from django.db import transaction
from student.forms import SignInForm, ForgotPasswordForm

# Create your views here.

load_settings()

User = get_user_model()

def signin(request):
    
    if request.user.is_authenticated:
        return redirect('home')
        
    page_title = "Log in"
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
                return redirect('admission')
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

def admission(request):
    return render(request, 'admission/dashboard.html')
