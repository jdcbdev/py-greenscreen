from django.shortcuts import render
import datetime
from django.shortcuts import redirect
from django.apps import apps
from django.conf import settings
from allauth.socialaccount.models import SocialAccount
from student.views import check_student_exists, add_student_partial, load_student
from student.models import Student

CustomAPI = apps.get_model('base', 'CustomAPI')
custom_api = CustomAPI.objects.get(name='google-email')

settings.EMAIL_HOST_USER = custom_api.username
settings.EMAIL_HOST_PASSWORD = custom_api.password

custom_api = CustomAPI.objects.get(name='g-recaptcha')
settings.RECAPTCHA_PUBLIC_KEY = custom_api.key
settings.RECAPTCHA_PRIVATE_KEY = custom_api.password

def home(request):
    page_title = "Home"
    current_year = datetime.datetime.now().year
    profile = None
        
    if request.user.is_authenticated and request.user.is_superuser:
        return redirect('admin/')
    elif request.user.is_authenticated and request.user.is_staff:
        return redirect('admin/')
    elif request.user.is_authenticated and not request.user.is_staff:
        try:
            extra_data = SocialAccount.objects.get(user=request.user).extra_data
            profile = {
                'first_name': extra_data['given_name'],
                'last_name': extra_data['family_name'],
                'email': extra_data['email'],
                'picture': extra_data['picture']
            }
            if not check_student_exists(extra_data['email']):
                add_student_partial(extra_data['email'])
            
            student = Student.objects.filter(account=request.user).first()
            if not student.is_profile_complete:
                pass
                            
        except:
            # Login not using Google
            print('not google')
            student = Student.objects.filter(account=request.user).first()
            if not student.is_profile_complete:
                pass
        
    context = {
        'page_title': page_title,
        'page_year': current_year,
        'profile': profile
    }
    return render(request, 'base/home.html', context)
