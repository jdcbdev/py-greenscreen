from django.shortcuts import render
import datetime
from django.shortcuts import redirect
from django.apps import apps
from django.conf import settings

# Create your views here.

CustomAPI = apps.get_model('base', 'CustomAPI')
custom_api = CustomAPI.objects.get(name='sandbox.smtp.mailtrap.io')

settings.EMAIL_HOST_USER = custom_api.username
settings.EMAIL_HOST_PASSWORD = custom_api.password

custom_api = CustomAPI.objects.get(name='g-recaptcha')
settings.G_RECAPTCHA = custom_api.key

def home(request):
    if request.user.is_authenticated and request.user.is_superuser:
        return redirect('admin/')
    else:
        page_title = "Home"
        current_year = datetime.datetime.now().year
        context = {
            'page_title': page_title,
            'page_year': current_year
        }
        return render(request, 'base/home.html', context)
