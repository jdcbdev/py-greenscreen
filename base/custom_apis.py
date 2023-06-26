from django.conf import settings
from .models import CustomAPI

def load_settings():
    custom_api = CustomAPI.objects.get(name='google-email')
    settings.EMAIL_HOST_USER = custom_api.username
    settings.EMAIL_HOST_PASSWORD = custom_api.password

    custom_api = CustomAPI.objects.get(name='g-recaptcha')
    settings.RECAPTCHA_PUBLIC_KEY = custom_api.key
    settings.RECAPTCHA_PRIVATE_KEY = custom_api.password