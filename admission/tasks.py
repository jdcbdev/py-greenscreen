from celery import shared_task
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.safestring import mark_safe
from base.custom_apis import load_settings

load_settings()

@shared_task
def send_faculty_email_task(first_name, to_email, password, domain, protocol):
    
    mail_subject = "New Faculty Account - GreenScreen Admission System"

    html_message  = mark_safe(render_to_string("email_add_faculty.html", {
        'user': first_name,
        'domain': domain,
        'email': to_email,
        'password': password,
        "protocol": protocol
    }))
    
    from_email = settings.DEFAULT_FROM_EMAIL
    email = EmailMessage(mail_subject, html_message, from_email, to=[to_email])
    email.content_subtype = 'html'
    email.send()