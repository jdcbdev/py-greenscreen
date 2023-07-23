from django.contrib import admin
from .models import Student, AdmissionApplication

# Register your models here.

admin.site.register(Student)
admin.site.register(AdmissionApplication)