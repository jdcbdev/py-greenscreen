from django.db import models
from django.contrib.auth import get_user_model

# Create your models here.

User = get_user_model()

class Student(models.Model):
    account = models.ForeignKey(User, on_delete=models.CASCADE)
    first_name = models.CharField(max_length=255, blank=True, default='')
    middle_name = models.CharField(max_length=255, blank=True, default='')
    last_name = models.CharField(max_length=255, blank=True, default='')
    extension_name = models.CharField(max_length=255, blank=True, default='')
    sex = models.CharField(max_length=255, blank=True, default='')
    birth_date = models.DateField(null=True)
    is_profile_complete = models.BooleanField(default=False)
    student_type = models.CharField(max_length=255, blank=True, default='new')
    student_type_name = models.CharField(max_length=255, blank=True, default='freshman')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # class Meta:
    #     ordering = ['-updated', '-created']

class SchoolBackground(models.Model):
    student = models.ForeignKey(Student, on_delete=models.CASCADE, null=True)
    last_school_attended = models.CharField(max_length=255, blank=True)
    last_course_attended = models.CharField(max_length=255, blank=True)