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
    
    is_personal_info_complete = models.BooleanField(default=False)
    is_cet_complete = models.BooleanField(default=False)
    is_shs_complete = models.BooleanField(default=False)
    is_economic_complete = models.BooleanField(default=False)
    is_personality_complete = models.BooleanField(default=False)
    is_study_complete = models.BooleanField(default=False)
    
    profile_photo = models.ImageField(upload_to="students/", null=True)

class ContactPoint(models.Model):
    student = models.ForeignKey(Student, on_delete=models.CASCADE, null=True)
    contact_email = models.EmailField(max_length=255)
    contact_number = models.CharField(max_length=255)

class PersonalAddress(models.Model):
    student = models.ForeignKey(Student, on_delete=models.CASCADE, null=True)
    house_no = models.CharField(max_length=255, blank=True)
    street_name = models.CharField(max_length=255, blank=True)
    barangay = models.CharField(max_length=255, blank=True)
    city = models.CharField(max_length=255, blank=True)
    province = models.CharField(max_length=255, blank=True)
    region = models.CharField(max_length=255, blank=True)
    
class CollegeEntranceTest(models.Model):
    student = models.ForeignKey(Student, on_delete=models.CASCADE, null=True)
    application_number = models.CharField(max_length=100, unique=True, blank=False)
    rating_period = models.CharField(max_length=100, blank=False)
    overall_percentile_rank = models.DecimalField(max_digits=5, decimal_places=2, blank=False)
    english_proficiency_skills = models.DecimalField(max_digits=5, decimal_places=2, blank=False)
    reading_comprehension_skills = models.DecimalField(max_digits=5, decimal_places=2, blank=False)
    science_process_skills = models.DecimalField(max_digits=5, decimal_places=2, blank=False)
    quantitative_skills = models.DecimalField(max_digits=5, decimal_places=2, blank=False)
    abstract_thinking_skills = models.DecimalField(max_digits=5, decimal_places=2, blank=False)
    report_of_rating = models.ImageField(upload_to='cet_reports/', null=True)

class SchoolBackground(models.Model):
    student = models.ForeignKey(Student, on_delete=models.CASCADE, null=True)
    last_school_attended = models.CharField(max_length=255, blank=True)
    last_course_attended = models.CharField(max_length=255, blank=True)
    
    