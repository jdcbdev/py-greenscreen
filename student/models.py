from django.db import models
from django.contrib.auth import get_user_model
from admission.models import Program, SchoolYear

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
    
    is_personal_info_complete = models.BooleanField(default=False)
    is_cet_complete = models.BooleanField(default=False)
    is_shs_complete = models.BooleanField(default=False)
    is_economic_complete = models.BooleanField(default=False)
    is_personality_complete = models.BooleanField(default=False)
    is_study_complete = models.BooleanField(default=False)
    
    profile_photo = models.ImageField(upload_to="students/", null=True)
    identification_card = models.ImageField(upload_to="identification/", null=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

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
    last_school_attended = models.CharField(max_length=255, blank=True, default='')
    last_course_attended = models.CharField(max_length=255, blank=True, default='')
    strand = models.CharField(max_length=150, blank=True, default='')
    high_school_name = models.CharField(max_length=255, blank=True, default='')
    class_rank = models.CharField(max_length=100, blank=True, default='')
    academic_awards_received = models.CharField(max_length=150, blank=True, default='')
    classroom_organization = models.CharField(max_length=150, blank=True, default='')
    student_supreme_government = models.CharField(max_length=150, blank=True, default='')
    gpa_first_semester = models.FloatField(blank=True, default=0)
    gpa_second_semester = models.FloatField(blank=True, default=0)
    photo_grade = models.ImageField(upload_to='shs_card/', null=True)
    
class EconomicStatus(models.Model):
    student = models.ForeignKey(Student, on_delete=models.CASCADE, null=True)
    father_highest_academic_degree = models.CharField(max_length=100)
    father_employment_status = models.CharField(max_length=100)
    father_current_occupation = models.CharField(max_length=255)
    mother_highest_academic_degree = models.CharField(max_length=100)
    mother_employment_status = models.CharField(max_length=100)
    mother_current_occupation = models.CharField(max_length=255)
    family_income = models.CharField(max_length=100, default='')
    computer = models.CharField(max_length=100)
    internet_connection = models.CharField(max_length=100)

class PersonalityTest(models.Model):
    student = models.ForeignKey(Student, on_delete=models.CASCADE, null=True)
    p1 = models.IntegerField(null=True)
    p2 = models.IntegerField(null=True)
    p3 = models.IntegerField(null=True)
    p4 = models.IntegerField(null=True)
    p5 = models.IntegerField(null=True)
    p6 = models.IntegerField(null=True)
    p7 = models.IntegerField(null=True)
    p8 = models.IntegerField(null=True)
    p9 = models.IntegerField(null=True)
    p10 = models.IntegerField(null=True)
    p11 = models.IntegerField(null=True)
    p12 = models.IntegerField(null=True)
    p13 = models.IntegerField(null=True)
    p14 = models.IntegerField(null=True)
    p15 = models.IntegerField(null=True)
    p16 = models.IntegerField(null=True)
    p17 = models.IntegerField(null=True)
    p18 = models.IntegerField(null=True)
    p19 = models.IntegerField(null=True)
    p20 = models.IntegerField(null=True)
    p21 = models.IntegerField(null=True)
    p22 = models.IntegerField(null=True)
    p23 = models.IntegerField(null=True)
    p24 = models.IntegerField(null=True)
    p25 = models.IntegerField(null=True)
    p26 = models.IntegerField(null=True)
    p27 = models.IntegerField(null=True)
    p28 = models.IntegerField(null=True)
    p29 = models.IntegerField(null=True)
    p30 = models.IntegerField(null=True)
    p31 = models.IntegerField(null=True)
    p32 = models.IntegerField(null=True)
    p33 = models.IntegerField(null=True)
    p34 = models.IntegerField(null=True)
    p35 = models.IntegerField(null=True)
    p36 = models.IntegerField(null=True)
    p37 = models.IntegerField(null=True)
    p38 = models.IntegerField(null=True)
    p39 = models.IntegerField(null=True)
    p40 = models.IntegerField(null=True)

class StudyHabit(models.Model):
    student = models.ForeignKey(Student, on_delete=models.CASCADE, null=True)
    s1 = models.IntegerField(null=True)
    s2 = models.IntegerField(null=True)
    s3 = models.IntegerField(null=True)
    s4 = models.IntegerField(null=True)
    s5 = models.IntegerField(null=True)
    s6 = models.IntegerField(null=True)
    s7 = models.IntegerField(null=True)
    s8 = models.IntegerField(null=True)
    s9 = models.IntegerField(null=True)
    s10 = models.IntegerField(null=True)
    s11 = models.IntegerField(null=True)
    s12 = models.IntegerField(null=True)
    s13 = models.IntegerField(null=True)
    s14 = models.IntegerField(null=True)
    s15 = models.IntegerField(null=True)
    s16 = models.IntegerField(null=True)
    s17 = models.IntegerField(null=True)
    s18 = models.IntegerField(null=True)
    s19 = models.IntegerField(null=True)
    s20 = models.IntegerField(null=True)
    s21 = models.IntegerField(null=True)
    s22 = models.IntegerField(null=True)
    s23 = models.IntegerField(null=True)
    s24 = models.IntegerField(null=True)
    s25 = models.CharField(max_length=255, null=True)

class AdmissionApplication(models.Model):
    student = models.ForeignKey(Student, on_delete=models.CASCADE)
    program = models.ForeignKey(Program, on_delete=models.CASCADE)
    school_year = models.ForeignKey(SchoolYear, on_delete=models.CASCADE)
    status = models.CharField(max_length=255, default='pending')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)