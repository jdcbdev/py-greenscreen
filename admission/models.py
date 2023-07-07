from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model

# Create your models here.

User = get_user_model()

class SchoolYear(models.Model):
    start_year = models.IntegerField(null=True)
    end_year = models.IntegerField(null=True)
    concat_year = models.CharField(max_length=100, default='')
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
class AdmissionPeriod(models.Model):
    school_year = models.ForeignKey(SchoolYear, on_delete=models.CASCADE, null=True)
    start_date = models.DateField(null=True)
    end_date = models.DateField(null=True)
    concat_date = models.CharField(max_length=100, default='')
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
class Program(models.Model):
    code = models.CharField(max_length=255, default='', unique=True)
    name = models.CharField(max_length=255, default='')
    duration = models.IntegerField(default=4)
    level = models.CharField(max_length=100, default='bachelor')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class Quota(models.Model):
    school_year = models.ForeignKey(SchoolYear, on_delete=models.CASCADE, null=True)
    program = models.ForeignKey(Program, on_delete=models.CASCADE, null=True)
    number = models.IntegerField(default=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class AutoAdmission(models.Model):
    school_year = models.ForeignKey(SchoolYear, on_delete=models.CASCADE, null=True)
    program = models.ForeignKey(Program, on_delete=models.CASCADE, null=True)
    automate = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class Criteria(models.Model):
    school_year = models.ForeignKey(SchoolYear, on_delete=models.CASCADE, null=True)
    program = models.ForeignKey(Program, on_delete=models.CASCADE, null=True)
    code = models.CharField(max_length=100, default='')
    name = models.CharField(max_length=100, default='')
    score = models.FloatField(default=0)
    weight = models.FloatField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
class AcademicRank(models.Model):
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name

class Department(models.Model):
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name

class AdmissionRole(models.Model):
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name

class Faculty(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.EmailField()
    academic_rank = models.ForeignKey(AcademicRank, on_delete=models.CASCADE)
    department = models.ForeignKey(Department, on_delete=models.CASCADE)
    admission_role = models.ForeignKey(AdmissionRole, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.first_name} {self.last_name}"