from django.db import models

# Create your models here.

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