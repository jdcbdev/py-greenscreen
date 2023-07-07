from django.contrib import admin
from .models import SchoolYear, AdmissionPeriod, Program, Quota, AutoAdmission, Criteria, AdmissionRole, Department, AcademicRank

# Register your models here.

admin.site.register(SchoolYear)
admin.site.register(AdmissionPeriod)
admin.site.register(Program)
admin.site.register(Quota)
admin.site.register(AutoAdmission)
admin.site.register(Criteria)
admin.site.register(AdmissionRole)
admin.site.register(Department)
admin.site.register(AcademicRank)