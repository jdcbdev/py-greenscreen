from django.contrib import admin
from .models import User, CustomAPI, SHSStrand, ClassRoomOrganization, StudentSupremeGovernment, ClassRank, AcademicAwards, AcademicDegree, EmploymentStatus

# Register your models here.

admin.site.register(User)
admin.site.register(CustomAPI)
admin.site.register(SHSStrand)
admin.site.register(ClassRoomOrganization)
admin.site.register(StudentSupremeGovernment)
admin.site.register(ClassRank)
admin.site.register(AcademicAwards)
admin.site.register(AcademicDegree)
admin.site.register(EmploymentStatus)