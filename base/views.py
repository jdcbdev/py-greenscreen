from django.shortcuts import render
import datetime
from django.shortcuts import redirect
from allauth.socialaccount.models import SocialAccount
from student.views import check_student_exists, add_student_partial
from student.models import Student, AdmissionApplication
from ph_geography.models import Region, Province, Municipality, Barangay
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_POST
from .custom_apis import load_settings
from admission.models import SchoolYear

load_settings()

def home(request):
    page_title = "Home"
    current_year = datetime.datetime.now().year
    profile = None
    student = None
    
    if request.user.is_authenticated and request.user.is_staff:
        return redirect('dashboard')
    elif request.user.is_authenticated and not request.user.is_staff:
        try:
            extra_data = SocialAccount.objects.get(user=request.user).extra_data
            profile = {
                'first_name': extra_data['given_name'],
                'last_name': extra_data['family_name'],
                'email': extra_data['email'],
                'picture': extra_data['picture']
            }
            if not check_student_exists(extra_data['email']):
                # choose type
                if 'link' in request.session:
                    if request.session['link'] == 'signup-new':
                        request.session['student_type'] = 'new'
                        request.session['student_type_name'] = 'freshman'
                        add_student_partial(request, extra_data['email'])
                    elif request.session['link'] == 'signup-old':
                        request.session['student_type'] = 'old'
                        request.session['student_type_name'] = ''
                        add_student_partial(request, extra_data['email'])
                    else:
                        request.session['student_type'] = ''
                        request.session['student_type_name'] = ''
                        add_student_partial(request, extra_data['email'])
            
            student = Student.objects.filter(account=request.user).first()
            if not student.is_profile_complete:
                request.session['is_profile_complete'] = 'no'
                return redirect('complete_profile')
            else:
                request.session['is_profile_complete'] = 'yes'
                                
        except:
            # Login not using Google
            print('not google')
            student = Student.objects.filter(account=request.user).first()
            if not student.is_profile_complete:
                request.session['is_profile_complete'] = 'no'
                return redirect('complete_profile')
            else:
                request.session['is_profile_complete'] = 'yes'
    
    school_year = SchoolYear.objects.filter(is_active=True).first()
    application = AdmissionApplication.objects.filter(student=student, school_year=school_year).first()
    context = {
        'page_title': page_title,
        'page_year': current_year,
        'application': application,
        'profile': profile
    }
    return render(request, 'base/home.html', context)

@ensure_csrf_cookie
@require_POST
def ph_address(request):
    if request.method == 'POST':
        if request.POST.get('action') == 'province':
            filter_value = request.POST.get('filter')
            region = Region.objects.get(code=filter_value)
            provinces = Province.objects.filter(region=region).order_by('name').values('code', 'name')
            return JsonResponse(list(provinces), safe=False)
        elif request.POST.get('action') == 'city':
            filter_value = request.POST.get('filter')
            province = Province.objects.get(code=filter_value)
            cities = Municipality.objects.filter(province=province).order_by('name').values('code', 'name')
            return JsonResponse(list(cities), safe=False)
        elif request.POST.get('action') == 'barangay':
            filter_value = request.POST.get('filter')
            city = Municipality.objects.get(code=filter_value)
            brgy = Barangay.objects.filter(municipality=city).order_by('name').values('code', 'name')
            return JsonResponse(list(brgy), safe=False)
        else:
            region = Region.objects.values('code', 'name').order_by('name')
            return JsonResponse(list(region), safe=False)
    else:
        return redirect('home')

