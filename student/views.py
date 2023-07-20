from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from .forms import SignUpForm, SignInForm, SignUpOldForm, ForgotPasswordForm, SetPasswordForm, PersonalInfoForm, CollegeEntranceTestForm, SchoolBackgroundForm, EconomicStatusForm, PersonalityTestForm1, PersonalityTestForm2, PersonalityTestForm3, PersonalityTestForm4
from .forms import StudyHabitForm1, StudyHabitForm2, StudyHabitForm3, WithdrawApplicationForm
from django.contrib.auth import authenticate, login, logout
from .models import Student, SchoolBackground, ContactPoint, PersonalAddress, CollegeEntranceTest, EconomicStatus, PersonalityTest, StudyHabit, AdmissionApplication, ApplicationStatusLogs, InterviewLogs
from base.models import SHSStrand, ClassRoomOrganization, StudentSupremeGovernment, ClassRank, AcademicAwards, AcademicDegree, EmploymentStatus
from django.db import transaction
from django.conf import settings
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from .tokens import account_activation_token, reset_password_token
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.contrib import messages
from django.utils.safestring import mark_safe
from django.db.models.query_utils import Q
from django.urls import reverse
import requests
from base.custom_apis import load_settings
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from datetime import date
from admission.models import Program, SchoolYear, AdmissionPeriod, DocumentaryRequirement, InterviewSlot, Criteria, Quota, Faculty
from django.http import HttpResponse
from decimal import Decimal
from django.core.mail import EmailMultiAlternatives
from django.utils.html import strip_tags

load_settings()

User = get_user_model()

def signin(request):
    
    if request.user.is_authenticated:
        return redirect('home')
        
    page_title = "Sign in"
    page_url = request.build_absolute_uri()
    success_message = None
    if 'google_error' in request.session:
        google_error = request.session['google_error']
        success_message = {
            'level': google_error.get('level'),
            'message': google_error.get('message')
        }
        del request.session['google_error']

    request.session['link'] = 'signin'
    
    if request.method == 'POST':
        form = SignInForm(request.POST)
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = authenticate(request, username=email, password=password)
            
            if user is not None and user.is_active and not user.is_staff:
                login(request, user)
                return redirect('home')
            else:
                success_message = {
                    'level': 'danger',
                    'message': 'Invalid email or password.'
                }
    else:
        form = SignInForm()
    
    context = {
        'page_title': page_title,
        'form': form,
        'success_message': success_message,
        'page_url': page_url,
    }
    return render(request, 'student/signin.html', context)

def signup_choose(request):
    
    if request.user.is_authenticated:
        return redirect('home')
    
    page_title = "Sign up"
    page_url = request.build_absolute_uri()
    context = {
        'page_title': page_title,
        'page_url': page_url,
    }
    return render(request, 'student/signup-choose.html', context)

@transaction.atomic
def signup_new(request):
    if request.user.is_authenticated:
        return redirect('home')

    page_title = "Sign up"
    page_url = request.build_absolute_uri()
    new = True
    success_message = None

    if 'google_error' in request.session:
        google_error = request.session['google_error']
        success_message = {
            'level': 'danger',
            'message': google_error.get('message')
        }
        del request.session['google_error']
        
    request.session['link'] = 'signup-new'

    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            response=grecaptcha_verify(request)
            if response['success']:
                try:
                    password = form.cleaned_data['password']
                    user = form.save(commit=False)
                    user.set_password(password)
                    user.is_active=False
                    user.save()
                    success_message = activate_email(request, user, form.cleaned_data.get('email'))

                    # Create and save the Student model
                    Student.objects.create(
                        account=user,
                        first_name=user.first_name,
                        last_name=user.last_name,
                    )
                    
                    form = SignUpForm()  # clear form

                except Exception as e:
                    # Handle the exception and rollback the transaction
                    transaction.set_rollback(True)
                    success_message = {
                        'level': 'danger',
                        'message': str(e)
                    }
            else:
                success_message = {
                        'level': 'danger',
                        'message': 'Invalid reCAPTCHA. Please try again.'
                    }

    else:
        form = SignUpForm()

    context = {
        'page_title': page_title,
        'form': form,
        'new': new,
        'success_message': success_message,
        'settings': settings,
        'page_url': page_url,
    }

    return render(request, 'student/signup-new.html', context)

@transaction.atomic
def signup_old(request):
    if request.user.is_authenticated:
        return redirect('home')

    page_title = "Sign up"
    page_url = request.build_absolute_uri()
    old = True
    success_message = None

    if 'google_error' in request.session:
        google_error = request.session['google_error']
        success_message = {
            'level': 'danger',
            'message': google_error.get('message')
        }
        del request.session['google_error']
        
    request.session['link'] = 'signup-old'
    
    if request.method == 'POST':
        form = SignUpOldForm(request.POST)
        if form.is_valid():
            response=grecaptcha_verify(request)
            if response['success']:
                try:
                    password = form.cleaned_data['password']
                    user = form.save(commit=False)
                    user.set_password(password)
                    user.is_active=False
                    user.save()
                    success_message = activate_email(request, user, form.cleaned_data.get('email'))

                    # Create and save the Student model
                    student = Student.objects.create(
                        account=user,
                        first_name=user.first_name,
                        last_name=user.last_name,
                        student_type='old',
                        student_type_name=form.cleaned_data['student_type_name'],
                    )

                    SchoolBackground.objects.create(
                        student=student,
                        last_school_attended=form.cleaned_data['last_school_attended'],
                        last_course_attended=form.cleaned_data['last_course_attended'],
                    )

                    form = SignUpOldForm()  # clear form

                except Exception as e:
                    # Handle the exception and rollback the transaction
                    transaction.set_rollback(True)
                    success_message = {
                        'level': 'danger',
                        'message': str(e)
                    }
            else:
                success_message = {
                        'level': 'danger',
                        'message': 'Invalid reCAPTCHA. Please try again.'
                    }

    else:
        form = SignUpOldForm()

    context = {
        'page_title': page_title,
        'form': form,
        'old': old,
        'success_message': success_message,
        'settings': settings,
        'page_url': page_url,
    }

    return render(request, 'student/signup-old.html', context)

def social_signup(request):
    if request.user.is_authenticated:
        return redirect('home')
    
    request.session['google_error'] = {
        'level': 'danger',
        'message': 'Something wrong here, it may be that you already have an account. Sign in using your registered email and password.'
    }
    
    return redirect(request.session['link'])

def forgot_password(request, reset=None):
    if request.user.is_authenticated:
        return redirect('home')
    
    page_title = "Forgot Password"
    page_url = request.build_absolute_uri()
    reset = True
    success_message = None
    
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            
            response=grecaptcha_verify(request)
            if response['success']:
        
                user_email = form.cleaned_data['email']
                associated_user = get_user_model().objects.filter(Q(email=user_email, is_staff=False)).first()
                if associated_user:
                    if associated_user.is_active:
                        mail_subject = "Password Reset Request - GreenScreen Admission System"
                        domain = get_current_site(request).domain
                        uid = urlsafe_base64_encode(force_bytes(associated_user.pk))
                        token = reset_password_token.make_token(associated_user)
                        protocol = 'https' if request.is_secure() else 'http'

                        html_message  = mark_safe(render_to_string("email_forgot_password.html", {
                            'user': associated_user.first_name,
                            'domain': domain,
                            'uid': uid,
                            'token': token,
                            "protocol": protocol
                        }))
                        
                        from_email = settings.DEFAULT_FROM_EMAIL
                        email = EmailMessage(mail_subject, html_message, from_email, to=[user_email])
                        email.content_subtype = 'html'
                        
                        if email.send():
                            msg = mark_safe(f'<b>Password reset sent!</b> We have emailed you instructions for setting your password.')
                            success_message = {
                                'level': 'success',
                                'message': msg
                            }
                            form = ForgotPasswordForm()
                        else:
                            success_message = {
                                'level': 'danger',
                                'message': mark_safe('Problem sending reset password email, <b>SERVER PROBLEM</b>')
                            }
                            
                    else:
                        success_message = {
                            'level': 'danger',
                            'message': 'Account associated with this email is not yet verified.'
                        }
                            
                else:
                    success_message = {
                        'level': 'danger',
                        'message': 'Email not found. Please make sure you have entered the email address you signed up with.'
                    }
            else:
                success_message = {
                        'level': 'danger',
                        'message': 'Invalid reCAPTCHA. Please try again.'
                    }
                
        else:
            form = ForgotPasswordForm()
    else:
        form = ForgotPasswordForm()

    context = {
        'page_title': page_title,
        'form': form,
        'reset': reset,
        'success_message': success_message,
        'settings': settings,
        'page_url': page_url,
    }

    return render(request, 'student/forgot_password.html', context)

def password_reset(request, uidb64, token):
    if request.user.is_authenticated:
        return redirect('home')
    
    page_title = "Password Reset"
    page_url = request.build_absolute_uri()
    success_message = None
    
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except:
        user = None

    if not user:
        return redirect('signin')
    
    form = SetPasswordForm()
    
    if user is not None and reset_password_token.check_token(user, token):
        if request.method == 'POST':
            form = SetPasswordForm(request.POST)
            if form.is_valid():
                response=grecaptcha_verify(request)
                
                if response['success']:
                    try:
                        password = form.cleaned_data['password']
                        user.set_password(password)
                        user.save()
                        
                        form = SetPasswordForm()  # clear form
                        
                        success_message = {
                            'level': 'success',
                            'message': mark_safe('Your password has been set. You may go ahead and <a class="green" href="{}">Sign in</a> now.'.format(reverse('signin')))
                        }

                    except Exception as e:
                        success_message = {
                            'level': 'danger',
                            'message': str(e)
                        }
                else:
                    success_message = {
                        'level': 'danger',
                        'message': 'Invalid reCAPTCHA. Please try again.'
                    }

        else:
            form = SetPasswordForm()
            
    else:
        success_message = {
            'level': 'danger',
            'message': mark_safe('Link has expired. Try requesting it again.')
        }

    context = {
        'page_title': page_title,
        'form': form,
        'success_message': success_message,
        'settings': settings,
        'page_url': page_url,
    }

    return render(request, 'student/password_reset_confirm.html', context)

def activate(request, uidb64, token):
    if request.user.is_authenticated:
        return redirect('home')
    
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except:
        user = None
    
    if not user:
        return redirect('signin')

    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()

        request.session['google_error'] = {
            'level': 'success',
            'message': 'Thank you for your email confirmation. Now you can sign in to your account.'
        }
    
    else:
        request.session['google_error'] = {
            'level': 'danger',
            'message': 'Activation link is invalid or the email is already verified.'
        }

    return redirect('signin')

def activate_email(request, user, to_email):
    if request.user.is_authenticated:
        return redirect('home')
    
    mail_subject = "Email Verification - GreenScreen Admission System"
    domain = get_current_site(request).domain
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = account_activation_token.make_token(user)
    protocol = 'https' if request.is_secure() else 'http'

    html_message  = mark_safe(render_to_string("email_activate_account.html", {
        'user': user.first_name,
        'domain': domain,
        'uid': uid,
        'token': token,
        "protocol": protocol
    }))
    
    from_email = settings.DEFAULT_FROM_EMAIL
    email = EmailMessage(mail_subject, html_message, from_email, to=[to_email])
    email.content_subtype = 'html'
    
    if email.send():
        msg = mark_safe(f'Hi <b>{user.first_name}</b>, please go to your email <b>{to_email}</b> inbox and click on \
                Verify Email button to confirm and complete the sign up. <b>Note:</b> Check your spam folder.')
        success_message = {
            'level': 'success',
            'message': msg
        }
    else:
        success_message = {
            'level': 'danger',
            'message': f'Problem sending email to {to_email}, check if you typed it correctly.'
        }
        
    return success_message

def signout(request):
    request.session.flush()
    logout(request)
    return redirect('signin')

def grecaptcha_verify(request):
    recaptcha_response = request.POST.get('g-recaptcha-response')
    data = {
        'secret': settings.RECAPTCHA_PRIVATE_KEY,
        'response': recaptcha_response
    }
    r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
    result = r.json()
    
    return result

def check_student_exists(email):
    user = User.objects.filter(email=email).first()
    if user:
        student = Student.objects.filter(account=user).first()
        if student:
            return True
    return False

def add_student_partial(request, email):
    user = User.objects.filter(email=email).first()
    if user:
        student = Student.objects.filter(account=user).first()
        if not student:
            Student.objects.create(
                account=user,
                first_name=user.first_name,
                last_name=user.last_name,
                student_type=request.session['student_type'],
                student_type_name=request.session['student_type_name'],
            )
            return True
        
    return False   

@login_required(login_url='/student/sign-in/')
def complete_profile(request):
    if request.user.is_authenticated and not request.user.is_staff and Student.objects.filter(account=request.user, is_profile_complete=True).exists():
        return redirect('home')
    elif request.user.is_authenticated and request.user.is_staff:
        return redirect('home')
    
    student = Student.objects.filter(account=request.user).first()
    if student.birth_date:
        student_birth_date = student.birth_date
        formatted_date = student_birth_date.strftime('%Y-%m-%d')
        student.birth_date = formatted_date
    contact = ContactPoint.objects.filter(student=student).first()
    address = PersonalAddress.objects.filter(student=student).first()
    cet = CollegeEntranceTest.objects.filter(student=student).first()
    strands = SHSStrand.objects.all()
    class_positions = ClassRoomOrganization.objects.all()
    ssg = StudentSupremeGovernment.objects.all()
    ranks = ClassRank.objects.all()
    awards = AcademicAwards.objects.all()
    school = SchoolBackground.objects.filter(student=student).first()
    degrees = AcademicDegree.objects.all()
    employment = EmploymentStatus.objects.all()
    economic = EconomicStatus.objects.filter(student=student).first()
    pt = PersonalityTest.objects.filter(student=student).first()
    sh = StudyHabit.objects.filter(student=student).first()
    
    page_title = 'Complete Profile'
    page_url = request.build_absolute_uri()
    context = {
        'page_title': page_title,
        'student': student,
        'contact': contact,
        'address': address,
        'cet': cet,
        'strands': strands,
        'class_positions': class_positions,
        'ssg': ssg,
        'ranks': ranks,
        'awards': awards,
        'school': school,
        'degrees': degrees,
        'employment': employment,
        'economic': economic,
        'pt': pt,
        'sh': sh,
        'settings': settings,
        'page_url': page_url,
    }
    return render(request, 'student/profile/main.html', context)

@login_required(login_url='/student/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def complete_personal_information(request):
    if request.user.is_authenticated and request.user.is_staff:
        return redirect('home')
    
    form = PersonalInfoForm(request.POST, request.FILES)
    if form.is_valid():
        # Update user's first name and last name
        user = request.user
        user.first_name = form.cleaned_data['first_name']
        user.last_name = form.cleaned_data['last_name']
        user.save()

        # Update student's personal information
        student, _ = Student.objects.get_or_create(account=user)
        student.first_name = form.cleaned_data['first_name']
        student.middle_name = form.cleaned_data['middle_name']
        student.last_name = form.cleaned_data['last_name']
        student.extension_name = form.cleaned_data['extension_name']
        student.sex = form.cleaned_data['sex']
        student.birth_date = form.cleaned_data['birth_date']
        student.is_personal_info_complete = True
        # Update or create uploaded photo
        if 'profile_photo' in request.FILES:
            student.profile_photo = request.FILES['profile_photo']
        if 'identification_card' in request.FILES:
            student.identification_card = request.FILES['identification_card']
            
        student.save()

        # Update or create contact information
        contact, _ = ContactPoint.objects.get_or_create(student=student)
        contact.contact_email = user.email
        contact.contact_number = form.cleaned_data['contact_number']
        contact.save()

        # Update or create address information
        address, _ = PersonalAddress.objects.get_or_create(student=student)
        address.house_no = form.cleaned_data['house_no']
        address.street_name = form.cleaned_data['street_name']
        address.barangay = form.cleaned_data['barangay']
        address.city = form.cleaned_data['city']
        address.province = form.cleaned_data['province']
        address.region = form.cleaned_data['region']
        address.save()

    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@login_required(login_url='/student/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def complete_college_entrance_test(request):
    if request.user.is_authenticated and request.user.is_staff:
        return redirect('home')
    
    student = Student.objects.get(account=request.user)
    try:
        cet = CollegeEntranceTest.objects.get(student=student)
    except CollegeEntranceTest.DoesNotExist:
        cet = None

    form = CollegeEntranceTestForm(request.POST, request.FILES, instance=cet)
    
    if form.is_valid():
        cet = form.save(commit=False)
        cet.student = student
        student.is_cet_complete = True
        student.save()
        #Update or create uploaded photo
        if 'report_of_rating' in request.FILES:
            cet.report_of_rating = form.cleaned_data['report_of_rating']
        cet.save()

    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@login_required(login_url='/student/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def complete_school_background(request):
    if request.user.is_authenticated and request.user.is_staff:
        return redirect('home')
    
    form = SchoolBackgroundForm(request.POST, request.FILES)
    if form.is_valid():
        
        user = request.user

        # Update student's additional information
        student = Student.objects.get(account=user)
        if form.cleaned_data['student_type_name'] == 'shiftee' or form.cleaned_data['student_type_name'] == 'transferee':
            student_type = 'old'
        else:
            student_type = 'new'
            
        student.student_type = student_type
        student.student_type_name = form.cleaned_data['student_type_name']
        student.is_personal_info_complete = True
        student.is_shs_complete = True
        student.save()

        # Update or create school information
        school, _ = SchoolBackground.objects.get_or_create(student=student)
        school.last_school_attended = form.cleaned_data['last_school_attended']
        school.last_course_attended = form.cleaned_data['last_course_attended']
        school.strand = form.cleaned_data['strand']
        school.high_school_name = form.cleaned_data['high_school_name']
        school.class_rank = form.cleaned_data['class_rank']
        school.academic_awards_received = form.cleaned_data['academic_awards_received']
        school.classroom_organization = form.cleaned_data['classroom_organization']
        school.student_supreme_government = form.cleaned_data['student_supreme_government']
        school.gpa_first_semester = form.cleaned_data['gpa_first_semester']
        school.gpa_second_semester = form.cleaned_data['gpa_second_semester']

        if school.gpa_first_semester is not None and school.gpa_second_semester is not None and school.gpa_first_semester != 0 and school.gpa_second_semester != 0:
            school.combined_gpa = (school.gpa_first_semester + school.gpa_second_semester) / 2
        elif school.gpa_second_semester is not None and school.gpa_second_semester != 0:
            school.combined_gpa = school.gpa_second_semester
        elif school.gpa_first_semester is not None and school.gpa_first_semester != 0:
            school.combined_gpa = school.gpa_first_semester
        else:
            school.combined_gpa = 0

        if 'photo_grade' in request.FILES:
            school.photo_grade = form.cleaned_data['photo_grade']
        school.save()
        

    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@login_required(login_url='/student/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def complete_economic_status(request):
    if request.user.is_authenticated and request.user.is_staff:
        return redirect('home')
    
    student = Student.objects.get(account=request.user)
    try:
        economic = EconomicStatus.objects.get(student=student)
    except EconomicStatus.DoesNotExist:
        economic = None

    form = EconomicStatusForm(request.POST, instance=economic)
    
    if form.is_valid():
        economic = form.save(commit=False)
        economic.student = student
        economic.save()
        
        student.is_economic_complete = True
        student.save()

    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@login_required(login_url='/student/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def complete_personality_test_1(request):
    if request.user.is_authenticated and request.user.is_staff:
        return redirect('home')
    
    form = PersonalityTestForm1(request.POST)
    if form.is_valid():
        student = Student.objects.get(account=request.user)
        
        pt, _ = PersonalityTest.objects.get_or_create(student=student)
        for i in range(1, 11):
            field_name = 'p{}'.format(i)
            setattr(pt, field_name, form.cleaned_data[field_name])
        pt.student = student
        pt.save()

    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@login_required(login_url='/student/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def complete_personality_test_2(request):
    if request.user.is_authenticated and request.user.is_staff:
        return redirect('home')
    
    form = PersonalityTestForm2(request.POST)
    if form.is_valid():
        student = Student.objects.get(account=request.user)
        
        pt, _ = PersonalityTest.objects.get_or_create(student=student)
        for i in range(11, 21):
            field_name = 'p{}'.format(i)
            setattr(pt, field_name, form.cleaned_data[field_name])
        pt.student = student
        pt.save()

    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@login_required(login_url='/student/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def complete_personality_test_3(request):
    if request.user.is_authenticated and request.user.is_staff:
        return redirect('home')
    
    form = PersonalityTestForm3(request.POST)
    if form.is_valid():
        student = Student.objects.get(account=request.user)
        
        pt, _ = PersonalityTest.objects.get_or_create(student=student)
        for i in range(21, 31):
            field_name = 'p{}'.format(i)
            setattr(pt, field_name, form.cleaned_data[field_name])
        pt.student = student
        pt.save()

    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@login_required(login_url='/student/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def complete_personality_test_4(request):
    if request.user.is_authenticated and request.user.is_staff:
        return redirect('home')
    
    form = PersonalityTestForm4(request.POST)
    if form.is_valid():
        student = Student.objects.get(account=request.user)
        
        pt, _ = PersonalityTest.objects.get_or_create(student=student)
        for i in range(31, 41):
            field_name = 'p{}'.format(i)
            setattr(pt, field_name, form.cleaned_data[field_name])
        pt.student = student
        pt.save()
        
        student.is_personality_complete = True
        student.save()

    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@login_required(login_url='/student/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def complete_study_habit_1(request):
    if request.user.is_authenticated and request.user.is_staff:
        return redirect('home')
    
    form = StudyHabitForm1(request.POST)
    if form.is_valid():
        student = Student.objects.get(account=request.user)
        
        sh, _ = StudyHabit.objects.get_or_create(student=student)
        for i in range(1, 11):
            field_name = 's{}'.format(i)
            setattr(sh, field_name, form.cleaned_data[field_name])
        sh.student = student
        sh.save()

    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@login_required(login_url='/student/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def complete_study_habit_2(request):
    if request.user.is_authenticated and request.user.is_staff:
        return redirect('home')
    
    form = StudyHabitForm2(request.POST)
    if form.is_valid():
        student = Student.objects.get(account=request.user)
        
        sh, _ = StudyHabit.objects.get_or_create(student=student)
        for i in range(11, 21):
            field_name = 's{}'.format(i)
            setattr(sh, field_name, form.cleaned_data[field_name])
        sh.student = student
        sh.save()

    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@login_required(login_url='/student/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def complete_study_habit_3(request):
    if request.user.is_authenticated and request.user.is_staff:
        return redirect('home')
    
    form = StudyHabitForm3(request.POST)
    if form.is_valid():
        student = Student.objects.get(account=request.user)
        
        sh, _ = StudyHabit.objects.get_or_create(student=student)
        for i in range(21, 26):
            field_name = 's{}'.format(i)
            setattr(sh, field_name, form.cleaned_data[field_name])
        sh.student = student
        sh.save()
        
        student.is_study_complete = True
        student.is_profile_complete = True
        student.save()

    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

@login_required(login_url='/student/sign-in/')
def my_profile(request):
    if request.user.is_authenticated and not request.user.is_staff and Student.objects.filter(account=request.user, is_profile_complete=False).exists():
        return redirect('complete_profile')
    elif request.user.is_authenticated and request.user.is_staff:
        return redirect('home')
    
    student = Student.objects.filter(account=request.user).first()
    if student.birth_date:
        student_birth_date = student.birth_date
        formatted_date = student_birth_date.strftime('%Y-%m-%d')
        student.birth_date = formatted_date
    contact = ContactPoint.objects.filter(student=student).first()
    address = PersonalAddress.objects.filter(student=student).first()
    cet = CollegeEntranceTest.objects.filter(student=student).first()
    strands = SHSStrand.objects.all()
    class_positions = ClassRoomOrganization.objects.all()
    ssg = StudentSupremeGovernment.objects.all()
    ranks = ClassRank.objects.all()
    awards = AcademicAwards.objects.all()
    school = SchoolBackground.objects.filter(student=student).first()
    degrees = AcademicDegree.objects.all()
    employment = EmploymentStatus.objects.all()
    economic = EconomicStatus.objects.filter(student=student).first()
    pt = PersonalityTest.objects.filter(student=student).first()
    sh = StudyHabit.objects.filter(student=student).first()
    
    page_title = 'My Profile'
    page_url = request.build_absolute_uri()
    lock = True
    context = {
        'page_title': page_title,
        'student': student,
        'contact': contact,
        'address': address,
        'cet': cet,
        'strands': strands,
        'class_positions': class_positions,
        'ssg': ssg,
        'ranks': ranks,
        'awards': awards,
        'school': school,
        'degrees': degrees,
        'employment': employment,
        'economic': economic,
        'pt': pt,
        'sh': sh,
        'settings': settings,
        'page_url': page_url,
        'lock': lock,
    }
    application = AdmissionApplication.objects.filter(student=student, status__in=['verified', 'interviewed', 'waiting-list', 'approved'])
    
    if application:
        return render(request, 'admission/student/main.html', context)
    
    return render(request, 'student/profile/main.html', context)

@login_required(login_url='/student/sign-in/')
@ensure_csrf_cookie
@require_POST
def view_apply_modal(request):
    if request.user.is_authenticated and request.user.is_staff:
        return redirect('home')
    
    program = Program.objects.get(code=request.POST.get('program_code'))
    school_year = SchoolYear.objects.filter(is_active=True).first()
    period = AdmissionPeriod.objects.filter(school_year=school_year, program=program, is_active=True).first()
    period_allowed = False
    if period:
        today = date.today()
        period_allowed = period.end_date > today
    
    cet_criteria = Criteria.objects.filter(program=program, school_year=school_year, code='cet').first()
    student = Student.objects.get(account=request.user)   
    student_cet = CollegeEntranceTest.objects.filter(student=student).first()
    
    quota = Quota.objects.filter(program=program, school_year=school_year).first()
    slot_taken = AdmissionApplication.objects.filter(program=program, school_year=school_year, status='approved').count()
    
    ongoing_application = AdmissionApplication.objects.filter(school_year=school_year, student=student, status__in=['pending', 'verified', 'interviewed', 'approved']).order_by('-created_at').first()
    invalid_application = AdmissionApplication.objects.filter(program=program, school_year=school_year, student=student, status__in=['cancelled', 'declined', 'withdrawn']).order_by('-created_at').first()
    
    is_admitted = AdmissionApplication.objects.filter(status='approved', student=student).order_by('-created_at').first()
    
    context = {
        'program': program,
        'period_allowed': period_allowed,
        'cet_criteria': cet_criteria,
        'student_cet': student_cet,
        'quota': quota,
        'slot_taken': slot_taken,
        'ongoing_application': ongoing_application,
        'invalid_application': invalid_application,
        'is_admitted': is_admitted,
    }
    
    rendered_html = render(request, 'student/partials/view_apply.modal.html', context)
    return HttpResponse(rendered_html, content_type='text/html')

@login_required(login_url='/student/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def send_application(request):
    if request.user.is_authenticated and request.user.is_staff:
        return redirect('home')
    
    student = Student.objects.get(account=request.user)
    program = Program.objects.get(pk=request.POST.get('program_id'))
    school_year = SchoolYear.objects.filter(is_active=True).first()

    application, _ = AdmissionApplication.objects.get_or_create(student=student,program=program,school_year=school_year)
    application.student=student
    application.program=program
    application.school_year=school_year
    application.status='pending'
    application.save()
    
    #send to student
    title = f"New {program.code.upper()} Application"
    receiver = student.first_name
    mail_subject = f"New {program.code.upper()} Application - GreenScreen Admission System"
    domain = get_current_site(request).domain
    application_url = reverse('my_application')
    message = f"""We have received your application for the <b>{program.name}</b> program in the GreenScreen Admission System.
                Our team is currently reviewing your application, and we will notify you of the outcome soon. 
                You can view the status of your application <a class="color-green" href="{domain}{application_url}">here</a>.
                <br><br>Thank you for choosing our program."""
    to_email = request.user.email
    student_send_email(title, receiver, mail_subject, message, to_email)
    
    #send to AO
    receiver = "Admission Officer"
    mail_subject = f"New {program.code.upper()} Application - GreenScreen Admission System"
    message = f"""We have received a new application for the <b>{program.name}</b> program in the GreenScreen Admission System. 
                <br><br>Please review and process the application promptly."""
    to_email = list(Faculty.objects.filter(department=program, admission_role_id=1).values_list('email', flat=True))
    student_send_email(title, receiver, mail_subject, message, to_email)
    
    return JsonResponse({'message': 'Application Sent!'})
    
@login_required(login_url='/student/sign-in/')
def my_application(request, id=None):
    if request.user.is_authenticated and not request.user.is_staff and Student.objects.filter(account=request.user, is_profile_complete=False).exists():
        return redirect('complete_profile')
    elif request.user.is_authenticated and request.user.is_staff:
        return redirect('home')
    
    student = Student.objects.filter(account=request.user).first()
    school_year = SchoolYear.objects.filter(is_active=True).first()
    if id:
        application = AdmissionApplication.objects.filter(pk=id, student=student, school_year=school_year).order_by('-created_at').first()
    else:
        application = AdmissionApplication.objects.filter(student=student, school_year=school_year).order_by('-created_at').first()
        
    appstatus = ApplicationStatusLogs.objects.filter(application=application).order_by('-created_at').first()
    interview = InterviewLogs.objects.filter(application=application).order_by('-created_at').first()
    documents = DocumentaryRequirement.objects.all()
    
    criterias = None
    shs = None
    cet = None
    total = 0
    
    if interview and interview.status == "interviewed":
        cet = CollegeEntranceTest.objects.filter(student=student).first()
        shs = SchoolBackground.objects.filter(student=student).first()
        criterias = Criteria.objects.filter(program=application.program, school_year=school_year)
        cet_crt = Criteria.objects.filter(program=application.program, school_year=school_year, code='cet').first()
        shs_crt = Criteria.objects.filter(program=application.program, school_year=school_year, code='shs').first()
        int_crt = Criteria.objects.filter(program=application.program, school_year=school_year, code='interview').first()
        total = ((Decimal(cet_crt.weight)/100*Decimal(cet.overall_percentile_rank))
                +(Decimal(shs_crt.weight)/100*Decimal(shs.combined_gpa))
                +(Decimal(int_crt.weight)/100*Decimal(interview.score)))
        total = round(total, 2)
    
    page_title = 'My Application'
    page_url = request.build_absolute_uri()
    context = {
        'page_title': page_title,
        'student': student,
        'application': application,
        'appstatus': appstatus,
        'interview': interview,
        'documents': documents,
        'criterias': criterias,
        'shs': shs,
        'cet': cet,
        'total': total,
        'settings': settings,
        'page_url': page_url,
    }
    return render(request, 'student/my-application/main.html', context)

@login_required(login_url='/student/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def cancel_application(request):
    if request.user.is_authenticated and request.user.is_staff:
        return redirect('home')
    
    application = AdmissionApplication.objects.get(pk=request.POST.get('application_id'))
    if application:
        application.status = 'cancelled'
        application.save()
        logs = InterviewLogs.objects.filter(application=application).order_by('-created_at').first()
        if logs:
            logs.status = application.status
            logs.save()
        
        #send to student
        title = f"{application.program.code.upper()} Application Status - Cancelled"
        receiver = application.student.first_name
        mail_subject = f"{application.program.code.upper()} Application Status (Cancelled) - GreenScreen Admission System"
        domain = get_current_site(request).domain
        application_url = reverse('my_application')
        message = f"""Your application for the <b>{application.program.name}</b> program has been cancelled. 
                    You can view the status of your application <a class="color-green" href="{domain}{application_url}">here</a>.
                    <br><br>We wish you good luck on your academic journey."""
        to_email = list(ContactPoint.objects.filter(student=application.student).values_list('contact_email', flat=True))
        student_send_email(title, receiver, mail_subject, message, to_email)
        
        #send to AO
        receiver = "Admission Officer"
        mail_subject = f"{application.program.code.upper()} Application Status (Cancelled) - GreenScreen Admission System"
        message = f"""Applicant <b>{application.student.first_name} {application.student.last_name}</b> of 
                    <b>{application.program.name}</b> program has cancelled their application in the GreenScreen Admission System. 
                    """
        to_email = list(Faculty.objects.filter(department=application.program, admission_role_id=1).values_list('email', flat=True))
        student_send_email(title, receiver, mail_subject, message, to_email)
    
    return JsonResponse({'message': 'Application Cancelled.'})

@login_required(login_url='/student/sign-in/')
@ensure_csrf_cookie
@require_POST
@transaction.atomic
def withdraw_application(request):
    if request.user.is_authenticated and request.user.is_staff:
        return redirect('home')
    
    application = AdmissionApplication.objects.get(pk=request.POST.get('application_id'))
    form = WithdrawApplicationForm(request.POST)
    if form.is_valid():
        if application:
            application.status = 'withdrawn'
            application.save()
            
            ApplicationStatusLogs.objects.create(
                status = application.status,
                comments = form.cleaned_data.get('reason'),
                application = application,
                processed_by = request.user
            )
            
            #send to student
            title = f"{application.program.code.upper()} Application Status - Withdrawn"
            receiver = application.student.first_name
            mail_subject = f"{application.program.code.upper()} Application Status (Withdrawn) - GreenScreen Admission System"
            domain = get_current_site(request).domain
            application_url = reverse('my_application')
            message = f"""Your application for the <b>{application.program.name}</b> program has been withdrawn. 
                        You can view the status of your application <a class="color-green" href="{domain}{application_url}">here</a>.
                        <br><br>We wish you good luck on your academic journey."""
            to_email = list(ContactPoint.objects.filter(student=application.student).values_list('contact_email', flat=True))
            student_send_email(title, receiver, mail_subject, message, to_email)
            
            #send to AO
            receiver = "Admission Officer"
            mail_subject = f"{application.program.code.upper()} Application Status (Withdrawn) - GreenScreen Admission System"
            message = f"""Applicant <b>{application.student.first_name} {application.student.last_name}</b> of 
                        <b>{application.program.name}</b> program has withdrawn their application in the GreenScreen Admission System. 
                        """
            to_email = list(Faculty.objects.filter(department=application.program, admission_role_id=1).values_list('email', flat=True))
            student_send_email(title, receiver, mail_subject, message, to_email)
        
    errors = form.errors.as_json()
    return JsonResponse(errors, safe=False)

def student_send_email(title, receiver, mail_subject, message, to_email):
    from_email = settings.DEFAULT_FROM_EMAIL

    html_content = render_to_string("student_send_email.html", {
        'title': title,
        'receiver': receiver,
        'message': mark_safe(message),
    })
    
    if not isinstance(to_email, (list, tuple)):
        to_email = [to_email]
        
    text_content = strip_tags(html_content)

    email = EmailMultiAlternatives(mail_subject, text_content, from_email, to=to_email)
    email.attach_alternative(html_content, "text/html")
    email.send()
    
