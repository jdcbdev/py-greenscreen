from django import forms
from django.contrib.auth import get_user_model
import re
from .models import Student, PersonalAddress, ContactPoint, CollegeEntranceTest, EconomicStatus, PersonalityTest
from datetime import date, timedelta

User = get_user_model()

class SignUpForm(forms.ModelForm):
    first_name = forms.CharField(max_length=100, required = True, widget=forms.TextInput)
    last_name = forms.CharField(max_length=100, required = True, widget=forms.TextInput)
    email = forms.EmailField(max_length=100, required = True)
    password = forms.CharField(required = True, widget=forms.PasswordInput)
    confirm_password = forms.CharField(required = True, widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'confirm_password']

    def clean(self):
        cleaned_data = super().clean()
        first_name = cleaned_data.get('first_name')
        last_name = cleaned_data.get('last_name')
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')

        if first_name and not re.match(r'^[a-zA-Z0-9\s_\'-]*$', first_name):
            self.add_error('first_name', 'Enter a valid first name.')

        if last_name and not re.match(r'^[a-zA-Z0-9\s_\'-]*$', last_name):
            self.add_error('last_name', 'Enter a valid last name.')

        if password and confirm_password and password.strip() != confirm_password.strip():
            self.add_error('confirm_password', 'Passwords do not match.')

        # Password strength validation
        if password:
            if password.strip() == '':
                self.add_error('password', 'Password cannot be blank.')
            elif ' ' in password:
                self.add_error('password', 'Password cannot contain spaces.')
            elif not self.is_password_strong(password):
                self.add_error('password', 'Password must contain at least 8 characters, including uppercase and lowercase letters, and numbers.')
                
        return cleaned_data

    def is_password_strong(self, password):
        # Add your custom password strength validation logic here
        # For example, check for minimum length, presence of uppercase/lowercase letters, and numbers
        return len(password) >= 8 and re.search(r'[A-Z]', password) and re.search(r'[a-z]', password) and re.search(r'\d', password)

class SignInForm(forms.Form):
    email = forms.EmailField(max_length=100, required = True)
    password = forms.CharField(required = True, widget=forms.PasswordInput)
    
class SignUpOldForm(forms.ModelForm):
    first_name = forms.CharField(max_length=100, required = True, widget=forms.TextInput)
    last_name = forms.CharField(max_length=100, required = True, widget=forms.TextInput)
    email = forms.EmailField(max_length=100, required = True)
    password = forms.CharField(required = True, widget=forms.PasswordInput)
    confirm_password = forms.CharField(required = True, widget=forms.PasswordInput)
    
    student_type_name = forms.CharField(max_length=100, required = True)
    last_school_attended = forms.CharField(max_length=200, required = True)
    last_course_attended = forms.CharField(max_length=200, required = True)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'confirm_password']

    def clean(self):
        cleaned_data = super().clean()
        first_name = cleaned_data.get('first_name')
        last_name = cleaned_data.get('last_name')
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')

        if first_name and not re.match(r'^[a-zA-Z0-9\s_\'-]*$', first_name):
            self.add_error('first_name', 'Enter a valid first name.')

        if last_name and not re.match(r'^[a-zA-Z0-9\s_\'-]*$', last_name):
            self.add_error('last_name', 'Enter a valid last name.')

        if password and confirm_password and password.strip() != confirm_password.strip():
            self.add_error('confirm_password', 'Passwords do not match.')

        # Password strength validation
        if password:
            if password.strip() == '':
                self.add_error('password', 'Password cannot be blank.')
            elif ' ' in password:
                self.add_error('password', 'Password cannot contain spaces.')
            elif not self.is_password_strong(password):
                self.add_error('password', 'Password must contain at least 8 characters, including uppercase and lowercase letters, and numbers.')
                
        return cleaned_data

    def is_password_strong(self, password):
        # Add your custom password strength validation logic here
        # For example, check for minimum length, presence of uppercase/lowercase letters, and numbers
        return len(password) >= 8 and re.search(r'[A-Z]', password) and re.search(r'[a-z]', password) and re.search(r'\d', password)

class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(max_length=100, required = True)
    
class SetPasswordForm(forms.ModelForm):
    password = forms.CharField(required = True, widget=forms.PasswordInput)
    confirm_password = forms.CharField(required = True, widget=forms.PasswordInput)
    
    class Meta:
        model = User
        fields = ['password', 'confirm_password']
    
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        
        if password and confirm_password and password.strip() != confirm_password.strip():
            self.add_error('confirm_password', 'Passwords do not match.')

        # Password strength validation
        if password:
            if password.strip() == '':
                self.add_error('password', 'Password cannot be blank.')
            elif ' ' in password:
                self.add_error('password', 'Password cannot contain spaces.')
            elif not self.is_password_strong(password):
                self.add_error('password', 'Password must contain at least 8 characters, including uppercase and lowercase letters, and numbers.')
                
        return cleaned_data

    def is_password_strong(self, password):
        # Add your custom password strength validation logic here
        # For example, check for minimum length, presence of uppercase/lowercase letters, and numbers
        return len(password) >= 8 and re.search(r'[A-Z]', password) and re.search(r'[a-z]', password) and re.search(r'\d', password)
    
class PersonalInfoForm(forms.Form):
    first_name = forms.CharField(max_length=100, required = True, widget=forms.TextInput)
    middle_name = forms.CharField(max_length=100, required = False, widget=forms.TextInput)
    last_name = forms.CharField(max_length=100, required = True, widget=forms.TextInput)
    extension_name = forms.CharField(max_length=100, required = False, widget=forms.TextInput)
    sex = forms.CharField(max_length=100, required = True)
    birth_date = forms.DateField(required = True, widget=forms.DateInput)
    
    contact_email = forms.CharField(max_length=100, required = True)
    contact_number = forms.CharField(max_length=100, required = True, widget=forms.TextInput)
    
    house_no = forms.CharField(max_length=100, required = False, widget=forms.TextInput)
    street_name = forms.CharField(max_length=255, required = False, widget=forms.TextInput)
    
    barangay = forms.CharField(max_length=100, required = True)
    city = forms.CharField(max_length=100, required = True)
    province = forms.CharField(max_length=100, required = True)
    region = forms.CharField(max_length=100, required = True)
    
    profile_photo = forms.FileField(required=False)
    
    def __init__(self, *args, **kwargs):
        self.instance = kwargs.pop('instance', None)
        super().__init__(*args, **kwargs)
    
    def clean_profile_photo(self):
        profile_photo = self.cleaned_data.get('profile_photo', False)

        if not profile_photo:
            return profile_photo

        max_size = 2 * 1024 * 1024  # 2MB in bytes
        if profile_photo.size > max_size:
            raise forms.ValidationError('The file size exceeds the maximum allowed limit of 2MB.')

        allowed_formats = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif']
        if profile_photo.content_type not in allowed_formats:
            raise forms.ValidationError('The selected file format is not supported. Please choose a JPEG, PNG, or GIF image.')

        return profile_photo
    
    def clean_contact_number(self):
        contact_number = self.cleaned_data['contact_number']
        if len(contact_number) != 11 or not contact_number.isdigit() or not contact_number.startswith('0'):
            raise forms.ValidationError('Phone number must be 11 digits long and start with 0.')

        # if contact_number and ContactPoint.objects.filter(contact_number=contact_number).exclude(pk=self.instance.pk).exists():
        #     raise forms.ValidationError('This number is already in use.')
        
        return contact_number
    
    def clean_birth_date(self):
        birth_date = self.cleaned_data['birth_date']
        
        minimum_age = date.today() - timedelta(days=12*365)
        if birth_date > minimum_age:
            raise forms.ValidationError('You must be at least 12 years old.')
        
        return birth_date
    
    def clean_contact_email(self):
        contact_email = self.cleaned_data['contact_email']
        # if contact_email and ContactPoint.objects.filter(contact_email=contact_email).exclude(pk=self.instance.pk).exists():
        #     raise forms.ValidationError('This email is already in use.')
        
        return contact_email
    
    def clean(self):
        cleaned_data = super().clean()
           
        return cleaned_data

class CollegeEntranceTestForm(forms.ModelForm):
    report_of_rating = forms.FileField(required=False)
    class Meta:
        model = CollegeEntranceTest
        fields = [
            'rating_period',
            'application_number',
            'overall_percentile_rank',
            'english_proficiency_skills',
            'reading_comprehension_skills',
            'science_process_skills',
            'quantitative_skills',
            'abstract_thinking_skills',
        ]
    
    def clean_report_of_rating(self):
        report_of_rating = self.cleaned_data.get('report_of_rating', False)

        if not report_of_rating:
            return report_of_rating

        max_size = 5 * 1024 * 1024  # 2MB in bytes
        if report_of_rating.size > max_size:
            raise forms.ValidationError('The file size exceeds the maximum allowed limit of 5MB.')

        allowed_formats = ['image/jpeg', 'image/jpg', 'image/png']
        if report_of_rating.content_type not in allowed_formats:
            raise forms.ValidationError('The selected file format is not supported. Please choose a JPEG, or PNG.')

        return report_of_rating
    
    def clean(self):
        cleaned_data = super().clean()
           
        return cleaned_data

class SchoolBackgroundForm(forms.Form):
    student_type_name = forms.CharField(max_length=150, required=False)
    last_school_attended = forms.CharField(max_length=255, required=False)
    last_course_attended = forms.CharField(max_length=255, required=False)
    strand = forms.CharField(max_length=150, required=True)
    high_school_name = forms.CharField(max_length=255, required=True)
    class_rank = forms.CharField(max_length=100, required=True)
    academic_awards_received = forms.CharField(max_length=150, required=True)
    classroom_organization = forms.CharField(max_length=150, required=True)
    student_supreme_government = forms.CharField(max_length=150, required=True)
    gpa_first_semester = forms.FloatField(required=False)
    gpa_second_semester = forms.FloatField(required=False)
    photo_grade = forms.ImageField(required=False)
    
    def clean_student_type_name(self):
        student_type_name = self.cleaned_data.get('student_type_name')
        
        if not student_type_name:
            raise forms.ValidationError('Choose student type.')
        
        return student_type_name
    
    def clean_last_school_attended(self):
        last_school_attended = self.cleaned_data.get('last_school_attended')
        student_type_name = self.cleaned_data.get('student_type_name')
        
        if student_type_name == 'shiftee' and not last_school_attended:
            raise forms.ValidationError('This field is required.')
        if student_type_name == 'transferee' and not last_school_attended:
            raise forms.ValidationError('This field is required.')
        
        return last_school_attended
    
    def clean_last_course_attended(self):
        last_course_attended = self.cleaned_data.get('last_course_attended')
        student_type_name = self.cleaned_data.get('student_type_name')
        
        if student_type_name == 'shiftee' and not last_course_attended:
            raise forms.ValidationError('This field is required.')
        if student_type_name == 'transferee' and not last_course_attended:
            raise forms.ValidationError('This field is required.')
        
        return last_course_attended
    
    def clean_photo_grade(self):
        photo_grade = self.cleaned_data.get('photo_grade', False)

        if not photo_grade:
            return photo_grade

        max_size = 5 * 1024 * 1024  # 2MB in bytes
        if photo_grade.size > max_size:
            raise forms.ValidationError('The file size exceeds the maximum allowed limit of 5MB.')

        allowed_formats = ['image/jpeg', 'image/jpg', 'image/png']
        if photo_grade.content_type not in allowed_formats:
            raise forms.ValidationError('The selected file format is not supported. Please choose a JPEG, or PNG.')

        return photo_grade
    
    def clean(self):
        cleaned_data = super().clean()
           
        return cleaned_data

class EconomicStatusForm(forms.ModelForm):
    class Meta:
        model = EconomicStatus
        fields = [
            'father_highest_academic_degree',
            'father_employment_status',
            'father_current_occupation',
            'mother_highest_academic_degree',
            'mother_employment_status',
            'mother_current_occupation',
            'family_income',
            'computer',
            'internet_connection',
        ]
    
    def clean(self):
        cleaned_data = super().clean()
           
        return cleaned_data

class PersonalityTestForm1(forms.Form):
    p1 = forms.CharField(required=False)
    p2 = forms.CharField(required=False)
    p3 = forms.CharField(required=False)
    p4 = forms.CharField(required=False)
    p5 = forms.CharField(required=False)
    p6 = forms.CharField(required=False)
    p7 = forms.CharField(required=False)
    p8 = forms.CharField(required=False)
    p9 = forms.CharField(required=False)
    p10 = forms.CharField(required=False)

    def clean_p1(self):
        p1 = self.cleaned_data.get('p1')
        if not p1:
            raise forms.ValidationError('Select an answer.')
        return p1
    
    def clean_p2(self):
        p2 = self.cleaned_data.get('p2')
        if not p2:
            raise forms.ValidationError('Select an answer.')
        return p2
    
    def clean_p3(self):
        p3 = self.cleaned_data.get('p3')

        if not p3:
            raise forms.ValidationError('Select an answer.')

        return p3

    def clean_p4(self):
        p4 = self.cleaned_data.get('p4')

        if not p4:
            raise forms.ValidationError('Select an answer.')

        return p4

    def clean_p5(self):
        p5 = self.cleaned_data.get('p5')

        if not p5:
            raise forms.ValidationError('Select an answer.')

        return p5

    def clean_p6(self):
        p6 = self.cleaned_data.get('p6')

        if not p6:
            raise forms.ValidationError('Select an answer.')

        return p6

    def clean_p7(self):
        p7 = self.cleaned_data.get('p7')

        if not p7:
            raise forms.ValidationError('Select an answer.')

        return p7

    def clean_p8(self):
        p8 = self.cleaned_data.get('p8')

        if not p8:
            raise forms.ValidationError('Select an answer.')

        return p8

    def clean_p9(self):
        p9 = self.cleaned_data.get('p9')

        if not p9:
            raise forms.ValidationError('Select an answer.')

        return p9

    def clean_p10(self):
        p10 = self.cleaned_data.get('p10')

        if not p10:
            raise forms.ValidationError('Select an answer.')

        return p10

    def clean(self):
        cleaned_data = super().clean()
           
        return cleaned_data

class PersonalityTestForm2(forms.Form):
    p11 = forms.CharField(required=False)
    p12 = forms.CharField(required=False)
    p13 = forms.CharField(required=False)
    p14 = forms.CharField(required=False)
    p15 = forms.CharField(required=False)
    p16 = forms.CharField(required=False)
    p17 = forms.CharField(required=False)
    p18 = forms.CharField(required=False)
    p19 = forms.CharField(required=False)
    p20 = forms.CharField(required=False)

    def clean_p11(self):
        p11 = self.cleaned_data.get('p11')

        if not p11:
            raise forms.ValidationError('Select an answer.')

        return p11

    def clean_p12(self):
        p12 = self.cleaned_data.get('p12')

        if not p12:
            raise forms.ValidationError('Select an answer.')

        return p12

    def clean_p13(self):
        p13 = self.cleaned_data.get('p13')

        if not p13:
            raise forms.ValidationError('Select an answer.')

        return p13

    def clean_p14(self):
        p14 = self.cleaned_data.get('p14')

        if not p14:
            raise forms.ValidationError('Select an answer.')

        return p14

    def clean_p15(self):
        p15 = self.cleaned_data.get('p15')

        if not p15:
            raise forms.ValidationError('Select an answer.')

        return p15

    def clean_p16(self):
        p16 = self.cleaned_data.get('p16')

        if not p16:
            raise forms.ValidationError('Select an answer.')

        return p16

    def clean_p17(self):
        p17 = self.cleaned_data.get('p17')

        if not p17:
            raise forms.ValidationError('Select an answer.')

        return p17

    def clean_p18(self):
        p18 = self.cleaned_data.get('p18')

        if not p18:
            raise forms.ValidationError('Select an answer.')

        return p18

    def clean_p19(self):
        p19 = self.cleaned_data.get('p19')

        if not p19:
            raise forms.ValidationError('Select an answer.')

        return p19

    def clean_p20(self):
        p20 = self.cleaned_data.get('p20')

        if not p20:
            raise forms.ValidationError('Select an answer.')

        return p20

    def clean(self):
        cleaned_data = super().clean()
           
        return cleaned_data

class PersonalityTestForm3(forms.Form):
    p21 = forms.CharField(required=False)
    p22 = forms.CharField(required=False)
    p23 = forms.CharField(required=False)
    p24 = forms.CharField(required=False)
    p25 = forms.CharField(required=False)
    p26 = forms.CharField(required=False)
    p27 = forms.CharField(required=False)
    p28 = forms.CharField(required=False)
    p29 = forms.CharField(required=False)
    p30 = forms.CharField(required=False)

    def clean_p21(self):
        p21 = self.cleaned_data.get('p21')

        if not p21:
            raise forms.ValidationError('Select an answer.')

        return p21

    def clean_p22(self):
        p22 = self.cleaned_data.get('p22')

        if not p22:
            raise forms.ValidationError('Select an answer.')

        return p22

    def clean_p23(self):
        p23 = self.cleaned_data.get('p23')

        if not p23:
            raise forms.ValidationError('Select an answer.')

        return p23

    def clean_p24(self):
        p24 = self.cleaned_data.get('p24')

        if not p24:
            raise forms.ValidationError('Select an answer.')

        return p24

    def clean_p25(self):
        p25 = self.cleaned_data.get('p25')

        if not p25:
            raise forms.ValidationError('Select an answer.')

        return p25

    def clean_p26(self):
        p26 = self.cleaned_data.get('p26')

        if not p26:
            raise forms.ValidationError('Select an answer.')

        return p26

    def clean_p27(self):
        p27 = self.cleaned_data.get('p27')

        if not p27:
            raise forms.ValidationError('Select an answer.')

        return p27

    def clean_p28(self):
        p28 = self.cleaned_data.get('p28')

        if not p28:
            raise forms.ValidationError('Select an answer.')

        return p28

    def clean_p29(self):
        p29 = self.cleaned_data.get('p29')

        if not p29:
            raise forms.ValidationError('Select an answer.')

        return p29

    def clean_p30(self):
        p30 = self.cleaned_data.get('p30')

        if not p30:
            raise forms.ValidationError('Select an answer.')

        return p30
    
    def clean(self):
        cleaned_data = super().clean()
           
        return cleaned_data

class PersonalityTestForm4(forms.Form):
    p31 = forms.CharField(required=False)
    p32 = forms.CharField(required=False)
    p33 = forms.CharField(required=False)
    p34 = forms.CharField(required=False)
    p35 = forms.CharField(required=False)
    p36 = forms.CharField(required=False)
    p37 = forms.CharField(required=False)
    p38 = forms.CharField(required=False)
    p39 = forms.CharField(required=False)
    p40 = forms.CharField(required=False)

    def clean_p31(self):
        p31 = self.cleaned_data.get('p31')

        if not p31:
            raise forms.ValidationError('Select an answer.')

        return p31

    def clean_p32(self):
        p32 = self.cleaned_data.get('p32')

        if not p32:
            raise forms.ValidationError('Select an answer.')

        return p32

    def clean_p33(self):
        p33 = self.cleaned_data.get('p33')

        if not p33:
            raise forms.ValidationError('Select an answer.')

        return p33

    def clean_p34(self):
        p34 = self.cleaned_data.get('p34')

        if not p34:
            raise forms.ValidationError('Select an answer.')

        return p34

    def clean_p35(self):
        p35 = self.cleaned_data.get('p35')

        if not p35:
            raise forms.ValidationError('Select an answer.')

        return p35

    def clean_p36(self):
        p36 = self.cleaned_data.get('p36')

        if not p36:
            raise forms.ValidationError('Select an answer.')

        return p36

    def clean_p37(self):
        p37 = self.cleaned_data.get('p37')

        if not p37:
            raise forms.ValidationError('Select an answer.')

        return p37

    def clean_p38(self):
        p38 = self.cleaned_data.get('p38')

        if not p38:
            raise forms.ValidationError('Select an answer.')

        return p38

    def clean_p39(self):
        p39 = self.cleaned_data.get('p39')

        if not p39:
            raise forms.ValidationError('Select an answer.')

        return p39

    def clean_p40(self):
        p40 = self.cleaned_data.get('p40')

        if not p40:
            raise forms.ValidationError('Select an answer.')

        return p40
    
    def clean(self):
        cleaned_data = super().clean()
           
        return cleaned_data

