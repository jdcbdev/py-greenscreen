from django import forms
from django.contrib.auth import get_user_model
import re
from .models import Student, PersonalAddress, ContactPoint, UploadedPhoto
from betterforms.multiform import MultiModelForm
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