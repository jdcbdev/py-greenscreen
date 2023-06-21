from django import forms
from django.contrib.auth import get_user_model
from django.core import validators
import re

User = get_user_model()

class SignUpForm(forms.ModelForm):
    first_name = forms.CharField(max_length=50, validators=[validators.RegexValidator(r'^[a-zA-Z0-9\s_\'-]*$', 'Enter a valid first name.')])
    last_name = forms.CharField(max_length=50, validators=[validators.RegexValidator(r'^[a-zA-Z0-9\s_\'-]*$', 'Enter a valid last name.')])
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'type', 'avatar', 'password', 'confirm_password']

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
