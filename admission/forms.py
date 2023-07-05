from django import forms
from .models import SchoolYear, AdmissionPeriod
from datetime import date

class SchoolYearForm(forms.Form):
    start_year = forms.IntegerField(required=True)
    end_year = forms.IntegerField(required=True)

    def clean_start_year(self):
        start_year = self.cleaned_data.get('start_year')
        current_year = date.today().year

        if start_year != current_year:
            raise forms.ValidationError('Start year should be equal to the current year.')

        return start_year

    def clean_end_year(self):
        start_year = self.cleaned_data.get('start_year')
        end_year = self.cleaned_data.get('end_year')
        
        if not start_year or not end_year:
            return end_year

        if end_year != start_year + 1:
            raise forms.ValidationError('End year should be one year ahead of the start year.')

        return end_year

    def clean(self):
        cleaned_data = super().clean()

        return cleaned_data
    
class AdmissionPeriodForm(forms.Form):
    start_date = forms.DateField(required=True)
    end_date = forms.DateField(required=True)

    def clean_end_date(self):
        start_date = self.cleaned_data.get('start_date')
        end_date = self.cleaned_data.get('end_date')

        if start_date and end_date and end_date <= start_date:
            raise forms.ValidationError('End date must be greater than the start date.')
        
        return end_date
    
    def clean(self):
        cleaned_data = super().clean()

        return cleaned_data

class QuotaForm(forms.Form):
    program_code = forms.CharField(required=True, max_length=100)
    number = forms.IntegerField(required=True)

    def clean_number(self):
        number = self.cleaned_data.get('number')

        if number is not None and number <= 0:
            raise forms.ValidationError('Quota number must be greater than zero.')
        
        return number
    
    def clean(self):
        cleaned_data = super().clean()

        return cleaned_data