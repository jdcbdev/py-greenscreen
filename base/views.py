from django.shortcuts import render
import datetime
from django.shortcuts import redirect

# Create your views here.

def home(request):
    if 'logged_id' in request.session and request.session['user_type'] == 'admin':
        return redirect('admin:dashboard')  # Redirect to admin dashboard URL
    elif 'logged_id' in request.session and request.session['user_type'] == 'faculty':
        return redirect('faculty:dashboard')  # Redirect to faculty dashboard URL
    elif 'logged_id' in request.session and request.session['user_type'] == 'student':
        return redirect('student:index')  # Redirect to student index URL
    else:
        page_title = "Home"
        current_year = datetime.datetime.now().year
        context = {
            'page_title': page_title,
            'page_year': current_year
        }
        return render(request, 'home.html', context)
