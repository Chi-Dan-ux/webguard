from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from .models import Profile

def landing_view(request):
    return render(request, 'index.html')

def docs_view(request):
    return render(request, 'docs.html')

def research_view(request):
    return render(request, 'research.html')

def owasp_view(request):
    return render(request, 'owasp.html')

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        # Find user by email
        try:
            user = User.objects.get(email=email)
            user = authenticate(request, username=user.username, password=password)
            if user is not None:
                login(request, user)
                return redirect('dashboard')
            else:
                messages.error(request, 'Invalid email or password.')
        except User.DoesNotExist:
            messages.error(request, 'No account found with that email.')
    
    return render(request, 'accounts/login.html')


def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name  = request.POST.get('last_name')
        email      = request.POST.get('email')
        role       = request.POST.get('role')
        password   = request.POST.get('password')
        confirm    = request.POST.get('confirm_password')

        # Validation
        if password != confirm:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'accounts/register.html')
        
        if User.objects.filter(email=email).exists():
            messages.error(request, 'An account with this email already exists.')
            return render(request, 'accounts/register.html')
        
        if len(password) < 8:
            messages.error(request, 'Password must be at least 8 characters.')
            return render(request, 'accounts/register.html')

        # Create user
        username = email.split('@')[0]
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name
        )

        # Create profile
        Profile.objects.create(user=user, role=role)

        messages.success(request, 'Account created successfully. Please sign in.')
        return redirect('login')
    
    return render(request, 'accounts/register.html')


def logout_view(request):
    logout(request)
    return redirect('login')


def dashboard_view(request):
    if not request.user.is_authenticated:
        return redirect('login')
    try:
        role = request.user.profile.role
    except Profile.DoesNotExist:
        role = 'it'

    role_display = 'Administrator' if role == 'admin' else 'IT Personnel'
    full_name = f"{request.user.first_name} {request.user.last_name}".strip() or request.user.username
    initials = ''.join([n[0].upper() for n in full_name.split()[:2]]) if full_name else 'U'

    return render(request, 'dashboard.html', {
        'user_role': role,
        'role_display': role_display,
        'full_name': full_name,
        'initials': initials,
    })