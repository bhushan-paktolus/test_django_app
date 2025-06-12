from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.urls import reverse
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth import login, logout, authenticate
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings
from django.utils.crypto import get_random_string
from django.utils import timezone
from django.http import HttpResponseForbidden, JsonResponse
from django.core.exceptions import PermissionDenied
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.password_validation import validate_password
from django.core.validators import validate_email
from django.core.cache import cache
from .forms import (
    UserRegisterForm, 
    PasswordResetRequestForm, 
    OTPVerificationForm, 
    SetNewPasswordForm,
    UserEditForm,
    EmailAuthenticationForm,
    AuthenticationForm,
    PasswordChangeForm
)
from .models import CustomUser, PasswordResetOTP, UserActivity
from smtplib import SMTPSenderRefused, SMTPException
import random
import logging
from .utils.logger import (
    log_auth_event,
    log_user_event,
    log_security_event,
    log_email_event,
    get_client_ip
)
from .utils.display import display_otp_in_terminal
import string
import os

# Get an instance of a logger
logger = logging.getLogger('accounts')

# Constants for rate limiting
MAX_LOGIN_ATTEMPTS = 5  # Maximum number of failed login attempts
LOGIN_ATTEMPT_TIMEOUT = 60  # Timeout in seconds (1 minute)
MAX_PASSWORD_RESET_ATTEMPTS = 3  # Maximum number of password reset attempts
PASSWORD_RESET_TIMEOUT = 300  # Timeout in seconds (5 minutes)

# Decorator to check if user is admin or staff
def admin_or_staff_required(function):
    def check_admin_or_staff(user):
        return user.is_authenticated and (user.is_superuser or user.role == 'staff')
    decorated_view = user_passes_test(check_admin_or_staff, login_url='login')(function)
    return decorated_view

# User Management Views
@login_required
@admin_or_staff_required
def user_list(request):
    """View to list all users (admin and staff only)"""
    users = CustomUser.objects.all()
    
    # Calculate user statistics
    total_users = users.count()
    active_users = users.filter(is_active=True).count()
    admin_users = users.filter(role='admin').count()
    recent_users = users.order_by('-date_joined')[:5].count()
    
    context = {
        'users': users,
        'total_users': total_users,
        'active_users': active_users,
        'admin_users': admin_users,
        'recent_users': recent_users,
    }
    
    return render(request, 'accounts/user_list.html', context)

@login_required
@admin_or_staff_required
def user_create(request):
    """View to create a new user (admin and staff only)"""
    if request.method == 'POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            logger.info(f"New user created by {request.user.email}: {user.email}")
            messages.success(request, 'User created successfully.')
            return redirect('user_list')
    else:
        form = UserRegisterForm()
    return render(request, 'accounts/user_create.html', {'form': form})

@login_required
def user_edit(request, user_id):
    """View to edit user details"""
    user_to_edit = get_object_or_404(CustomUser, id=user_id)
    
    # Check permissions
    if not (request.user.is_superuser or request.user.role == 'staff' or request.user.id == user_id):
        logger.warning(f"Unauthorized attempt to edit user {user_id} by {request.user.email}")
        messages.error(request, "You don't have permission to edit this user.")
        raise PermissionDenied
    
    # Staff can't edit admins
    if request.user.role == 'staff' and (user_to_edit.is_superuser or user_to_edit.role == 'admin'):
        logger.warning(f"Staff member {request.user.email} attempted to edit admin {user_to_edit.email}")
        messages.error(request, "Staff members cannot edit admin users.")
        raise PermissionDenied
    
    if request.method == 'POST':
        form = UserEditForm(request.POST, instance=user_to_edit)
        if form.is_valid():
            try:
                user = form.save(commit=False)
                
                # Only admins can change roles
                if not request.user.is_superuser:
                    user.role = user_to_edit.role
                
                user.save()
                logger.info(f"User {user.email} updated successfully by {request.user.email}")
                messages.success(request, 'User updated successfully.')
                return redirect('user_list')
            except Exception as e:
                logger.error(f"Error updating user {user_to_edit.email}: {str(e)}")
                messages.error(request, 'An error occurred while updating the user. Please try again.')
        else:
            logger.warning(f"Invalid form submission for user {user_to_edit.email}: {form.errors}")
            messages.error(request, 'Please correct the errors below.')
    else:
        form = UserEditForm(instance=user_to_edit)
    
    return render(request, 'accounts/user_edit.html', {
        'form': form,
        'user_to_edit': user_to_edit,
        'can_edit_role': request.user.is_superuser
    })

@login_required
@admin_or_staff_required
def user_delete(request, user_id):
    """View to delete a user"""
    user_to_delete = get_object_or_404(CustomUser, id=user_id)
    
    # Check permissions
    if not (request.user.is_superuser or request.user.role == 'staff'):
        logger.warning(f"Unauthorized attempt to delete user {user_id} by {request.user.email}")
        raise PermissionDenied
    
    # Staff can't delete admins or other staff
    if request.user.role == 'staff' and (user_to_delete.is_superuser or user_to_delete.role in ['admin', 'staff']):
        logger.warning(f"Staff member {request.user.email} attempted to delete privileged user {user_to_delete.email}")
        raise PermissionDenied
    
    # Prevent deleting yourself
    if user_to_delete == request.user:
        messages.error(request, "You cannot delete your own account.")
        return redirect('user_list')
    
    # Prevent deleting superusers
    if user_to_delete.is_superuser:
        messages.error(request, "Superuser accounts cannot be deleted.")
        return redirect('user_list')

    if request.method == 'POST':
        # Store the email for the success message before deletion
        user_email = user_to_delete.email
        user_to_delete.delete()
        logger.info(f"User {user_email} deleted by {request.user.email}")
        messages.success(request, f"User {user_email} has been deleted successfully.")
        return redirect('user_list')
    
    # If it's a GET request, just show the confirmation page
    return render(request, 'accounts/user_delete_confirm.html', {
        'user_to_delete': user_to_delete
    })

# Rate limiting helper functions
def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def check_rate_limit(request, prefix='login', max_attempts=MAX_LOGIN_ATTEMPTS, timeout=LOGIN_ATTEMPT_TIMEOUT):
    client_ip = get_client_ip(request)
    cache_key = f"{prefix}_attempts_{client_ip}"
    attempts = cache.get(cache_key, 0)
    
    if attempts >= max_attempts:
        logger.warning(f"{prefix.title()} blocked due to too many attempts from IP: {client_ip}")
        return False
    return True

def increment_attempts(request, prefix='login', timeout=LOGIN_ATTEMPT_TIMEOUT):
    client_ip = get_client_ip(request)
    cache_key = f"{prefix}_attempts_{client_ip}"
    attempts = cache.get(cache_key, 0)
    cache.set(cache_key, attempts + 1, timeout)

def reset_attempts(request, prefix='login'):
    client_ip = get_client_ip(request)
    cache_key = f"{prefix}_attempts_{client_ip}"
    cache.delete(cache_key)

def rate_limit_response(request):
    """Return appropriate response based on request type (API vs Web)"""
    if request.headers.get('Accept') == 'application/json':
        return JsonResponse({
            'error': 'Too many requests',
            'message': 'Please try again later'
        }, status=429)
    return render(request, '429.html', status=429)

@csrf_protect
def register(request):
    if request.method == 'POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            log_auth_event(
                f"User registered successfully: {user.email}",
                level='info',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            messages.success(request, 'You have been successfully registered! Please log in.')
            return redirect('login')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = UserRegisterForm()
    return render(request, 'accounts/register.html', {'form': form})

@csrf_protect
@require_http_methods(['GET', 'POST'])
def login_view(request):
    """View to handle user login with rate limiting"""
    if request.method == 'POST':
        # Check rate limiting
        if not check_rate_limit(request):
            return rate_limit_response(request)

        form = EmailAuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            reset_attempts(request)  # Reset failed attempts on successful login

            # Log successful login
            ip_address = get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            log_auth_event(
                f"Successful login for user: {user.email}",
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            # Create activity log
            UserActivity.objects.create(
                user=user,
                activity_type='login_success',
                ip_address=ip_address,
                user_agent=user_agent
            )

            return redirect('profile')
        else:
            # Increment failed attempts
            increment_attempts(request)

            # Get the email from the form data
            email = request.POST.get('username', '')
            try:
                user = CustomUser.objects.get(email=email)
                # Log failed login for existing user
                ip_address = get_client_ip(request)
                user_agent = request.META.get('HTTP_USER_AGENT', '')
                log_auth_event(
                    f"Failed login attempt for user: {email}",
                    level='warning',
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                # Create activity log
                UserActivity.objects.create(
                    user=user,
                    activity_type='login_failed',
                    ip_address=ip_address,
                    user_agent=user_agent
                )
            except CustomUser.DoesNotExist:
                # Log failed login attempt for non-existent user
                log_auth_event(
                    f"Failed login attempt for non-existent user: {email}",
                    level='warning',
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )

    else:
        form = EmailAuthenticationForm(request)

    return render(request, 'accounts/login.html', {'form': form})

@login_required
def profile(request):
    """View to handle user profile updates"""
    if request.method == 'POST':
        form = UserEditForm(request.POST, instance=request.user)
        if form.is_valid():
            user = form.save()
            log_user_event(f"Profile updated for user: {user.email}")
            messages.success(request, 'Your profile has been updated successfully.')
            return redirect('profile')
    else:
        form = UserEditForm(instance=request.user)
    
    return render(request, 'accounts/profile.html', {'form': form})

@login_required
def profile_picture_upload(request):
    """View to handle profile picture uploads"""
    if request.method == 'POST':
        if 'picture' in request.FILES:
            request.user.profile_picture = request.FILES['picture']
            request.user.save()
            messages.success(request, 'Profile picture updated successfully.')
            return redirect('profile')
    return redirect('profile')

def password_reset_request(request):
    if request.method == 'POST':
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = CustomUser.objects.get(email=email)
                # Generate OTP
                otp = ''.join(random.choices(string.digits, k=6))
                otp_obj = PasswordResetOTP.objects.create(user=user, otp=otp)
                
                # Print OTP to terminal
                print("\n")
                print("=" * 70)
                print("\n   PASSWORD RESET OTP DETAILS")
                print(f"\n   Email: {email}")
                print(f"\n   OTP: {otp}")
                print("\n   Please use this OTP to reset your password")
                print("\n")
                print("=" * 70)
                print("\n")
                
                # Also log to Django's logger
                logger.info(f"Password Reset OTP for {email}: {otp}")
                
                # TODO: Send OTP via email
                log_security_event(f"Password reset OTP generated for user: {email}")
                messages.success(request, 'Password reset OTP has been sent to your email.')
                request.session['reset_email'] = email
                return redirect('verify_otp')
            except CustomUser.DoesNotExist:
                log_security_event(f"Password reset attempted for non-existent user: {email}", level='warning')
                messages.error(request, 'No user found with this email address.')
                return render(request, 'accounts/password_reset_request.html', {'form': form})
    else:
        form = PasswordResetRequestForm()
    return render(request, 'accounts/password_reset_request.html', {'form': form})

def verify_otp(request):
    """View to verify OTP for password reset"""
    if 'reset_email' not in request.session:
        messages.error(request, 'Please request a password reset first.')
        return redirect('password_reset_request')

    email = request.session['reset_email']
    try:
        user = CustomUser.objects.get(email=email)
    except CustomUser.DoesNotExist:
        messages.error(request, 'Invalid session. Please try again.')
        return redirect('password_reset_request')

    if request.method == 'POST':
        form = OTPVerificationForm(request.POST)
        if form.is_valid():
            otp = form.cleaned_data['otp']
            try:
                otp_obj = PasswordResetOTP.objects.filter(
                    user=user,
                    otp=otp,
                    is_used=False
                ).latest('created_at')
                
                if otp_obj.is_valid():
                    otp_obj.is_used = True
                    otp_obj.save()
                    request.session['reset_user_id'] = user.id
                    log_security_event(f"OTP verified successfully for user: {email}")
                    messages.success(request, 'OTP verified successfully.')
                    return redirect('set_new_password')
                else:
                    status = otp_obj.get_status()
                    if status == "expired":
                        messages.error(request, 'OTP has expired. Please request a new one.')
                    elif status == "used":
                        messages.error(request, 'This OTP has already been used. Please request a new one.')
                    elif status == "superseded":
                        messages.error(request, 'A newer OTP has been generated. Please use the latest OTP sent to your email.')
                    else:
                        messages.error(request, 'Invalid OTP. Please try again.')
            except PasswordResetOTP.DoesNotExist:
                log_security_event(f"Invalid OTP attempt for user: {email}", level='warning')
                messages.error(request, 'Invalid OTP. Please try again.')
    else:
        form = OTPVerificationForm()
    
    return render(request, 'accounts/verify_otp.html', {
        'form': form,
        'email': email,
        'resend_url': reverse('password_reset_request')
    })

@csrf_protect
def set_new_password(request):
    """View to set new password after OTP verification"""
    if 'reset_user_id' not in request.session:
        messages.error(request, 'Password reset session has expired.')
        return redirect('password_reset_request')

    user = get_object_or_404(CustomUser, id=request.session['reset_user_id'])

    if request.method == 'POST':
        form = SetNewPasswordForm(request.POST)
        if form.is_valid():
            new_password = form.cleaned_data['new_password1']
            user.set_password(new_password)
            user.save()

            # Clear all session data related to password reset
            for key in ['reset_user_id', 'reset_email', 'otp_verified']:
                request.session.pop(key, None)

            log_auth_event(f"Password reset successful for user: {user.email}")
            messages.success(request, 'Your password has been reset successfully. Please log in with your new password.')
            return redirect('login')
        else:
            messages.error(request, 'Please correct the errors below.')
            return render(request, 'accounts/set_new_password.html', {'form': form})
    else:
        form = SetNewPasswordForm()

    return render(request, 'accounts/set_new_password.html', {'form': form})

@login_required
def logout_view(request):
    """View to handle user logout"""
    email = request.user.email
    logout(request)
    log_auth_event(
        f"User logged out: {email}",
        level='info',
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )
    messages.info(request, 'You have been logged out.')
    return redirect('login')

@login_required
@csrf_protect
def password_change(request):
    """View to handle password change with session invalidation"""
    if request.method == 'POST':
        form = PasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            # Change password
            request.user.set_password(form.cleaned_data['new_password1'])
            request.user.save()
            
            # Log the password change
            log_security_event(f"Password changed successfully for user: {request.user.email}")
            
            # Log the user out (this will clear the current session)
            logout(request)
            
            messages.success(request, 'Your password has been changed successfully. Please log in with your new password.')
            return redirect('login')
    else:
        form = PasswordChangeForm(user=request.user)
    
    return render(request, 'accounts/password_change.html', {'form': form})

def custom_404(request, exception):
    """Custom 404 error page"""
    return render(request, 'errors/404.html', status=404)

def custom_500(request):
    """Custom 500 error page"""
    return render(request, 'errors/500.html', status=500)

def custom_403(request, exception):
    """Custom 403 error page"""
    return render(request, 'errors/403.html', status=403)

def home(request):
    """View for the home page"""
    return render(request, 'accounts/home.html')
