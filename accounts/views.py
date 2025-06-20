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
from django.utils.http import url_has_allowed_host_and_scheme
from django_otp import devices_for_user
from django_otp.plugins.otp_totp.models import TOTPDevice
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
from .models import CustomUser, PasswordResetOTP, UserActivity, BackupCode
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
from django.db.models import Q
import qrcode
import qrcode.image.svg
from io import BytesIO
import base64

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
    
    # Handle search query
    search_query = request.GET.get('q', '').strip()
    if search_query:
        # Split the search query into words
        search_words = search_query.split()
        
        # Start with an empty Q object
        query = Q()
        
        # Add each word to the query
        for word in search_words:
            word_query = (
                Q(email__icontains=word) |
                Q(first_name__icontains=word) |
                Q(last_name__icontains=word) |
                Q(username__icontains=word) |
                Q(role__icontains=word)
            )
            query &= word_query  # Use AND for multiple words
        
        users = users.filter(query)
    
    # Calculate user statistics
    total_users = CustomUser.objects.count()
    active_users = CustomUser.objects.filter(is_active=True).count()
    admin_users = CustomUser.objects.filter(role='admin').count()
    recent_users = CustomUser.objects.order_by('-date_joined')[:5].count()
    
    context = {
        'users': users,
        'total_users': total_users,
        'active_users': active_users,
        'admin_users': admin_users,
        'recent_users': recent_users,
        'search_query': search_query,
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
    try:
        user_to_delete = get_object_or_404(CustomUser, id=user_id)
        
        # Check permissions
        if not (request.user.is_superuser or request.user.role == 'staff'):
            logger.warning(f"Unauthorized attempt to delete user {user_id} by {request.user.email}")
            return JsonResponse({
                'status': 'error',
                'message': "You don't have permission to delete users."
            }, status=403)
        
        # Staff can't delete admins or other staff
        if request.user.role == 'staff' and (user_to_delete.is_superuser or user_to_delete.role in ['admin', 'staff']):
            logger.warning(f"Staff member {request.user.email} attempted to delete privileged user {user_to_delete.email}")
            return JsonResponse({
                'status': 'error',
                'message': "Staff members cannot delete admin or other staff users."
            }, status=403)
        
        # Prevent deleting yourself
        if user_to_delete == request.user:
            return JsonResponse({
                'status': 'error',
                'message': "You cannot delete your own account."
            }, status=400)
        
        # Prevent deleting superusers
        if user_to_delete.is_superuser:
            return JsonResponse({
                'status': 'error',
                'message': "Superuser accounts cannot be deleted."
            }, status=400)

        if request.method == 'POST':
            try:
                # Store the email for the success message before deletion
                user_email = user_to_delete.email
                user_to_delete.delete()
                logger.info(f"User {user_email} deleted successfully by {request.user.email}")
                
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({
                        'status': 'success',
                        'message': f"User {user_email} has been deleted successfully."
                    })
                
                messages.success(request, f"User {user_email} has been deleted successfully.")
                return redirect('user_list')
            
            except Exception as e:
                logger.error(f"Error deleting user {user_to_delete.email}: {str(e)}")
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({
                        'status': 'error',
                        'message': "An error occurred while deleting the user."
                    }, status=500)
                
                messages.error(request, "An error occurred while deleting the user.")
                return redirect('user_list')
        
        # If it's a GET request, show the confirmation page
        return render(request, 'accounts/user_delete_confirm.html', {
            'user_to_delete': user_to_delete
        })
    
    except CustomUser.DoesNotExist:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                'status': 'error',
                'message': "User not found."
            }, status=404)
        
        messages.error(request, "User not found.")
        return redirect('user_list')
    
    except Exception as e:
        logger.error(f"Unexpected error in user_delete view: {str(e)}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                'status': 'error',
                'message': "An unexpected error occurred."
            }, status=500)
        
        messages.error(request, "An unexpected error occurred.")
        return redirect('user_list')

# Rate limiting helper functions
def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def check_rate_limit(request, prefix='login', max_attempts=MAX_LOGIN_ATTEMPTS, timeout=LOGIN_ATTEMPT_TIMEOUT):
    """Check if the request has exceeded the rate limit"""
    client_ip = get_client_ip(request)
    user_id = request.session.get('2fa_user_id', 'anonymous')
    cache_key = f"{prefix}_{user_id}_{client_ip}"
    attempts = cache.get(cache_key, 0)
    
    logger.debug(f"Rate limit check - Prefix: {prefix}, User: {user_id}, IP: {client_ip}, Attempts: {attempts}, Max: {max_attempts}")
    
    if attempts >= max_attempts:
        logger.warning(f"{prefix.title()} blocked due to too many attempts - User: {user_id}, IP: {client_ip}, Attempts: {attempts}")
        return True
    return False

def increment_attempts(request, prefix='login', timeout=LOGIN_ATTEMPT_TIMEOUT):
    """Increment the number of attempts for the request"""
    client_ip = get_client_ip(request)
    user_id = request.session.get('2fa_user_id', 'anonymous')
    cache_key = f"{prefix}_{user_id}_{client_ip}"
    attempts = cache.get(cache_key, 0)
    attempts += 1
    cache.set(cache_key, attempts, timeout)
    logger.debug(f"Incremented attempts - Prefix: {prefix}, User: {user_id}, IP: {client_ip}, New Attempts: {attempts}")

def reset_attempts(request, prefix='login'):
    """Reset the number of attempts for the request"""
    client_ip = get_client_ip(request)
    user_id = request.session.get('2fa_user_id', 'anonymous')
    cache_key = f"{prefix}_{user_id}_{client_ip}"
    cache.delete(cache_key)
    logger.debug(f"Reset attempts - Prefix: {prefix}, User: {user_id}, IP: {client_ip}")

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
    """View to handle user login with 2FA support"""
    if request.method == 'POST':
        logger.debug(f"Processing login POST request - IP: {get_client_ip(request)}")
        
        # Check rate limiting
        if check_rate_limit(request):
            logger.warning(f"Login rate limit exceeded - IP: {get_client_ip(request)}")
            return rate_limit_response(request)

        form = EmailAuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            logger.debug(f"Login form valid for user: {user.email}")
            
            # Check if 2FA is enabled
            if user.two_factor_enabled:
                logger.debug(f"2FA enabled for user: {user.email}, redirecting to verification")
                # Log the user in but mark them as needing 2FA verification
                login(request, user)
                request.session['2fa_user_id'] = user.id
                request.session['2fa_verified'] = False
                request.session['next'] = request.GET.get('next', 'home')
                return redirect('verify_2fa')
            
            # If 2FA is not enabled, proceed with normal login
            login(request, user)
            reset_attempts(request)
            request.session['2fa_verified'] = True

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

            next_url = request.GET.get('next')
            if next_url and url_has_allowed_host_and_scheme(
                url=next_url,
                allowed_hosts={request.get_host()},
                require_https=request.is_secure()
            ):
                logger.debug(f"Redirecting to next URL: {next_url}")
                return redirect(next_url)
            logger.debug("Redirecting to home")
            return redirect('home')
        else:
            logger.debug("Login form invalid")
            increment_attempts(request)
            email = request.POST.get('username', '')
            try:
                user = CustomUser.objects.get(email=email)
                ip_address = get_client_ip(request)
                user_agent = request.META.get('HTTP_USER_AGENT', '')
                log_auth_event(
                    f"Failed login attempt for user: {email}",
                    level='warning',
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                UserActivity.objects.create(
                    user=user,
                    activity_type='login_failed',
                    ip_address=ip_address,
                    user_agent=user_agent
                )
            except CustomUser.DoesNotExist:
                log_auth_event(
                    f"Failed login attempt for non-existent user: {email}",
                    level='warning',
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
    else:
        logger.debug("Displaying login form")
        form = EmailAuthenticationForm(request)

    return render(request, 'accounts/login.html', {'form': form})

def two_factor_required(function):
    """Decorator to require 2FA for views"""
    def wrap(request, *args, **kwargs):
        if not request.user.is_authenticated:
            # Store the requested URL in the session
            request.session['next'] = request.get_full_path()
            return redirect('login')
            
        if request.user.two_factor_enabled and not request.session.get('2fa_verified'):
            # Store the requested URL in the session
            request.session['next'] = request.get_full_path()
            request.session['2fa_user_id'] = request.user.id
            return redirect('verify_2fa')
            
        return function(request, *args, **kwargs)
    return wrap

@two_factor_required
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

@two_factor_required
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

@two_factor_required
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

@login_required
@csrf_protect
def setup_2fa(request):
    """View to set up 2FA for a user"""
    if request.user.two_factor_enabled:
        messages.warning(request, '2FA is already enabled for your account.')
        return redirect('profile')

    # Get existing device or create a new one
    device = TOTPDevice.objects.filter(user=request.user, confirmed=False).first()
    
    if not device:
        # Only create a new device if none exists
        device = TOTPDevice.objects.create(
            user=request.user,
            name=f"Default TOTP device for {request.user.email}",
            confirmed=False
        )
        logger.info(f"Created new TOTP device for {request.user.email}")

    if request.method == 'POST':
        token = request.POST.get('token')
        logger.info(f"Verifying token for user {request.user.email}: {token}")
        
        try:
            # Validate token format
            if not token or not token.isdigit() or len(token) != 6:
                messages.error(request, 'Please enter a valid 6-digit code.')
                return render(request, 'accounts/setup_2fa.html', {
                    'qr_code_data': qr_code_data,
                    'secret_key': device.config_url
                })

            # Verify the token with a small time window
            if device.verify_token(token):
                # Generate backup codes before enabling 2FA
                backup_codes = BackupCode.generate_backup_codes(request.user)
                
                device.confirmed = True
                device.save()
                request.user.two_factor_enabled = True
                request.user.save()
                
                logger.info(f"2FA successfully enabled for user {request.user.email}")
                messages.success(request, '2FA has been successfully enabled for your account.')
                
                # Show backup codes to user
                return render(request, 'accounts/backup_codes.html', {
                    'backup_codes': backup_codes
                })
            else:
                logger.warning(f"Invalid token attempt for user {request.user.email}: {token}")
                messages.error(request, 
                    'Invalid verification code. Please enter the current code shown in your authenticator app. '
                    'Note that codes expire every 30 seconds.'
                )
        except Exception as e:
            logger.error(f"Error verifying token for user {request.user.email}: {str(e)}")
            messages.error(request, 'An error occurred while verifying the code. Please try again.')

    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    
    qr.add_data(device.config_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer)
    qr_code_data = base64.b64encode(buffer.getvalue()).decode()

    return render(request, 'accounts/setup_2fa.html', {
        'qr_code_data': qr_code_data,
        'secret_key': device.config_url
    })

@login_required
@two_factor_required
@csrf_protect
def disable_2fa(request):
    """View to disable 2FA"""
    if not request.user.two_factor_enabled:
        messages.warning(request, '2FA is not enabled for your account.')
        return redirect('profile')

    if request.method == 'POST':
        request.user.disable_2fa()
        messages.success(request, '2FA has been disabled for your account.')
        return redirect('profile')

    return render(request, 'accounts/disable_2fa.html')

@csrf_protect
def verify_2fa(request):
    """View to verify 2FA token during login"""
    logger.debug(f"Processing 2FA verification request - IP: {get_client_ip(request)}")
    
    if not request.session.get('2fa_user_id'):
        logger.warning("No 2FA user ID in session, redirecting to login")
        return redirect('login')

    try:
        user = CustomUser.objects.get(id=request.session['2fa_user_id'])
        device = user.get_totp_device()
        logger.debug(f"Found TOTP device for user: {user.email}")
        
        if not device:
            logger.error(f"No TOTP device found for user {user.email}")
            messages.error(request, 'No 2FA device found. Please contact support.')
            return redirect('login')

        if request.method == 'POST':
            # Check rate limit (5 attempts in 5 minutes)
            if check_rate_limit(request, prefix='2fa', max_attempts=5, timeout=300):
                logger.warning(f"Rate limit exceeded for 2FA verification: {user.email}")
                return render(request, '429.html', status=429)

            token = request.POST.get('token')
            logger.info(f"Verifying 2FA token for user {user.email}: {token}")
            
            try:
                # First check if it's a backup code
                backup_code = BackupCode.objects.filter(
                    user=user,
                    code=token,
                    used=False
                ).first()

                if backup_code:
                    logger.debug(f"Valid backup code used for user: {user.email}")
                    # Mark the backup code as used
                    backup_code.used = True
                    backup_code.used_at = timezone.now()
                    backup_code.save()
                    
                    # Complete the login
                    login(request, user)
                    del request.session['2fa_user_id']
                    request.session['2fa_verified'] = True
                    reset_attempts(request, prefix='2fa')
                    
                    logger.info(f"Successful 2FA verification using backup code for user {user.email}")
                    messages.success(request, 'Login successful using backup code.')
                    messages.warning(request, 'You have used a backup code to login. Please generate new backup codes if needed.')
                    return redirect(request.session.get('next', 'home'))

                # If not a backup code, validate token format
                if not token or not token.isdigit() or len(token) != 6:
                    logger.debug(f"Invalid token format: {token}")
                    increment_attempts(request, prefix='2fa')
                    messages.error(request, 'Invalid verification code. Please enter a valid 6-digit code or backup code.')
                    return render(request, 'accounts/verify_2fa.html')

                # Try to verify with a small time window
                if device.verify_token(token):
                    logger.debug(f"Valid TOTP token for user: {user.email}")
                    # Complete the login
                    login(request, user)
                    del request.session['2fa_user_id']
                    request.session['2fa_verified'] = True
                    reset_attempts(request, prefix='2fa')
                    
                    logger.info(f"Successful 2FA verification for user {user.email}")
                    messages.success(request, f'Welcome back, {user.get_full_name() or user.email}!')
                    return redirect(request.session.get('next', 'home'))
                else:
                    logger.warning(f"Invalid 2FA token attempt for user {user.email}: {token}")
                    increment_attempts(request, prefix='2fa')
                    messages.error(request, 'Invalid verification code. Please try again.')
                    
            except Exception as e:
                logger.error(f"Error verifying 2FA token for user {user.email}: {str(e)}")
                increment_attempts(request, prefix='2fa')
                messages.error(request, 'An error occurred while verifying the code. Please try again.')
    except CustomUser.DoesNotExist:
        logger.error(f"Invalid user ID in session: {request.session.get('2fa_user_id')}")
        messages.error(request, 'Invalid session. Please try logging in again.')
        return redirect('login')
    except Exception as e:
        logger.error(f"Unexpected error in verify_2fa: {str(e)}")
        messages.error(request, 'An unexpected error occurred. Please try again.')
        return redirect('login')

    return render(request, 'accounts/verify_2fa.html')
