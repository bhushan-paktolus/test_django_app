from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
from datetime import timedelta
import logging
from django.core.validators import RegexValidator, MinLengthValidator, EmailValidator, MaxLengthValidator
import re
import random
from django.core.exceptions import ValidationError

logger = logging.getLogger('accounts')

# Phone number validator
phone_regex = RegexValidator(
    regex=r'^\+?1?\d{9,15}$',
    message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
)

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        
        # Set default role if not provided
        if 'role' not in extra_fields:
            extra_fields['role'] = 'user'
            
        # Handle is_staff and is_superuser based on role
        if extra_fields.get('is_staff'):
            extra_fields['role'] = 'staff'
        if extra_fields.get('is_superuser'):
            extra_fields['role'] = 'admin'
            
        # Remove is_staff and is_superuser from extra_fields as they're properties
        extra_fields.pop('is_staff', None)
        extra_fields.pop('is_superuser', None)
        
        user = self.model(email=email, **extra_fields)
        if password:
            user.set_password(password)
        user.save(using=self._db)
        logger.info(f"Created new user: {email}")
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', 'admin')
        
        if not extra_fields.get('is_staff'):
            raise ValueError('Superuser must have is_staff=True.')
        if not extra_fields.get('is_superuser'):
            raise ValueError('Superuser must have is_superuser=True.')
            
        return self.create_user(email, password, **extra_fields)

def validate_name(value):
    """Validate that the name contains only letters, spaces, and hyphens"""
    if not re.match(r'^[a-zA-Z\s-]+$', value):
        raise ValidationError('Name can only contain letters, spaces, and hyphens.')

class CustomUser(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = [
        ('user', 'User'),
        ('staff', 'Staff'),
        ('admin', 'Admin'),
    ]

    id = models.AutoField(primary_key=True)
    username = models.CharField(
        max_length=150,
        unique=True,
        null=True,
        blank=True,
        validators=[
            RegexValidator(
                regex='^[a-zA-Z0-9_]+$',
                message='Username can only contain letters, numbers, and underscores.',
                code='invalid_username'
            ),
            MinLengthValidator(3),
            MaxLengthValidator(150)
        ],
        error_messages={
            'unique': 'A user with that username already exists.',
            'required': 'Username is required.'
        }
    )

    email = models.EmailField(
        unique=True,
        validators=[EmailValidator(message='Enter a valid email address.')],
        error_messages={
            'unique': 'A user with that email already exists.',
            'required': 'Email address is required.'
        }
    )
    first_name = models.CharField(
        max_length=30,
        validators=[
            RegexValidator(
                regex='^[a-zA-Z\s-]+$',
                message='First name can only contain letters, spaces and hyphens.',
                code='invalid_first_name'
            ),
            MinLengthValidator(2),
            MaxLengthValidator(30)
        ],
        error_messages={
            'required': 'First name is required.'
        }
    )
    last_name = models.CharField(
        max_length=30,
        validators=[
            RegexValidator(
                regex='^[a-zA-Z\s-]+$',
                message='Last name can only contain letters, spaces and hyphens.',
                code='invalid_last_name'
            ),
            MinLengthValidator(2),
            MaxLengthValidator(30)
        ],
        error_messages={
            'required': 'Last name is required.'
        }
    )
    phone = models.CharField(
        max_length=16,
        validators=[phone_regex],
        blank=True,
        null=True,
        help_text="Enter a valid phone number (e.g., '+1234567890')"
    )
    role = models.CharField(
        max_length=10,
        choices=ROLE_CHOICES,
        default='user'
    )
    is_active = models.BooleanField(
        default=True,
        help_text='Designates whether this user should be treated as active.'
    )
    date_joined = models.DateTimeField(default=timezone.now)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        ordering = ['-date_joined']

    def __str__(self):
        return self.email

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"

    def get_short_name(self):
        return self.first_name

    def get_initials(self):
        """Get user's initials from first and last name"""
        initials = ""
        if self.first_name:
            initials += self.first_name[0].upper()
        if self.last_name:
            initials += self.last_name[0].upper()
        return initials if initials else self.email[0].upper()

    @property
    def is_staff(self):
        return self.role in ['staff', 'admin']

    @is_staff.setter
    def is_staff(self, value):
        if value:
            self.role = 'staff' if not self.is_superuser else 'admin'
        else:
            self.role = 'user'

    @property
    def is_superuser(self):
        return self.role == 'admin'

    @is_superuser.setter
    def is_superuser(self, value):
        if value:
            self.role = 'admin'
        else:
            self.role = 'staff' if self.is_staff else 'user'

    def clean(self):
        """Additional model-level validation"""
        super().clean()
        # Ensure email is lowercase
        if self.email:
            self.email = self.email.lower()
        
        # Validate phone number format if provided
        if self.phone:
            # Remove any spaces or special characters except +
            self.phone = re.sub(r'[^\d+]', '', self.phone)
            if not self.phone.startswith('+'):
                self.phone = '+' + self.phone

    def save(self, *args, **kwargs):
        self.clean()
        is_new = self._state.adding
        super().save(*args, **kwargs)
        if is_new:
            logger.info(f"New user account created: {self.email}")
        else:
            logger.info(f"User account updated: {self.email}")

class PasswordResetOTP(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)
    
    def save(self, *args, **kwargs):
        if not self.pk:  # New OTP being created
            # Invalidate all previous OTPs for this user
            PasswordResetOTP.objects.filter(user=self.user).update(is_used=True)
            logger.info(f"New OTP generated for user: {self.user.email}")
        elif self.is_used:
            logger.info(f"OTP verified for user: {self.user.email}")
        super().save(*args, **kwargs)
    
    def is_valid(self):
        """Check if OTP is valid"""
        if self.is_used:
            return False
            
        # Check if OTP is expired (10 minutes)
        time_diff = timezone.now() - self.created_at
        if time_diff.total_seconds() > 600:  # 10 minutes
            return False
            
        # Check if newer OTP exists
        newer_otp = PasswordResetOTP.objects.filter(
            user=self.user,
            created_at__gt=self.created_at
        ).exists()
        if newer_otp:
            return False
            
        return True
    
    def get_status(self):
        """Get the current status of the OTP"""
        if self.is_used:
            return "used"
            
        time_diff = timezone.now() - self.created_at
        if time_diff.total_seconds() > 600:
            return "expired"
            
        if PasswordResetOTP.objects.filter(
            user=self.user,
            created_at__gt=self.created_at
        ).exists():
            return "superseded"
            
        return "valid"

    @classmethod
    def generate_otp(cls, user):
        """Generate a new OTP for the user"""
        otp_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        otp = cls.objects.create(user=user, otp=otp_code)
        return otp

class UserActivity(models.Model):
    user = models.ForeignKey('CustomUser', on_delete=models.CASCADE)
    activity_type = models.CharField(max_length=50)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    
    class Meta:
        verbose_name_plural = 'User Activities'
        ordering = ['-timestamp']
        
    def __str__(self):
        return f"{self.user.email} - {self.activity_type} at {self.timestamp}"



