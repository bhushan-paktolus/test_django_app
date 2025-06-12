from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, PasswordResetForm, SetPasswordForm
from django.contrib.auth import password_validation
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Row, Column, Submit, HTML, Field
from .models import CustomUser, phone_regex
from django.contrib.auth import get_user_model
import re
from django.core.validators import RegexValidator, MinLengthValidator, MaxLengthValidator

User = get_user_model()

class UserRegisterForm(UserCreationForm):
    email = forms.EmailField()
    first_name = forms.CharField(
        max_length=30,
        validators=[
            RegexValidator(
                regex='^[a-zA-Z\s-]+$',
                message='First name can only contain letters, spaces and hyphens.',
                code='invalid_first_name'
            ),
            MinLengthValidator(2),
            MaxLengthValidator(30)
        ]
    )
    last_name = forms.CharField(
        max_length=30,
        validators=[
            RegexValidator(
                regex='^[a-zA-Z\s-]+$',
                message='Last name can only contain letters, spaces and hyphens.',
                code='invalid_last_name'
            ),
            MinLengthValidator(2),
            MaxLengthValidator(30)
        ]
    )
    phone = forms.CharField(
        max_length=15,
        required=False,
        validators=[
            RegexValidator(
                regex='^\+?1?\d{10,15}$',
                message='Phone number must be entered in the format: "+999999999". Up to 15 digits allowed.',
                code='invalid_phone'
            )
        ]
    )
    role = forms.ChoiceField(choices=CustomUser.ROLE_CHOICES, initial='user')
    password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your password'
        }),
        help_text=password_validation.password_validators_help_text_html()
    )
    password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm your password'
        }),
        help_text='Enter the same password as above, for verification.'
    )

    class Meta:
        model = CustomUser
        fields = ['email', 'first_name', 'last_name', 'phone', 'role', 'password1', 'password2']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_tag = False
        self.helper.form_class = 'user-form'
        self.helper.layout = Layout(
            Row(
                Column('email', css_class='form-group col-md-12 mb-3'),
                css_class='form-row'
            ),
            Row(
                Column('first_name', css_class='form-group col-md-6 mb-3'),
                Column('last_name', css_class='form-group col-md-6 mb-3'),
                css_class='form-row'
            ),
            Row(
                Column('phone', css_class='form-group col-md-6 mb-3'),
                Column('role', css_class='form-group col-md-6 mb-3'),
                css_class='form-row'
            ),
            Row(
                Column('password1', css_class='form-group col-md-6 mb-3'),
                Column('password2', css_class='form-group col-md-6 mb-3'),
                css_class='form-row'
            )
        )

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email:
            email = email.lower()
            if CustomUser.objects.filter(email=email).exists():
                raise ValidationError('This email is already registered.')
        return email

    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        if phone:
            phone = phone.replace(' ', '')
        return phone

    def clean_first_name(self):
        first_name = self.cleaned_data.get('first_name')
        if not first_name:
            raise ValidationError('First name is required.')
        if not re.match(r'^[a-zA-Z\s-]+$', first_name):
            raise ValidationError('First name can only contain letters, spaces and hyphens.')
        return first_name.title()

    def clean_last_name(self):
        last_name = self.cleaned_data.get('last_name')
        if not last_name:
            raise ValidationError('Last name is required.')
        if not re.match(r'^[a-zA-Z\s-]+$', last_name):
            raise ValidationError('Last name can only contain letters, spaces and hyphens.')
        return last_name.title()

    def clean_password1(self):
        password = self.cleaned_data.get('password1')
        if password:
            # Django's built-in password validation
            validate_password(password)
            # Additional custom password requirements
            if not any(char.isupper() for char in password):
                raise ValidationError('Password must contain at least one uppercase letter.')
            if not any(char.islower() for char in password):
                raise ValidationError('Password must contain at least one lowercase letter.')
            if not any(char.isdigit() for char in password):
                raise ValidationError('Password must contain at least one number.')
            if not any(char in '!@#$%^&*()' for char in password):
                raise ValidationError('Password must contain at least one special character (!@#$%^&*()).')
            if len(password) < 8:
                raise ValidationError('Password must be at least 8 characters long.')
            if len(password) > 128:
                raise ValidationError('Password cannot exceed 128 characters.')
        return password

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')
        if password1 and password2 and password1 != password2:
            raise ValidationError('The two password fields do not match.')
        return password2

    def clean(self):
        cleaned_data = super().clean()
        # Additional cross-field validation can be added here
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        user.first_name = self.cleaned_data['first_name']
        user.last_name = self.cleaned_data['last_name']
        user.phone = self.cleaned_data['phone']
        user.role = self.cleaned_data['role']
        if commit:
            user.save()
        return user

class UserEditForm(forms.ModelForm):
    first_name = forms.CharField(max_length=30, required=True)
    last_name = forms.CharField(max_length=30, required=True)
    phone = forms.CharField(max_length=15, required=True, validators=[phone_regex])

    class Meta:
        model = CustomUser
        fields = ('first_name', 'last_name', 'phone')

    def clean_first_name(self):
        first_name = self.cleaned_data.get('first_name')
        if not first_name:
            raise forms.ValidationError('First name is required.')
        return first_name  # Return without changing case

    def clean_last_name(self):
        last_name = self.cleaned_data.get('last_name')
        if not last_name:
            raise forms.ValidationError('Last name is required.')
        return last_name  # Return without changing case

    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        if not phone:
            raise forms.ValidationError('Phone number is required.')
        return phone

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.form_class = 'user-form'
        self.helper.layout = Layout(
            Row(
                Column('first_name', css_class='form-group col-md-6 mb-3'),
                Column('last_name', css_class='form-group col-md-6 mb-3'),
                css_class='form-row'
            ),
            Row(
                Column('phone', css_class='form-group col-md-6 mb-3'),
                css_class='form-row'
            ),
            Submit('submit', 'Update Profile', css_class='btn btn-primary')
        )

class PasswordResetRequestForm(forms.Form):
    email = forms.EmailField()

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email:
            email = email.lower()
        return email

class OTPVerificationForm(forms.Form):
    otp = forms.CharField(
        label='Enter OTP',
        max_length=6,
        min_length=6,
        help_text='Enter the 6-digit code sent to your email.',
        widget=forms.TextInput(attrs={
            'class': 'form-control form-control-lg text-center',
            'pattern': '[0-9]*',
            'inputmode': 'numeric',
            'autocomplete': 'one-time-code',
            'placeholder': '• • • • • •',
            'style': 'letter-spacing: 0.5em; font-size: 1.5em;'
        })
    )

    def clean_otp(self):
        otp = self.cleaned_data['otp']
        if not otp.isdigit():
            raise ValidationError('OTP must contain only numbers.')
        if len(otp) != 6:
            raise ValidationError('OTP must be exactly 6 digits.')
        return otp

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_tag = False
        self.helper.form_class = 'otp-form'
        self.helper.layout = Layout(
            Field('otp', wrapper_class='mb-3 text-center')
        )

class SetNewPasswordForm(forms.Form):
    new_password1 = forms.CharField(
        widget=forms.PasswordInput(),
        validators=[
            MinLengthValidator(8, message="Password must be at least 8 characters long."),
            RegexValidator(
                regex=r'[A-Z]',
                message="Password must contain at least one uppercase letter.",
            ),
            RegexValidator(
                regex=r'[a-z]',
                message="Password must contain at least one lowercase letter.",
            ),
            RegexValidator(
                regex=r'[0-9]',
                message="Password must contain at least one number.",
            ),
            RegexValidator(
                regex=r'[!@#$%^&*(),.?":{}|<>]',
                message="Password must contain at least one special character.",
            ),
            MaxLengthValidator(128, message="Password cannot be longer than 128 characters."),
        ]
    )
    new_password2 = forms.CharField(widget=forms.PasswordInput())

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('new_password1')
        password2 = cleaned_data.get('new_password2')

        if password1 and password2 and password1 != password2:
            self.add_error('new_password2', "The two password fields didn't match.")

        return cleaned_data

class EmailAuthenticationForm(AuthenticationForm):
    username = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'autofocus': True,
            'class': 'form-control',
            'placeholder': 'Email'
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Password'
        })
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].label = 'Email'

    def clean_username(self):
        email = self.cleaned_data.get('username')
        if email:
            email = email.lower()
        return email

class PasswordChangeForm(forms.Form):
    old_password = forms.CharField(
        label='Current Password',
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
        required=True
    )
    new_password1 = forms.CharField(
        label='New Password',
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
        required=True,
        validators=[
            MinLengthValidator(12, message="Password must be at least 12 characters long."),
            RegexValidator(
                regex=r'[A-Z]',
                message="Password must contain at least one uppercase letter.",
            ),
            RegexValidator(
                regex=r'[a-z]',
                message="Password must contain at least one lowercase letter.",
            ),
            RegexValidator(
                regex=r'[0-9]',
                message="Password must contain at least one number.",
            ),
            RegexValidator(
                regex=r'[!@#$%^&*(),.?":{}|<>]',
                message="Password must contain at least one special character.",
            ),
            MaxLengthValidator(128, message="Password cannot be longer than 128 characters."),
        ]
    )
    new_password2 = forms.CharField(
        label='Confirm New Password',
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
        required=True
    )

    def __init__(self, user=None, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.form_class = 'mt-3'
        self.helper.layout = Layout(
            Field('old_password', css_class='mb-3'),
            Field('new_password1', css_class='mb-3'),
            Field('new_password2', css_class='mb-3'),
            Submit('submit', 'Change Password', css_class='btn btn-primary w-100 mt-4')
        )

    def clean_old_password(self):
        old_password = self.cleaned_data.get('old_password')
        if not self.user.check_password(old_password):
            raise ValidationError('Your current password was entered incorrectly.')
        return old_password

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('new_password1')
        password2 = cleaned_data.get('new_password2')

        if password1 and password2:
            if password1 != password2:
                raise ValidationError("The two password fields didn't match.")
            
            # Check if new password is different from old password
            if self.user.check_password(password1):
                raise ValidationError("New password must be different from the current password.")
            
            try:
                # Validate password against Django's password validation
                validate_password(password1, self.user)
            except ValidationError as e:
                self.add_error('new_password1', e)

        return cleaned_data