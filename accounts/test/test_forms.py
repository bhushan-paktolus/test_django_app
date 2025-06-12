from django.test import TestCase
from django.core.exceptions import ValidationError
from accounts.forms import (
    UserRegisterForm,
    UserEditForm,
    PasswordResetRequestForm,
    SetNewPasswordForm,
    EmailAuthenticationForm
)
from accounts.models import CustomUser

class TestUserRegisterForm(TestCase):
    def setUp(self):
        self.valid_data = {
            'email': 'test@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'phone': '+1234567890',
            'role': 'user',
            'password1': 'TestPass123!',
            'password2': 'TestPass123!'
        }

    def test_valid_form(self):
        form = UserRegisterForm(data=self.valid_data)
        self.assertTrue(form.is_valid())

    def test_password_validation(self):
        # Test too short password
        data = self.valid_data.copy()
        data['password1'] = data['password2'] = 'short'
        form = UserRegisterForm(data=data)
        self.assertFalse(form.is_valid())
        self.assertIn('password1', form.errors)

        # Test password without uppercase
        data['password1'] = data['password2'] = 'testpass123!'
        form = UserRegisterForm(data=data)
        self.assertFalse(form.is_valid())
        self.assertIn('password1', form.errors)

        # Test password without lowercase
        data['password1'] = data['password2'] = 'TESTPASS123!'
        form = UserRegisterForm(data=data)
        self.assertFalse(form.is_valid())
        self.assertIn('password1', form.errors)

        # Test password without number
        data['password1'] = data['password2'] = 'TestPassWord!'
        form = UserRegisterForm(data=data)
        self.assertFalse(form.is_valid())
        self.assertIn('password1', form.errors)

        # Test password without special character
        data['password1'] = data['password2'] = 'TestPass123'
        form = UserRegisterForm(data=data)
        self.assertFalse(form.is_valid())
        self.assertIn('password1', form.errors)

        # Test password too long
        data['password1'] = data['password2'] = 'T' * 129
        form = UserRegisterForm(data=data)
        self.assertFalse(form.is_valid())
        self.assertIn('password1', form.errors)

    def test_password_mismatch(self):
        data = self.valid_data.copy()
        data['password2'] = 'DifferentPass123!'
        form = UserRegisterForm(data=data)
        self.assertFalse(form.is_valid())
        self.assertIn('password2', form.errors)

    def test_email_validation(self):
        # Test invalid email format
        data = self.valid_data.copy()
        data['email'] = 'invalid-email'
        form = UserRegisterForm(data=data)
        self.assertFalse(form.is_valid())
        self.assertIn('email', form.errors)

        # Test duplicate email
        CustomUser.objects.create_user(
            email='existing@example.com',
            password='TestPass123!',
            first_name='Test',
            last_name='User'
        )
        data['email'] = 'existing@example.com'
        form = UserRegisterForm(data=data)
        self.assertFalse(form.is_valid())
        self.assertIn('email', form.errors)

    def test_phone_validation(self):
        invalid_phones = [
            '123',  # Too short
            'abc123456789',  # Contains letters
            '+1234',  # Too short with plus
            '+' + '1' * 16,  # Too long
            '++1234567890',  # Multiple plus signs
            '+abc1234567890'  # Invalid characters
        ]
        
        for phone in invalid_phones:
            data = self.valid_data.copy()
            data['phone'] = phone
            form = UserRegisterForm(data=data)
            self.assertFalse(form.is_valid())
            self.assertIn('phone', form.errors)

    def test_name_validation(self):
        invalid_names = [
            'Test123',  # Contains numbers
            'Test@User',  # Contains special characters
            'T',  # Too short
            'A' * 31  # Too long
        ]
        
        # Test first name validation
        for name in invalid_names:
            data = self.valid_data.copy()
            data['first_name'] = name
            form = UserRegisterForm(data=data)
            self.assertFalse(form.is_valid())
            self.assertIn('first_name', form.errors)
        
        # Test last name validation
        for name in invalid_names:
            data = self.valid_data.copy()
            data['last_name'] = name
            form = UserRegisterForm(data=data)
            self.assertFalse(form.is_valid())
            self.assertIn('last_name', form.errors)

    def test_role_validation(self):
        data = self.valid_data.copy()
        data['role'] = 'invalid_role'
        form = UserRegisterForm(data=data)
        self.assertFalse(form.is_valid())
        self.assertIn('role', form.errors)

class TestUserEditForm(TestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email='test@example.com',
            password='TestPass123!',
            first_name='Test',
            last_name='User',
            phone='+1234567890',
            role='user'
        )
        self.valid_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'first_name': 'NewTest',
            'last_name': 'NewUser',
            'phone': '+9876543210',
            'role': 'staff',
            'is_active': True
        }

    def test_valid_form(self):
        form = UserEditForm(data=self.valid_data, instance=self.user)
        self.assertTrue(form.is_valid())

    def test_phone_validation(self):
        data = self.valid_data.copy()
        data['phone'] = 'invalid-phone'
        form = UserEditForm(data=data, instance=self.user)
        self.assertFalse(form.is_valid())
        self.assertIn('phone', form.errors)

class TestPasswordResetRequestForm(TestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email='test@example.com',
            password='TestPass123!'
        )

    def test_valid_email(self):
        form = PasswordResetRequestForm(data={'email': 'test@example.com'})
        self.assertTrue(form.is_valid())

    def test_invalid_email_format(self):
        form = PasswordResetRequestForm(data={'email': 'invalid-email'})
        self.assertFalse(form.is_valid())
        self.assertIn('email', form.errors)

    def test_nonexistent_email(self):
        form = PasswordResetRequestForm(data={'email': 'nonexistent@example.com'})
        self.assertTrue(form.is_valid())  # Form should be valid even with non-existent email
        # The actual user existence check should be done in the view, not the form

    def test_empty_email(self):
        form = PasswordResetRequestForm(data={'email': ''})
        self.assertFalse(form.is_valid())
        self.assertIn('email', form.errors)

class TestSetNewPasswordForm(TestCase):
    def test_valid_password(self):
        form = SetNewPasswordForm(data={
            'new_password1': 'NewSecurePass123!',
            'new_password2': 'NewSecurePass123!'
        })
        self.assertTrue(form.is_valid())

    def test_password_mismatch(self):
        form = SetNewPasswordForm(data={
            'new_password1': 'NewSecurePass123!',
            'new_password2': 'DifferentPass123!'
        })
        self.assertFalse(form.is_valid())
        self.assertIn('new_password2', form.errors)

    def test_password_validation(self):
        invalid_passwords = [
            'short',  # Too short
            'onlylowercase123!',  # No uppercase
            'ONLYUPPERCASE123!',  # No lowercase
            'NoNumbers!',  # No numbers
            'NoSpecialChars123',  # No special characters
            'A' * 129  # Too long
        ]
        
        for password in invalid_passwords:
            form = SetNewPasswordForm(data={
                'new_password1': password,
                'new_password2': password
            })
            self.assertFalse(form.is_valid())
            self.assertIn('new_password1', form.errors)

class TestEmailAuthenticationForm(TestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email='test@example.com',
            password='TestPass123!',
            first_name='Test',
            last_name='User'
        )

    def test_valid_credentials(self):
        form = EmailAuthenticationForm(data={
            'username': 'test@example.com',
            'password': 'TestPass123!'
        })
        self.assertTrue(form.is_valid())

    def test_invalid_email(self):
        form = EmailAuthenticationForm(data={
            'username': 'invalid-email',
            'password': 'TestPass123!'
        })
        self.assertFalse(form.is_valid())
        self.assertIn('username', form.errors)

    def test_wrong_password(self):
        form = EmailAuthenticationForm(data={
            'username': 'test@example.com',
            'password': 'WrongPass123!'
        })
        self.assertFalse(form.is_valid())  # Form validation should fail for wrong password
        self.assertTrue(any('Please enter a correct email and password' in str(err) for err in form.errors.get('__all__', [])))

    def test_nonexistent_user(self):
        form = EmailAuthenticationForm(data={
            'username': 'nonexistent@example.com',
            'password': 'TestPass123!'
        })
        self.assertFalse(form.is_valid())  # Form validation should fail for nonexistent user
        self.assertTrue(any('Please enter a correct email and password' in str(err) for err in form.errors.get('__all__', []))) 