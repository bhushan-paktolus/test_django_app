import pytest
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from accounts.models import CustomUser, PasswordResetOTP, UserActivity
from django.utils import timezone
from datetime import timedelta

class TestRegistrationView(TestCase):
    def setUp(self):
        self.client = Client()
        self.register_url = reverse('register')

    def test_get_register_page(self):
        response = self.client.get(self.register_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'accounts/register.html')

    def test_successful_registration(self):
        data = {
            'email': 'test@example.com',
            'password1': 'TestPass123!',
            'password2': 'TestPass123!',
            'first_name': 'Test',
            'last_name': 'User',
            'phone': '+1234567890',
            'role': 'user'  # Add role field
        }
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, 302)  # Redirect after success
        self.assertTrue(CustomUser.objects.filter(email='test@example.com').exists())

    def test_invalid_registration(self):
        # Test with invalid data
        data = {
            'email': 'invalid-email',  # Invalid email format
            'password1': 'short',  # Too short password
            'password2': 'different',  # Mismatched passwords
            'first_name': 'Test123',  # Invalid name with numbers
            'last_name': 'User',
            'phone': '123'  # Invalid phone format
        }
        response = self.client.post(self.register_url, data)
        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertFalse(form.is_valid())
        self.assertIn('email', form.errors)
        self.assertIn('Enter a valid email address.', form.errors['email'])

class TestLoginView(TestCase):
    def setUp(self):
        self.client = Client()
        self.login_url = reverse('login')
        self.user = CustomUser.objects.create_user(
            email='test@example.com',
            password='TestPass123!'
        )

    def test_get_login_page(self):
        response = self.client.get(self.login_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'accounts/login.html')

    def test_successful_login(self):
        response = self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'TestPass123!'
        })
        self.assertEqual(response.status_code, 302)  # Redirect after success
        self.assertTrue('_auth_user_id' in self.client.session)

    def test_invalid_login(self):
        response = self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'WrongPass123!'
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse('_auth_user_id' in self.client.session)

    def test_inactive_user_login(self):
        self.user.is_active = False
        self.user.save()
        response = self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'TestPass123!'
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse('_auth_user_id' in self.client.session)

class TestPasswordResetViews(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = CustomUser.objects.create_user(
            email='test@example.com',
            password='TestPass123!'
        )
        self.reset_request_url = reverse('password_reset_request')
        self.verify_otp_url = reverse('verify_otp')
        self.set_new_password_url = reverse('set_new_password')

    def test_password_reset_request(self):
        # Test GET request
        response = self.client.get(self.reset_request_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'accounts/password_reset_request.html')

        # Test POST request with valid email
        response = self.client.post(self.reset_request_url, {'email': 'test@example.com'})
        self.assertEqual(response.status_code, 302)  # Redirect to verify OTP
        self.assertTrue(PasswordResetOTP.objects.filter(user=self.user).exists())

        # Test POST request with invalid email
        response = self.client.post(self.reset_request_url, {'email': 'nonexistent@example.com'})
        self.assertEqual(response.status_code, 200)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('No user found' in str(msg) for msg in messages))

    def test_verify_otp(self):
        # Set up session
        session = self.client.session
        session['reset_email'] = 'test@example.com'
        session.save()

        # Create OTP
        otp = PasswordResetOTP.objects.create(user=self.user, otp='123456')

        # Test GET request
        response = self.client.get(self.verify_otp_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'accounts/verify_otp.html')

        # Test POST request with valid OTP
        response = self.client.post(self.verify_otp_url, {'otp': '123456'})
        self.assertEqual(response.status_code, 302)  # Redirect to set new password
        self.assertTrue('reset_user_id' in self.client.session)

        # Test POST request with invalid OTP
        response = self.client.post(self.verify_otp_url, {'otp': '654321'})
        self.assertEqual(response.status_code, 200)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Invalid OTP' in str(msg) for msg in messages))

        # Test expired OTP
        otp.created_at = timezone.now() - timedelta(minutes=16)  # Assuming 15 minutes expiry
        otp.save()
        response = self.client.post(self.verify_otp_url, {'otp': '123456'})
        self.assertEqual(response.status_code, 200)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('OTP has expired' in str(msg) for msg in messages))

    def test_set_new_password(self):
        # Test GET request without session data
        response = self.client.get(self.set_new_password_url)
        self.assertEqual(response.status_code, 302)  # Should redirect to password reset request

        # Set up session
        session = self.client.session
        session['reset_user_id'] = self.user.id
        session.save()

        # Test GET request with session data
        response = self.client.get(self.set_new_password_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'accounts/set_new_password.html')

        # Test POST request with mismatched passwords
        response = self.client.post(self.set_new_password_url, {
            'new_password1': 'NewTestPass123!',
            'new_password2': 'DifferentPass123!'
        })
        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertFalse(form.is_valid())
        self.assertIn('new_password2', form.errors)
        self.assertEqual(form.errors['new_password2'][0], "The two password fields didn't match.")

        # Test POST request with valid passwords
        response = self.client.post(self.set_new_password_url, {
            'new_password1': 'NewTestPass123!',
            'new_password2': 'NewTestPass123!'
        })
        self.assertEqual(response.status_code, 302)  # Redirect to login
        self.assertRedirects(response, reverse('login'))
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('NewTestPass123!'))

class TestProfileView(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = CustomUser.objects.create_user(
            email='test@example.com',
            password='TestPass123!',
            first_name='Test',
            last_name='User',
            phone='+1234567890'
        )
        self.profile_url = reverse('profile')
        self.client.login(username='test@example.com', password='TestPass123!')

    def test_get_profile_page(self):
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'accounts/profile.html')
        self.assertEqual(response.context['user'], self.user)

    def test_update_profile(self):
        updated_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'first_name': 'NewTest',
            'last_name': 'NewUser',
            'phone': '+9876543210',
            'role': 'user',
            'is_active': True
        }
        response = self.client.post(self.profile_url, updated_data)
        self.assertEqual(response.status_code, 302)  # Redirect after success
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'NewTest')
        self.assertEqual(self.user.last_name, 'NewUser')
        self.assertEqual(self.user.phone, '+9876543210')

    def test_invalid_profile_update(self):
        invalid_data = {
            'first_name': 'Test123',  # Invalid name with numbers
            'last_name': 'User',
            'phone': '+1234567890',
            'email': 'test@example.com'  # Keep the same email
        }
        response = self.client.post(self.profile_url, invalid_data)
        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertFalse(form.is_valid())
        self.assertIn('first_name', form.errors)
        self.assertEqual(form.errors['first_name'][0], 'First name can only contain letters, spaces and hyphens.')

class TestLogoutView(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = CustomUser.objects.create_user(
            email='test@example.com',
            password='TestPass123!'
        )
        self.logout_url = reverse('logout')
        self.client.login(username='test@example.com', password='TestPass123!')

    def test_logout(self):
        response = self.client.get(self.logout_url)
        self.assertEqual(response.status_code, 302)  # Redirect after logout
        self.assertFalse('_auth_user_id' in self.client.session)

class TestUserActivityLogging(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = CustomUser.objects.create_user(
            email='test@example.com',
            password='TestPass123!'
        )
        self.login_url = reverse('login')

    def test_login_activity_logging(self):
        response = self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'TestPass123!'
        })
        self.assertEqual(response.status_code, 302)
        self.assertTrue(UserActivity.objects.filter(
            user=self.user,
            activity_type='login_success'
        ).exists())

    def test_failed_login_activity_logging(self):
        response = self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'WrongPass123!'
        })
        self.assertEqual(response.status_code, 200)
        self.assertTrue(UserActivity.objects.filter(
            user=self.user,
            activity_type='login_failed'
        ).exists()) 