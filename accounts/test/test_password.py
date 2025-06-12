from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.messages import get_messages
from accounts.models import CustomUser, PasswordResetOTP
from django.utils import timezone
from datetime import timedelta
from accounts.forms import SetNewPasswordForm, OTPVerificationForm

class PasswordSecurityTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = CustomUser.objects.create_user(
            email='test@example.com',
            password='TestPass123!',
            first_name='Test',
            last_name='User'
        )
        self.reset_request_url = reverse('password_reset_request')
        self.verify_otp_url = reverse('verify_otp')
        self.set_new_password_url = reverse('set_new_password')

    def test_password_reset_flow(self):
        """Test complete password reset flow"""
        # Request password reset
        response = self.client.post(self.reset_request_url, {
            'email': 'test@example.com'
        })
        self.assertEqual(response.status_code, 302)
        self.assertTrue(PasswordResetOTP.objects.filter(user=self.user).exists())
        
        # Get OTP
        otp = PasswordResetOTP.objects.filter(user=self.user).latest('created_at')
        
        # Set up session
        session = self.client.session
        session['reset_email'] = 'test@example.com'
        session.save()
        
        # Verify OTP
        response = self.client.post(self.verify_otp_url, {'otp': otp.otp})
        self.assertEqual(response.status_code, 302)
        self.assertTrue('reset_user_id' in self.client.session)
        
        # Set new password
        response = self.client.post(self.set_new_password_url, {
            'new_password1': 'NewSecurePass123!',
            'new_password2': 'NewSecurePass123!'
        })
        self.assertEqual(response.status_code, 302)
        
        # Verify new password works
        self.assertTrue(
            self.client.login(username='test@example.com', password='NewSecurePass123!')
        )

    def test_password_security_measures(self):
        """Test password security features"""
        # Test OTP expiration
        otp = PasswordResetOTP.objects.create(
            user=self.user,
            otp='123456'
        )
        otp.created_at = timezone.now() - timedelta(minutes=16)  # 15 min expiry
        otp.save()
        
        session = self.client.session
        session['reset_email'] = 'test@example.com'
        session.save()
        
        response = self.client.post(self.verify_otp_url, {'otp': otp.otp})
        self.assertEqual(response.status_code, 200)  # Stays on same page
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('expired' in str(msg).lower() for msg in messages))
        
        # Test password complexity requirements
        session['reset_user_id'] = self.user.id
        session.save()
        
        weak_passwords = [
            'short',  # Too short
            'onlylowercase123!',  # No uppercase
            'ONLYUPPERCASE123!',  # No lowercase
            'NoNumbers!',  # No numbers
            'NoSpecialChars123',  # No special characters
        ]
        
        for password in weak_passwords:
            response = self.client.post(self.set_new_password_url, {
                'new_password1': password,
                'new_password2': password
            })
            self.assertEqual(response.status_code, 200)  # Stays on same page
            form = response.context['form']
            self.assertFalse(form.is_valid())

    def test_password_reset_security(self):
        """Test security measures in password reset"""
        # Test non-existent email
        response = self.client.post(self.reset_request_url, {
            'email': 'nonexistent@example.com'
        })
        self.assertEqual(response.status_code, 200)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('no user found' in str(msg).lower() for msg in messages))
        
        # Test invalid OTP
        session = self.client.session
        session['reset_email'] = 'test@example.com'
        session.save()
        
        response = self.client.post(self.verify_otp_url, {'otp': '999999'})
        self.assertEqual(response.status_code, 200)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('invalid' in str(msg).lower() for msg in messages))
        
        # Test session requirement
        self.client.session.flush()
        response = self.client.post(self.verify_otp_url, {'otp': '123456'})
        self.assertEqual(response.status_code, 302)  # Redirects to reset request 