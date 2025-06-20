from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.messages import get_messages
from django.utils import timezone
from django_otp.plugins.otp_totp.models import TOTPDevice
from accounts.models import CustomUser, BackupCode
import base64
import re
from unittest.mock import patch
from django.core.cache import cache

class TwoFactorAuthenticationTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = CustomUser.objects.create_user(
            email='test@example.com',
            password='TestPass123!',
            first_name='Test',
            last_name='User'
        )
        self.setup_2fa_url = reverse('setup_2fa')
        self.verify_2fa_url = reverse('verify_2fa')
        self.disable_2fa_url = reverse('disable_2fa')
        
        # Reset rate limiting
        cache.clear()
        
        # Login the user
        self.client.login(username='test@example.com', password='TestPass123!')

    def tearDown(self):
        # Reset rate limiting after each test
        cache.clear()

    def _login_user(self):
        """Helper method to login user and reset rate limiting"""
        cache.clear()  # Reset rate limiting before login
        
        # Create a new session for each login attempt
        self.client.session.flush()
        
        response = self.client.post(reverse('login'), {
            'username': 'test@example.com',
            'password': 'TestPass123!'
        }, follow=True)  # Follow redirects
        
        return response

    def test_setup_2fa_flow(self):
        """Test the complete 2FA setup flow"""
        # Test GET request to setup page
        response = self.client.get(self.setup_2fa_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'accounts/setup_2fa.html')
        self.assertIn('qr_code_data', response.context)
        self.assertIn('secret_key', response.context)
        
        # Verify QR code data is valid base64
        qr_code_data = response.context['qr_code_data']
        try:
            base64.b64decode(qr_code_data)
        except Exception:
            self.fail("QR code data is not valid base64")
        
        # Get the TOTP device
        device = TOTPDevice.objects.get(user=self.user, confirmed=False)
        
        # Test invalid token format
        response = self.client.post(self.setup_2fa_url, {'token': '12345'})  # Too short
        self.assertEqual(response.status_code, 200)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('valid 6-digit code' in str(msg) for msg in messages))
        
        # Test invalid token
        response = self.client.post(self.setup_2fa_url, {'token': '123456'})
        self.assertEqual(response.status_code, 200)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Invalid verification code' in str(msg) for msg in messages))
        
        # Test successful setup with valid token
        with patch('django_otp.plugins.otp_totp.models.TOTPDevice.verify_token', return_value=True):
            response = self.client.post(self.setup_2fa_url, {'token': '123456'})
            self.assertEqual(response.status_code, 200)
            self.assertTemplateUsed(response, 'accounts/backup_codes.html')
            
            # Verify 2FA is enabled
            self.user.refresh_from_db()
            self.assertTrue(self.user.two_factor_enabled)
            
            # Verify backup codes were generated
            self.assertTrue(BackupCode.objects.filter(user=self.user).exists())
            self.assertEqual(BackupCode.objects.filter(user=self.user).count(), 8)

    def test_verify_2fa_flow(self):
        """Test the 2FA verification flow during login"""
        # Enable 2FA first
        device = TOTPDevice.objects.create(
            user=self.user,
            name=f"Test device for {self.user.email}",
            confirmed=True
        )
        self.user.two_factor_enabled = True
        self.user.save()
        
        # Logout and try to login
        self.client.logout()
        response = self.client.post(reverse('login'), {
            'username': 'test@example.com',
            'password': 'TestPass123!'
        })
        
        # Should redirect to 2FA verification
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('verify_2fa'))
        
        # Verify session contains user ID
        self.assertIn('2fa_user_id', self.client.session)
        
        # Test invalid token
        response = self.client.post(self.verify_2fa_url, {'token': '123456'})
        self.assertEqual(response.status_code, 200)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Invalid verification code' in str(msg) for msg in messages))
        
        # Test successful verification with valid token
        with patch('django_otp.plugins.otp_totp.models.TOTPDevice.verify_token', return_value=True):
            response = self.client.post(self.verify_2fa_url, {'token': '123456'})
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.url, reverse('home'))
            self.assertIn('_auth_user_id', self.client.session)

    def test_backup_codes(self):
        """Test backup codes functionality"""
        # Enable 2FA and generate backup codes
        device = TOTPDevice.objects.create(
            user=self.user,
            name=f"Test device for {self.user.email}",
            confirmed=True
        )
        self.user.two_factor_enabled = True
        self.user.save()
        
        backup_codes = BackupCode.generate_backup_codes(self.user)
        self.assertEqual(len(backup_codes), 8)
        
        # Verify backup codes format
        for code in backup_codes:
            self.assertTrue(re.match(r'^[0-9A-F]{8}$', code))
        
        # Test login with backup code
        self.client.logout()
        
        # First login with credentials
        self.client.post(reverse('login'), {
            'username': 'test@example.com',
            'password': 'TestPass123!'
        })
        
        # Then use backup code
        response = self.client.post(self.verify_2fa_url, {'token': backup_codes[0]})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('home'))
        
        # Verify backup code is marked as used
        used_code = BackupCode.objects.get(code=backup_codes[0])
        self.assertTrue(used_code.used)
        self.assertIsNotNone(used_code.used_at)
        
        # Try to reuse the same backup code
        self.client.logout()
        self.client.post(reverse('login'), {
            'username': 'test@example.com',
            'password': 'TestPass123!'
        })
        response = self.client.post(self.verify_2fa_url, {'token': backup_codes[0]})
        self.assertEqual(response.status_code, 200)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Invalid verification code' in str(msg) for msg in messages))

    def test_disable_2fa(self):
        """Test 2FA disabling functionality"""
        # Enable 2FA first
        device = TOTPDevice.objects.create(
            user=self.user,
            name=f"Test device for {self.user.email}",
            confirmed=True
        )
        self.user.two_factor_enabled = True
        self.user.save()
        BackupCode.generate_backup_codes(self.user)
        
        # Set 2FA as verified in session
        session = self.client.session
        session['2fa_verified'] = True
        session.save()
        
        # Test GET request
        response = self.client.get(self.disable_2fa_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'accounts/disable_2fa.html')
        
        # Test POST request to disable 2FA
        response = self.client.post(self.disable_2fa_url)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('profile'))
        
        # Verify 2FA is disabled
        self.user.refresh_from_db()
        self.assertFalse(self.user.two_factor_enabled)
        
        # Verify TOTP device is deleted
        self.assertFalse(TOTPDevice.objects.filter(user=self.user).exists())
        
        # Verify backup codes are deleted
        self.assertFalse(BackupCode.objects.filter(user=self.user).exists())

    def test_2fa_required_views(self):
        """Test that 2FA verification is required for protected views"""
        # Enable 2FA
        device = TOTPDevice.objects.create(
            user=self.user,
            name=f"Test device for {self.user.email}",
            confirmed=True
        )
        self.user.two_factor_enabled = True
        self.user.save()
        
        # Logout and login without 2FA verification
        self.client.logout()
        self.client.post(reverse('login'), {
            'username': 'test@example.com',
            'password': 'TestPass123!'
        })
        
        # Try to access protected views
        protected_urls = [
            reverse('profile'),
            reverse('password_change'),
            reverse('disable_2fa'),
        ]
        
        for url in protected_urls:
            response = self.client.get(url)
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.url, reverse('verify_2fa'))

    def test_rate_limiting(self):
        """Test rate limiting for 2FA verification attempts"""
        # Enable 2FA
        device = TOTPDevice.objects.create(
            user=self.user,
            name=f"Test device for {self.user.email}",
            confirmed=True
        )
        self.user.two_factor_enabled = True
        self.user.save()
        
        # Login to get to 2FA verification
        self.client.logout()
        self.client.post(reverse('login'), {
            'username': 'test@example.com',
            'password': 'TestPass123!'
        })
        
        # Make multiple failed attempts
        for _ in range(5):
            response = self.client.post(self.verify_2fa_url, {'token': '123456'})
            self.assertEqual(response.status_code, 200)
        
        # Next attempt should be blocked
        response = self.client.post(self.verify_2fa_url, {'token': '123456'})
        self.assertEqual(response.status_code, 429)  # Too Many Requests 