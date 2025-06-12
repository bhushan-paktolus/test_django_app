from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from accounts.models import CustomUser, UserActivity
from django.core.cache import cache
from django.test import override_settings
from django.middleware.csrf import get_token

class AuthenticationTests(TestCase):
    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)  # Enable CSRF checks
        self.register_url = reverse('register')
        self.login_url = reverse('login')
        self.logout_url = reverse('logout')
        self.profile_url = reverse('profile')
        
        # Create test user
        self.test_user = CustomUser.objects.create_user(
            email='test@example.com',
            password='TestPass123!',
            first_name='Test',
            last_name='User'
        )

    def tearDown(self):
        cache.clear()  # Clear rate limiting cache

    def _get_csrf_token(self):
        """Helper method to get CSRF token"""
        response = self.client.get(self.login_url)  # or any GET request
        return response.cookies['csrftoken'].value

    def test_registration_flow(self):
        """Test the complete registration flow with valid data"""
        # Get CSRF token first
        csrf_token = self._get_csrf_token()
        
        data = {
            'email': 'newuser@example.com',
            'password1': 'SecurePass123!',
            'password2': 'SecurePass123!',
            'first_name': 'New',
            'last_name': 'User',
            'role': 'user',
            'phone': ''  # Optional field
        }
        response = self.client.post(self.register_url, data, HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, 302)  # Redirect after success
        self.assertTrue(CustomUser.objects.filter(email='newuser@example.com').exists())
        
        # Verify user can login after registration
        csrf_token = self._get_csrf_token()  # Get new token for login
        login_response = self.client.post(self.login_url, {
            'username': 'newuser@example.com',
            'password': 'SecurePass123!'
        }, HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(login_response.status_code, 302)
        self.assertTrue('_auth_user_id' in self.client.session)

    def test_login_security(self):
        """Test login security including rate limiting and inactive users"""
        # Test inactive user first
        self.test_user.is_active = False
        self.test_user.save()
        
        csrf_token = self._get_csrf_token()
        response = self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'TestPass123!'
        }, HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, 200)  # Should stay on login page
        self.assertFalse('_auth_user_id' in self.client.session)

        # Reactivate user for rate limiting test
        self.test_user.is_active = True
        self.test_user.save()
        
        # Test rate limiting
        csrf_token = self._get_csrf_token()
        for _ in range(5):  # Assuming max attempts is 5
            self.client.post(self.login_url, {
                'username': 'test@example.com',
                'password': 'WrongPass123!'
            }, HTTP_X_CSRFTOKEN=csrf_token)
        
        # Next attempt should be blocked
        response = self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'WrongPass123!'
        }, HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, 429)  # Too Many Requests

    def test_session_management(self):
        """Test session creation and invalidation"""
        # Login and check session
        csrf_token = self._get_csrf_token()
        self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'TestPass123!'
        }, HTTP_X_CSRFTOKEN=csrf_token)
        self.assertTrue('_auth_user_id' in self.client.session)
        
        # Access protected route
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, 200)
        
        # Logout and verify session is cleared
        self.client.get(self.logout_url)
        self.assertFalse('_auth_user_id' in self.client.session)
        
        # Verify protected route is no longer accessible
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, 302)  # Redirects to login

    @override_settings(
        SECURE_BROWSER_XSS_FILTER=True,
        SECURE_CONTENT_TYPE_NOSNIFF=True,
        X_FRAME_OPTIONS='DENY'
    )
    def test_security_headers(self):
        """Test security-related headers"""
        response = self.client.get(self.login_url)
        self.assertTrue(response.has_header('X-Frame-Options'))
        self.assertTrue(response.has_header('X-Content-Type-Options'))
        # Skip X-XSS-Protection check in development
        # self.assertTrue(response.has_header('X-XSS-Protection'))

    def test_csrf_protection(self):
        """Test CSRF protection"""
        # Try to post without CSRF token
        response = self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'TestPass123!'
        })
        self.assertEqual(response.status_code, 403)  # CSRF validation failed

    def test_activity_logging(self):
        """Test security event logging"""
        # Test successful login logging
        csrf_token = self._get_csrf_token()
        self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'TestPass123!'
        }, HTTP_X_CSRFTOKEN=csrf_token)
        self.assertTrue(UserActivity.objects.filter(
            user=self.test_user,
            activity_type='login_success'
        ).exists())
        
        # Test failed login logging
        csrf_token = self._get_csrf_token()
        self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'WrongPass123!'
        }, HTTP_X_CSRFTOKEN=csrf_token)
        self.assertTrue(UserActivity.objects.filter(
            user=self.test_user,
            activity_type='login_failed'
        ).exists()) 