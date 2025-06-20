import pytest
from django.test import TestCase
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from accounts.models import CustomUser, PasswordResetOTP, UserActivity, BackupCode
from django.utils import timezone
from datetime import timedelta
import re

class TestCustomUser(TestCase):
    def setUp(self):
        self.user_data = {
            'email': 'test@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'phone': '+1234567890',
            'password': 'TestPass123!',
            'role': 'user'
        }

    def test_create_user(self):
        user = CustomUser.objects.create_user(
            email=self.user_data['email'],
            password=self.user_data['password'],
            first_name=self.user_data['first_name'],
            last_name=self.user_data['last_name'],
            phone=self.user_data['phone'],
            role=self.user_data['role']
        )
        self.assertEqual(user.email, self.user_data['email'])
        self.assertEqual(user.first_name, self.user_data['first_name'])
        self.assertEqual(user.last_name, self.user_data['last_name'])
        self.assertEqual(user.phone, self.user_data['phone'])
        self.assertEqual(user.role, self.user_data['role'])
        self.assertTrue(user.check_password(self.user_data['password']))
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_create_superuser(self):
        admin_user = CustomUser.objects.create_superuser(
            email='admin@example.com',
            password='AdminPass123!',
            first_name='Admin',
            last_name='User'
        )
        self.assertEqual(admin_user.email, 'admin@example.com')
        self.assertTrue(admin_user.is_active)
        self.assertTrue(admin_user.is_staff)
        self.assertTrue(admin_user.is_superuser)
        self.assertEqual(admin_user.role, 'admin')

    def test_user_str_method(self):
        user = CustomUser.objects.create_user(
            email=self.user_data['email'],
            password=self.user_data['password']
        )
        self.assertEqual(str(user), self.user_data['email'])

    def test_invalid_email(self):
        invalid_emails = [
            'invalid-email',
            'user@',
            '@domain.com',
            'user@domain',
            'user.domain.com'
        ]
        for email in invalid_emails:
            with self.assertRaises(ValidationError):
                user = CustomUser(
                    email=email,
                    first_name='Test',
                    last_name='User'
                )
                user.full_clean()

    def test_invalid_phone(self):
        invalid_phones = [
            'invalid-phone',
            '123',  # Too short
            'abc123456789',  # Contains letters
            '+1234',  # Too short with plus
            '+' + '1' * 16  # Too long
        ]
        for phone in invalid_phones:
            with self.assertRaises(ValidationError):
                user = CustomUser(
                    email='test@example.com',
                    first_name='Test',
                    last_name='User',
                    phone=phone
                )
                user.full_clean()

    def test_invalid_names(self):
        invalid_names = [
            'Test123',  # Contains numbers
            'Test@User',  # Contains special characters
            'T',        # Too short
            'A' * 31    # Too long
        ]
        for name in invalid_names:
            with self.assertRaises(ValidationError):
                user = CustomUser(
                    email='test@example.com',
                    first_name=name,
                    last_name='User'
                )
                user.full_clean()

            with self.assertRaises(ValidationError):
                user = CustomUser(
                    email='test@example.com',
                    first_name='Test',
                    last_name=name
                )
                user.full_clean()

    def test_invalid_role(self):
        with self.assertRaises(ValidationError):
            user = CustomUser(
                email='test@example.com',
                first_name='Test',
                last_name='User',
                role='invalid_role'
            )
            user.full_clean()

    def test_email_unique(self):
        CustomUser.objects.create_user(
            email=self.user_data['email'],
            password='TestPass123!'
        )
        with self.assertRaises(ValidationError):
            user2 = CustomUser(
                email=self.user_data['email'],
                password='TestPass123!'
            )
            user2.full_clean()

class TestPasswordResetOTP(TestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email='test@example.com',
            password='TestPass123!'
        )

    def test_create_otp(self):
        otp = PasswordResetOTP.objects.create(
            user=self.user,
            otp='123456'
        )
        self.assertEqual(otp.user, self.user)
        self.assertEqual(otp.otp, '123456')
        self.assertFalse(otp.is_used)
        self.assertIsNotNone(otp.created_at)

    def test_otp_is_valid(self):
        # Test valid OTP
        otp = PasswordResetOTP.objects.create(user=self.user, otp='123456')
        self.assertTrue(otp.is_valid())

        # Test used OTP
        otp.is_used = True
        otp.save()
        self.assertFalse(otp.is_valid())

        # Test expired OTP
        otp = PasswordResetOTP.objects.create(user=self.user, otp='654321')
        otp.created_at = timezone.now() - timedelta(minutes=11)  # 11 minutes old
        otp.save()
        self.assertFalse(otp.is_valid())

        # Test superseded OTP
        old_otp = PasswordResetOTP.objects.create(user=self.user, otp='111111')
        old_otp.created_at = timezone.now() - timedelta(minutes=5)
        old_otp.save()
        new_otp = PasswordResetOTP.objects.create(user=self.user, otp='222222')  # Creates a newer OTP
        self.assertFalse(old_otp.is_valid())  # Old OTP should be invalid
        self.assertTrue(new_otp.is_valid())  # New OTP should be valid

class TestUserActivity(TestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email='test@example.com',
            password='TestPass123!'
        )

    def test_create_activity(self):
        activity = UserActivity.objects.create(
            user=self.user,
            activity_type='login',
            ip_address='127.0.0.1',
            user_agent='Test User Agent'
        )
        self.assertEqual(activity.user, self.user)
        self.assertEqual(activity.activity_type, 'login')
        self.assertEqual(activity.ip_address, '127.0.0.1')
        self.assertEqual(activity.user_agent, 'Test User Agent')
        self.assertIsNotNone(activity.timestamp)

    def test_activity_str_method(self):
        activity = UserActivity.objects.create(
            user=self.user,
            activity_type='login',
            ip_address='127.0.0.1',
            user_agent='test-agent'
        )
        expected_str = f"{self.user.email} - login at {activity.timestamp}"
        self.assertEqual(str(activity), expected_str)

class TestBackupCode(TestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email='test@example.com',
            password='TestPass123!'
        )

    def test_generate_backup_codes(self):
        """Test backup code generation"""
        # Generate initial codes
        codes = BackupCode.generate_backup_codes(self.user)
        
        # Verify number of codes
        self.assertEqual(len(codes), 8)
        self.assertEqual(BackupCode.objects.filter(user=self.user).count(), 8)
        
        # Verify code format (8 character hex)
        for code in codes:
            self.assertTrue(re.match(r'^[0-9A-F]{8}$', code))
        
        # Store old codes and mark one as used
        old_codes = list(BackupCode.objects.filter(user=self.user))
        used_code = BackupCode.objects.get(code=codes[0])
        used_code.used = True
        used_code.used_at = timezone.now()
        used_code.save()
        
        # Generate new codes
        new_codes = BackupCode.generate_backup_codes(self.user)
        
        # Verify unused old codes are deleted but used code is kept
        self.assertTrue(BackupCode.objects.filter(id=used_code.id).exists())
        for old_code in old_codes:
            if old_code.id != used_code.id:
                self.assertFalse(BackupCode.objects.filter(id=old_code.id).exists())
        
        # Verify new codes are created
        self.assertEqual(len(new_codes), 8)
        self.assertEqual(BackupCode.objects.filter(user=self.user).count(), 9)  # 8 new + 1 used

    def test_backup_code_usage(self):
        """Test backup code usage tracking"""
        codes = BackupCode.generate_backup_codes(self.user)
        code_obj = BackupCode.objects.get(code=codes[0])
        
        # Initially not used
        self.assertFalse(code_obj.used)
        self.assertIsNone(code_obj.used_at)
        
        # Mark as used
        code_obj.used = True
        code_obj.used_at = timezone.now()
        code_obj.save()
        
        # Verify used status
        code_obj.refresh_from_db()
        self.assertTrue(code_obj.used)
        self.assertIsNotNone(code_obj.used_at)

    def test_backup_code_cleanup(self):
        """Test cleanup of old backup codes"""
        # Generate initial codes
        old_codes = BackupCode.generate_backup_codes(self.user)
        
        # Mark one code as used
        used_code = BackupCode.objects.get(code=old_codes[0])
        used_code.used = True
        used_code.used_at = timezone.now()
        used_code.save()
        
        # Generate new codes
        new_codes = BackupCode.generate_backup_codes(self.user)
        
        # Verify used code is kept but unused old codes are deleted
        self.assertTrue(BackupCode.objects.filter(code=old_codes[0]).exists())
        for code in old_codes[1:]:
            self.assertFalse(BackupCode.objects.filter(code=code).exists())
        
        # Verify total number of codes (8 new + 1 old used)
        self.assertEqual(BackupCode.objects.filter(user=self.user).count(), 9)

    def test_backup_code_uniqueness(self):
        """Test that backup codes are unique per user"""
        # Create another user
        other_user = CustomUser.objects.create_user(
            email='other@example.com',
            password='TestPass123!'
        )
        
        # Generate codes for both users
        user1_codes = BackupCode.generate_backup_codes(self.user)
        user2_codes = BackupCode.generate_backup_codes(other_user)
        
        # Verify no codes are shared between users
        user1_code_set = set(user1_codes)
        user2_code_set = set(user2_codes)
        self.assertEqual(len(user1_code_set.intersection(user2_code_set)), 0)
        
        # Verify each user has correct number of codes
        self.assertEqual(BackupCode.objects.filter(user=self.user).count(), 8)
        self.assertEqual(BackupCode.objects.filter(user=other_user).count(), 8) 