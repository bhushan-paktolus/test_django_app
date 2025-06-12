import pytest
from django.test import TestCase
from accounts.utils.logger import (
    get_auth_logger,
    get_user_logger,
    get_security_logger,
    get_email_logger,
    log_auth_event,
    log_user_event,
    log_security_event,
    log_email_event
)
import logging
import os

class TestLoggers(TestCase):
    def setUp(self):
        self.log_dir = 'logs'
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

    def test_auth_logger(self):
        logger = get_auth_logger()
        self.assertIsInstance(logger, logging.Logger)
        self.assertEqual(logger.name, 'auth')
        
        # Test logging
        test_message = "Test auth log message"
        log_auth_event(test_message)
        
        # Check if message was logged
        with open(os.path.join(self.log_dir, 'auth.log'), 'r') as f:
            log_content = f.read()
            self.assertIn(test_message, log_content)

    def test_user_logger(self):
        logger = get_user_logger()
        self.assertIsInstance(logger, logging.Logger)
        self.assertEqual(logger.name, 'user')
        
        # Test logging
        test_message = "Test user log message"
        log_user_event(test_message)
        
        # Check if message was logged
        with open(os.path.join(self.log_dir, 'user.log'), 'r') as f:
            log_content = f.read()
            self.assertIn(test_message, log_content)

    def test_security_logger(self):
        logger = get_security_logger()
        self.assertIsInstance(logger, logging.Logger)
        self.assertEqual(logger.name, 'security')
        
        # Test logging
        test_message = "Test security log message"
        log_security_event(test_message)
        
        # Check if message was logged
        with open(os.path.join(self.log_dir, 'security.log'), 'r') as f:
            log_content = f.read()
            self.assertIn(test_message, log_content)

    def test_email_logger(self):
        logger = get_email_logger()
        self.assertIsInstance(logger, logging.Logger)
        self.assertEqual(logger.name, 'email')
        
        # Test logging
        test_message = "Test email log message"
        log_email_event(test_message)
        
        # Check if message was logged
        with open(os.path.join(self.log_dir, 'email.log'), 'r') as f:
            log_content = f.read()
            self.assertIn(test_message, log_content)

    def test_log_levels(self):
        # Test different log levels
        test_message = "Test log message"
        
        # Info level
        log_auth_event(test_message, level='info')
        with open(os.path.join(self.log_dir, 'auth.log'), 'r') as f:
            log_content = f.read()
            self.assertIn('INFO', log_content)
            self.assertIn(test_message, log_content)
        
        # Warning level
        log_security_event(test_message, level='warning')
        with open(os.path.join(self.log_dir, 'security.log'), 'r') as f:
            log_content = f.read()
            self.assertIn('WARNING', log_content)
            self.assertIn(test_message, log_content)
        
        # Error level
        log_email_event(test_message, level='error')
        with open(os.path.join(self.log_dir, 'email.log'), 'r') as f:
            log_content = f.read()
            self.assertIn('ERROR', log_content)
            self.assertIn(test_message, log_content)
        
        # Debug level
        log_user_event(test_message, level='debug')
        with open(os.path.join(self.log_dir, 'user.log'), 'r') as f:
            log_content = f.read()
            self.assertIn('DEBUG', log_content)
            self.assertIn(test_message, log_content)

    def test_invalid_log_level(self):
        test_message = "Test invalid log level"
        with self.assertRaises(ValueError):
            log_auth_event(test_message, level='invalid_level')

    def test_log_formatting(self):
        test_message = "Test log formatting"
        log_auth_event(test_message)
        
        with open(os.path.join(self.log_dir, 'auth.log'), 'r') as f:
            log_content = f.read()
            # Check timestamp format
            self.assertRegex(log_content, r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}')
            # Check log level
            self.assertIn('INFO', log_content)
            # Check message
            self.assertIn(test_message, log_content)

    def tearDown(self):
        # Clean up log files after tests
        log_files = ['auth.log', 'user.log', 'security.log', 'email.log']
        for log_file in log_files:
            file_path = os.path.join(self.log_dir, log_file)
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except PermissionError:
                    # Skip if file is locked
                    pass
        try:
            if os.path.exists(self.log_dir):
                os.rmdir(self.log_dir)
        except (PermissionError, OSError):
            # Skip if directory is not empty or locked
            pass 