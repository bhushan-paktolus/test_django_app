import logging
import os

# Create logs directory if it doesn't exist
log_dir = 'logs'
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Configure logging format
log_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def setup_logger(name, log_file):
    """Helper function to set up a logger with file handler"""
    handler = logging.FileHandler(os.path.join(log_dir, log_file))
    handler.setFormatter(log_format)

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)

    return logger

# Initialize loggers
auth_logger = setup_logger('auth', 'auth.log')
user_logger = setup_logger('user', 'user.log')
security_logger = setup_logger('security', 'security.log')
email_logger = setup_logger('email', 'email.log')

def get_auth_logger():
    return auth_logger

def get_user_logger():
    return user_logger

def get_security_logger():
    return security_logger

def get_email_logger():
    return email_logger

def log_event(logger, message, level='info'):
    """Generic logging function"""
    level = level.lower()
    if level not in ['debug', 'info', 'warning', 'error', 'critical']:
        raise ValueError(f"Invalid log level: {level}")

    log_func = getattr(logger, level)
    log_func(message)

def log_auth_event(message, level='info', ip_address=None, user_agent=None):
    """Log authentication events with optional IP and user agent information"""
    if ip_address or user_agent:
        message = f"{message} [IP: {ip_address or 'unknown'}, UA: {user_agent or 'unknown'}]"
    log_event(auth_logger, message, level)

def log_user_event(message, level='info'):
    log_event(user_logger, message, level)

def log_security_event(message, level='info'):
    log_event(security_logger, message, level)

def log_email_event(message, level='info'):
    log_event(email_logger, message, level)

def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR') 