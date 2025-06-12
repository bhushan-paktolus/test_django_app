import logging
import time
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings

logger = logging.getLogger('accounts')

class RequestLoggingMiddleware(MiddlewareMixin):
    """Middleware to log all requests and responses"""
    
    def process_request(self, request):
        """Store the start time of the request"""
        request.start_time = time.time()

    def process_response(self, request, response):
        """Log the request and response details"""
        if hasattr(request, 'start_time'):
            # Calculate request duration
            duration = time.time() - request.start_time
            
            # Get user info
            user = request.user.email if request.user.is_authenticated else 'Anonymous'
            
            # Get request details
            status_code = response.status_code
            method = request.method
            path = request.get_full_path()
            ip = self.get_client_ip(request)
            
            # Create log message
            log_message = (
                f"[{method}] {path} - "
                f"Status: {status_code} - "
                f"User: {user} - "
                f"IP: {ip} - "
                f"Duration: {duration:.2f}s"
            )
            
            # Log based on status code
            if 200 <= status_code < 400:
                logger.info(log_message)
            elif status_code == 404:
                logger.warning(f"Not Found: {log_message}")
            elif 400 <= status_code < 500:
                logger.warning(f"Client Error: {log_message}")
            else:
                logger.error(f"Server Error: {log_message}")
        
        return response

    def process_exception(self, request, exception):
        """Log unhandled exceptions"""
        user = request.user.email if request.user.is_authenticated else 'Anonymous'
        ip = self.get_client_ip(request)
        
        logger.error(
            f"Exception in request: {request.get_full_path()} - "
            f"User: {user} - "
            f"IP: {ip} - "
            f"Error: {str(exception)}"
        )
        return None
    
    def get_client_ip(self, request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')

class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Add security headers
        response['X-XSS-Protection'] = '1; mode=block'
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['Referrer-Policy'] = 'same-origin'
        response['Cross-Origin-Opener-Policy'] = 'same-origin'
        
        if not request.is_secure():
            return response
            
        # Add HSTS header for HTTPS requests
        response['Strict-Transport-Security'] = f'max-age={settings.SECURE_HSTS_SECONDS}; includeSubDomains'
        
        return response 