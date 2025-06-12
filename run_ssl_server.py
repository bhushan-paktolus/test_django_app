import os
import sys
import ssl
from django.core.management.commands.runserver import Command as RunserverCommand
from django.core.management import execute_from_command_line

if __name__ == '__main__':
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'myauth_project.settings')
    from django.conf import settings
    
    # Override the default port and address
    sys.argv = [sys.argv[0], 'runserver', '127.0.0.1:8000']
    
    # Enable SSL
    os.environ['HTTPS'] = 'on'
    os.environ['wsgi.url_scheme'] = 'https'
    
    # Run the server
    execute_from_command_line(sys.argv) 