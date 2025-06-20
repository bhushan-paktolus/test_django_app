from .base import *

# Import environment-specific settings
from os import environ

if environ.get('DJANGO_ENV') == 'production':
    from .production import *
else:
    from .development import * 