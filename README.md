# Django Authentication Project

A secure Django authentication system with features like 2FA, rate limiting, and backup codes.

## Features

- Custom User Model with email authentication
- Two-Factor Authentication (2FA)
- Backup codes for 2FA recovery
- Rate limiting for login and password reset attempts
- Secure password reset with OTP
- User activity logging
- Role-based access control
- Production-ready security settings

## Setup Instructions

1. Clone the repository
2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the project root with the following variables:

```ini
# Django Settings
DJANGO_ENV=development  # or production
DJANGO_SECRET_KEY=your-secret-key-here
ALLOWED_HOSTS=example.com,www.example.com
CSRF_TRUSTED_ORIGINS=https://example.com,https://www.example.com

# Database Settings (for production)
DB_NAME=your_db_name
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_HOST=localhost
DB_PORT=5432

# Email Settings (for production)
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_HOST_USER=your-email@example.com
EMAIL_HOST_PASSWORD=your-email-password
DEFAULT_FROM_EMAIL=noreply@example.com

# Redis Settings (for production)
REDIS_URL=redis://localhost:6379/1

# Security Settings
MAX_LOGIN_ATTEMPTS=5
LOGIN_ATTEMPT_TIMEOUT=300
MAX_PASSWORD_RESET_ATTEMPTS=3
PASSWORD_RESET_TIMEOUT=300
```

5. Run migrations:
```bash
python manage.py migrate
```

6. Create a superuser:
```bash
python manage.py createsuperuser
```

7. Run the development server:
```bash
python manage.py runserver
```

## Production Deployment

For production deployment:

1. Set `DJANGO_ENV=production` in your environment
2. Configure a PostgreSQL database and update database settings
3. Set up Redis for caching
4. Configure your email backend
5. Set up HTTPS with a valid SSL certificate
6. Use gunicorn as the application server:
```bash
gunicorn myauth_project.wsgi:application
```

7. Configure Nginx as a reverse proxy
8. Set up static files serving with whitenoise

## Security Features

- HTTPS enforcement in production
- Secure session and cookie settings
- CSRF protection
- XSS protection
- Content Security Policy
- Rate limiting
- Two-factor authentication
- Backup codes for account recovery
- Activity logging
- Strong password validation

## Testing

Run the test suite:
```bash
pytest
```

Generate coverage report:
```bash
pytest --cov=accounts
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Technology Stack

- Python 3.8+
- Django 4.0+
- SQLite (default) / PostgreSQL (recommended for production)
- pytest for testing
- Bootstrap for frontend styling

## Project Structure

