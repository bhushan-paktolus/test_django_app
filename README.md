# Django Authentication System

A robust and secure Django-based authentication system with advanced security features and user management capabilities.

## Features

### Authentication & Security
- 🔐 Secure user registration and login
- 🔑 Password reset with OTP (One-Time Password)
- 🛡️ CSRF protection
- 🔒 PBKDF2 password hashing with SHA256
- 🚫 Login attempt limiting
- 📝 Comprehensive activity logging
- 🔄 Secure session management

### User Management
- 👤 User profile management
- 👥 Role-based access control
- 📧 Email verification
- 📱 Phone number validation
- 🔐 Password strength validation
- 📊 User activity tracking

## Technology Stack

- Python 3.8+
- Django 4.0+
- SQLite (default)
- pytest for testing
- Bootstrap for frontend styling

## Installation

1. **Clone the Repository**
```bash
git clone <repository-url>
cd django-auth-system
```

2. **Set Up Virtual Environment**
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

3. **Install Dependencies**
```bash
pip install -r requirements.txt
```

4. **Environment Setup**
- Create a `.env` file in the project root
- Copy contents from `.env.example` and update with your settings
```bash
cp .env.example .env
```

5. **Database Setup**
```bash
python manage.py migrate
```

6. **Create Superuser** (Optional)
```bash
python manage.py createsuperuser
```

7. **Run Development Server**
```bash
python manage.py runserver
```

## Testing

Run the comprehensive test suite:
```bash
pytest
```

View test coverage:
```bash
pytest --cov=accounts
```

## Project Structure

