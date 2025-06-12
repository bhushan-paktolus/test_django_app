import pytest
from django.test import RequestFactory
from django.core.files.uploadedfile import SimpleUploadedFile
from accounts.models import CustomUser

@pytest.fixture
def rf():
    return RequestFactory()

@pytest.fixture
def user_data():
    return {
        'email': 'test@example.com',
        'username': 'testuser',
        'first_name': 'Test',
        'last_name': 'User',
        'phone': '+1234567890',
        'role': 'user',
        'password1': 'TestPassword123!',
        'password2': 'TestPassword123!'
    }

@pytest.fixture
def test_user(db):
    user = CustomUser.objects.create_user(
        email='test@example.com',
        username='testuser',
        password='TestPassword123!',
        first_name='Test',
        last_name='User',
        role='user',
        phone='+1234567890'
    )
    return user

@pytest.fixture
def test_password():
    return 'TestPassword123!'

@pytest.fixture
def authenticated_client(client, test_user, test_password):
    client.login(username=test_user.email, password=test_password)
    return client 