"""
Comprehensive tests for auth_api views
Testing all authentication-related views including OAuth integrations
"""
import pytest
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from unittest.mock import patch, MagicMock
from django.contrib.auth import get_user_model
from user_mang.models.visitor import Visitor
from user_mang.models.custom_user import Custom_User
from django.utils import timezone
from datetime import timedelta
import json

User = get_user_model()

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture  
def sample_user():
    return Custom_User.objects.create(
        username='testuser',
        email='test@example.com',
        email_verified=True,
        is_active=True
    )

@pytest.fixture
def sample_visitor():
    return Visitor.objects.create(
        device_id='test_device_123',
        anon_id='anon_test_123'
    )

class VisitorLoginViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse('visitor-login')  # Adjust URL name as needed
        
    def test_visitor_login_success(self):
        """Test successful visitor login creates new visitor"""
        data = {
            'device_id': 'test_device_456',
            'user_agent': 'Test Browser'
        }
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('anon_id', response.data)
        self.assertIn('device_id', response.data)
        self.assertEqual(response.data['device_id'], 'test_device_456')
        
    def test_visitor_login_invalid_data(self):
        """Test visitor login with invalid data"""
        data = {}
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
    def test_visitor_login_server_error(self):
        """Test visitor login handles server errors gracefully"""
        with patch('auth_api.serializer.VisitorSerializer.save') as mock_save:
            mock_save.side_effect = Exception("Database error")
            
            data = {'device_id': 'test_device_789'}
            response = self.client.post(self.url, data, format='json')
            
            self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)

class RegisterViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse('register')  # Adjust URL name as needed
        
    def test_register_success(self):
        """Test successful user registration"""
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'secure_password_123'
        }
        
        with patch('django.core.mail.send_mail') as mock_send_mail:
            response = self.client.post(self.url, data, format='json')
            
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            self.assertIn('user_id', response.data)
            self.assertIn('access_token', response.data)
            self.assertIn('refresh_token', response.data)
            self.assertTrue(response.data['onboarding'])
            mock_send_mail.assert_called_once()
            
    def test_register_duplicate_email(self):
        """Test registration with duplicate email"""
        # Create existing user
        Custom_User.objects.create(
            username='existing',
            email='duplicate@example.com'
        )
        
        data = {
            'username': 'newuser',
            'email': 'duplicate@example.com',
            'password': 'secure_password_123'
        }
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
    def test_register_invalid_password(self):
        """Test registration with weak password"""
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com', 
            'password': '123'
        }
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

class EmailPinVerifyViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse('email-pin-verify')  # Adjust URL name as needed
        self.user = Custom_User.objects.create(
            username='testuser',
            email='test@example.com',
            profile_email_pin='12345',
            profile_email_pin_created=timezone.now(),
            email_verified=False
        )
        
    def test_pin_verify_success(self):
        """Test successful PIN verification"""
        data = {
            'email': 'test@example.com',
            'pin': '12345'
        }
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify user is updated
        self.user.refresh_from_db()
        self.assertTrue(self.user.email_verified)
        self.assertIsNone(self.user.profile_email_pin)
        
    def test_pin_verify_invalid_pin(self):
        """Test PIN verification with wrong PIN"""
        data = {
            'email': 'test@example.com',
            'pin': '54321'
        }
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
    def test_pin_verify_expired_pin(self):
        """Test PIN verification with expired PIN"""
        # Set PIN created time to 15 minutes ago
        self.user.profile_email_pin_created = timezone.now() - timedelta(minutes=15)
        self.user.save()
        
        data = {
            'email': 'test@example.com',
            'pin': '12345'
        }
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
    def test_pin_verify_user_not_found(self):
        """Test PIN verification for non-existent user"""
        data = {
            'email': 'nonexistent@example.com',
            'pin': '12345'
        }
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

class SetPasswordAfterEmailVerifyViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse('set-password')  # Adjust URL name as needed
        self.user = Custom_User.objects.create(
            username='testuser',
            email='test@example.com',
            email_verified=True
        )
        
    def test_set_password_success(self):
        """Test successful password setting"""
        data = {
            'email': 'test@example.com',
            'password': 'hashed_frontend_password'
        }
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify password is set
        self.user.refresh_from_db()
        self.assertIsNotNone(self.user.user_password)
        
    def test_set_password_email_not_verified(self):
        """Test password setting when email not verified"""
        self.user.email_verified = False
        self.user.save()
        
        data = {
            'email': 'test@example.com',
            'password': 'hashed_frontend_password'
        }
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

class LoginViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse('login')  # Adjust URL name as needed
        self.user = Custom_User.objects.create(
            username='testuser',
            email='test@example.com',
            user_password='hashed_password',
            email_verified=True,
            is_active=True
        )
        
    def test_login_success(self):
        """Test successful login"""
        data = {
            'email': 'test@example.com',
            'password': 'hashed_password'
        }
        
        with patch('auth_api.serializer.LoginSerializer.is_valid', return_value=True):
            with patch('auth_api.serializer.LoginSerializer.validated_data', 
                      {'user': self.user}):
                response = self.client.post(self.url, data, format='json')
                
                self.assertEqual(response.status_code, status.HTTP_200_OK)
                self.assertIn('access_token', response.data)
                self.assertIn('refresh_token', response.data)
                self.assertIn('user_id', response.data)
        
    def test_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        data = {
            'email': 'test@example.com',
            'password': 'wrong_password'
        }
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
    def test_login_inactive_user(self):
        """Test login with inactive user"""
        self.user.is_active = False
        self.user.save()
        
        data = {
            'email': 'test@example.com',
            'password': 'hashed_password'
        }
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

class LogoutViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse('logout')  # Adjust URL name as needed
        
    def test_logout_success(self):
        """Test successful logout"""
        response = self.client.post(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('Logged out successfully', response.data['detail'])

class HealthCheckViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse('health-check')  # Adjust URL name as needed
        
    def test_health_check(self):
        """Test health check endpoint"""
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'ok')
        self.assertIn('Server is up', response.data['message'])

class GoogleOAuthViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse('google-oauth')  # Adjust URL name as needed
        
    def test_google_oauth_success(self):
        """Test successful Google OAuth"""
        data = {'token': 'valid_google_token'}
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('Google OAuth success', response.data['message'])
        
    def test_google_oauth_invalid_token(self):
        """Test Google OAuth with invalid token"""
        data = {'token': 'invalid_token'}
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('Invalid token', response.data['error'])

class OpenRouterOAuthViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse('openrouter-oauth')  # Adjust URL name as needed
        
    def test_openrouter_oauth_success(self):
        """Test successful OpenRouter OAuth"""
        data = {'token': 'valid_openrouter_token'}
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('OpenRouter OAuth success', response.data['message'])
        
    def test_openrouter_oauth_invalid_token(self):
        """Test OpenRouter OAuth with invalid token"""
        data = {'token': 'invalid_token'}
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('Invalid token', response.data['error'])

class LoginWithOTPViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse('otp-login')  # Adjust URL name as needed
        self.user = Custom_User.objects.create(
            username='testuser',
            email='test@example.com',
            is_active=True
        )
        
    def test_otp_login_success(self):
        """Test successful OTP login"""
        data = {
            'email': 'test@example.com',
            'password': 'test_password'
        }
        
        with patch('auth_api.serializer.LoginSerializer.is_valid', return_value=True):
            with patch('auth_api.serializer.LoginSerializer.validated_data',
                      {'user': self.user}):
                response = self.client.post(self.url, data, format='json')
                
                self.assertEqual(response.status_code, status.HTTP_200_OK)
                self.assertIn('OTP sent successfully', response.data['message'])
        
    def test_otp_login_invalid_credentials(self):
        """Test OTP login with invalid credentials"""
        data = {
            'email': 'test@example.com',
            'password': 'wrong_password'
        }
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

# Integration Tests
class AuthIntegrationTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        
    def test_complete_registration_flow(self):
        """Test complete user registration and login flow"""
        # Step 1: Register user
        register_data = {
            'username': 'flowuser',
            'email': 'flow@example.com',
            'password': 'secure_password_123'
        }
        
        with patch('django.core.mail.send_mail'):
            register_response = self.client.post(
                reverse('register'), register_data, format='json'
            )
            
        self.assertEqual(register_response.status_code, status.HTTP_201_CREATED)
        
        # Step 2: Verify email PIN
        user = Custom_User.objects.get(email='flow@example.com')
        pin_data = {
            'email': 'flow@example.com',
            'pin': user.profile_email_pin
        }
        
        pin_response = self.client.post(
            reverse('email-pin-verify'), pin_data, format='json'
        )
        self.assertEqual(pin_response.status_code, status.HTTP_200_OK)
        
        # Step 3: Set password
        password_data = {
            'email': 'flow@example.com',
            'password': 'hashed_frontend_password'
        }
        
        password_response = self.client.post(
            reverse('set-password'), password_data, format='json'
        )
        self.assertEqual(password_response.status_code, status.HTTP_200_OK)
        
        # Step 4: Login
        login_data = {
            'email': 'flow@example.com',
            'password': 'hashed_frontend_password'
        }
        
        with patch('auth_api.serializer.LoginSerializer.is_valid', return_value=True):
            with patch('auth_api.serializer.LoginSerializer.validated_data',
                      {'user': user}):
                login_response = self.client.post(
                    reverse('login'), login_data, format='json'
                )
                
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', login_response.data)

# Performance Tests  
class AuthPerformanceTest(TestCase):
    def test_concurrent_visitor_logins(self):
        """Test handling multiple concurrent visitor logins"""
        import threading
        import time
        
        results = []
        
        def create_visitor(device_id):
            client = APIClient()
            data = {'device_id': device_id}
            response = client.post(reverse('visitor-login'), data, format='json')
            results.append(response.status_code)
            
        threads = []
        for i in range(10):
            thread = threading.Thread(target=create_visitor, args=[f'device_{i}'])
            threads.append(thread)
            thread.start()
            
        for thread in threads:
            thread.join()
            
        # All requests should be successful
        self.assertTrue(all(status == 201 for status in results))
        self.assertEqual(len(results), 10)