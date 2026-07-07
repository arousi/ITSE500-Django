from django.test import TestCase
import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from django.contrib.auth.models import User
# from .serializers import RegisterSerializer (kept for future direct serializer unit tests)
import json

@pytest.fixture
def api_client():
    return APIClient()

@pytest.mark.django_db
def test_register_view_success(api_client):
    url = reverse('Register')
    data = {'username': 'testuser', 'email': 'test@example.com',
            'user_password': 'testpassword'}
    response = api_client.post(url, data, format='json')
    assert response.status_code == status.HTTP_201_CREATED

@pytest.mark.django_db
def test_register_view_failure(api_client):
    url = reverse('Register')
    test_cases = [
        {'username': '', 'email': 'test@example.com',
         'user_password': 'testpassword'},
        
        {'username': 'testuser', 'email': '',
         'user_password': 'testpassword'},
        
        {'username': 'testuser', 'email': 'test@example.com',
         'user_password': ''},
        
        {'username': '', 'email': '',
         'user_password': ''},
        
        {'username': 'testuser', 'email': 'invalid_email',
         'user_password': 'testpassword'},
        
        {'username': 'testuser', 'email': 'test@example.com',
         'user_password': 'short'},
        
        {'username': 'testuser', 'email': 'test@example.com',
         'user_password': 'testpassword', 'extra_field': 'unexpected'},
    ]

    for case in test_cases:
        response = api_client.post(url, case, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        for field, value in case.items():
            if field in ['username', 'email', 'user_password'] and not value:
                assert field in response.data

@pytest.mark.django_db
def test_login_view_success(api_client, django_user_model):
    url = reverse('Login')
    user = django_user_model.objects.create_user(username='testuser',
                                                 email='test@example.com', password='testpassword')
    data = {'username': 'testuser', 'email': 'test@example.com',
            'user_password': 'testpassword'}
    response = api_client.post(url, data, format='json')
    assert response.status_code == status.HTTP_200_OK

@pytest.mark.django_db
def test_logout_view(api_client, django_user_model):
    url = reverse('Logout')
    user = django_user_model.objects.create_user(username='testuser',
                                                 email='test@example.com', password='testpassword')
    api_client.force_authenticate(user=user)
    response = api_client.post(url)
    assert response.status_code == status.HTTP_200_OK

@pytest.mark.django_db
def test_otp_authentication_success(api_client):
    url = reverse('otp-login')
    data = {'email': 'test@example.com', 'otp': '123456', 'user_password': 'testpassword'}
    response = api_client.post(url, data, format='json')
    assert response.status_code == status.HTTP_200_OK

@pytest.mark.django_db
def test_otp_authentication_failure(api_client):
    url = reverse('otp-login')
    data = {'email': 'test@example.com', 'otp': 'wrongotp', 'user_password': 'testpassword'}
    response = api_client.post(url, data, format='json')
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
""" 
@pytest.mark.django_db
def test_google_oauth_success(api_client):
    url = reverse('google-oauth')
    data = {'token': 'valid_google_token'}
    response = api_client.post(url, data, format='json')
    assert response.status_code == status.HTTP_200_OK

@pytest.mark.django_db
def test_google_oauth_failure(api_client):
    url = reverse('google-oauth')
    data = {'token': 'invalid_google_token'}
    response = api_client.post(url, data, format='json')
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

@pytest.mark.django_db
def test_openrouter_oauth_success(api_client):
    url = reverse('openrouter-oauth')
    data = {'token': 'valid_openrouter_token'}
    response = api_client.post(url, data, format='json')
    assert response.status_code == status.HTTP_200_OK

@pytest.mark.django_db
def test_openrouter_oauth_failure(api_client):
    url = reverse('openrouter-oauth')
    data = {'token': 'invalid_openrouter_token'}
    response = api_client.post(url, data, format='json')
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
 """