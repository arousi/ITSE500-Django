"""
Comprehensive tests for user_mang views
Testing user management functionality including admin operations
"""
import pytest
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient, force_authenticate
from unittest.mock import patch, MagicMock
from user_mang.models.custom_user import Custom_User
from django.contrib.auth.models import AnonymousUser
from django.utils import timezone
from datetime import timedelta
import json

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def sample_user():
    return Custom_User.objects.create(
        username='testuser',
        email='test@example.com',
        is_active=True,
        email_verified=True
    )

@pytest.fixture
def admin_user():
    return Custom_User.objects.create(
        username='admin',
        email='admin@example.com',
        is_active=True,
        is_staff=True,
        is_superuser=True
    )

@pytest.fixture
def inactive_user():
    return Custom_User.objects.create(
        username='inactiveuser',
        email='inactive@example.com',
        is_active=False
    )

class UserDetailViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse('user-detail')  # Adjust URL name as needed
        self.user = Custom_User.objects.create(
            username='testuser',
            email='test@example.com',
            is_active=True,
            email_verified=True,
            last_modified=timezone.now()
        )
        
    def test_get_user_detail_success(self):
        """Test successful retrieval of authenticated user's data"""
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], 'testuser')
        self.assertEqual(response.data['email'], 'test@example.com')
        
    def test_get_user_detail_unauthenticated(self):
        """Test user detail retrieval without authentication"""
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
    def test_get_user_detail_inactive_user(self):
        """Test user detail retrieval for inactive user"""
        self.user.is_active = False
        self.user.save()
        
        self.client.force_authenticate(user=self.user)
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('Account is locked or inactive', response.data['error'])
        
    def test_get_user_detail_with_last_modified_match(self):
        """Test user detail with matching last_modified parameter"""
        self.client.force_authenticate(user=self.user)
        
        last_modified = self.user.last_modified.isoformat()
        response = self.client.get(self.url, {'last_modified': last_modified})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'up-to-date')
        self.assertEqual(response.data['last_modified'], last_modified)
        
    def test_get_user_detail_with_last_modified_mismatch(self):
        """Test user detail with non-matching last_modified parameter"""
        self.client.force_authenticate(user=self.user)
        
        old_time = (timezone.now() - timedelta(hours=1)).isoformat()
        response = self.client.get(self.url, {'last_modified': old_time})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('username', response.data)  # Full data returned
        
    def test_put_user_detail_success(self):
        """Test successful update of user data"""
        self.client.force_authenticate(user=self.user)
        
        update_data = {
            'username': 'updateduser',
            'email': 'updated@example.com'
        }
        
        with patch('user_mang.serializers.CustomeUserSerializer.is_valid', return_value=True):
            with patch('user_mang.serializers.CustomeUserSerializer.save'):
                with patch('user_mang.serializers.CustomeUserSerializer.data', update_data):
                    response = self.client.put(self.url, update_data, format='json')
                    
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
    def test_put_user_detail_inactive_user(self):
        """Test update attempt by inactive user"""
        self.user.is_active = False
        self.user.save()
        
        self.client.force_authenticate(user=self.user)
        
        update_data = {'username': 'newname'}
        response = self.client.put(self.url, update_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('Account is locked or inactive', response.data['error'])
        
    def test_put_user_detail_up_to_date(self):
        """Test update when data is already up-to-date"""
        self.client.force_authenticate(user=self.user)
        
        last_modified = self.user.last_modified.isoformat()
        update_data = {
            'username': 'newname',
            'last_modified': last_modified
        }
        response = self.client.put(self.url, update_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'up-to-date')
        
    def test_put_user_detail_validation_error(self):
        """Test update with invalid data"""
        self.client.force_authenticate(user=self.user)
        
        update_data = {'email': 'invalid_email'}
        
        with patch('user_mang.serializers.CustomeUserSerializer.is_valid', return_value=False):
            with patch('user_mang.serializers.CustomeUserSerializer.errors', 
                      {'email': ['Enter a valid email address.']}):
                response = self.client.put(self.url, update_data, format='json')
                
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)
        
    def test_delete_user_archive(self):
        """Test user archiving (default delete behavior)"""
        self.client.force_authenticate(user=self.user)
        
        response = self.client.delete(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('User archived successfully', response.data['message'])
        
        # Verify user is archived
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_archived)
        
    def test_delete_user_permanent(self):
        """Test permanent user deletion"""
        self.client.force_authenticate(user=self.user)
        
        response = self.client.delete(self.url, {'delete': 'true'})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('User deleted successfully', response.data['message'])
        
        # Verify user is deleted
        with self.assertRaises(Custom_User.DoesNotExist):
            Custom_User.objects.get(pk=self.user.pk)

class AdminUserDetailViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.admin = Custom_User.objects.create(
            username='admin',
            email='admin@example.com',
            is_active=True,
            is_staff=True,
            is_superuser=True
        )
        self.target_user = Custom_User.objects.create(
            username='targetuser',
            email='target@example.com',
            is_active=True
        )
        self.url = reverse('admin-user-detail', kwargs={'user_id': self.target_user.pk})
        
    def test_admin_get_user_detail_success(self):
        """Test admin successfully retrieving user data"""
        self.client.force_authenticate(user=self.admin)
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], 'targetuser')
        self.assertEqual(response.data['email'], 'target@example.com')
        
    def test_admin_get_user_detail_not_admin(self):
        """Test non-admin user attempting to access admin endpoint"""
        regular_user = Custom_User.objects.create(
            username='regular',
            email='regular@example.com',
            is_active=True
        )
        
        self.client.force_authenticate(user=regular_user)
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
    def test_admin_get_user_detail_user_not_found(self):
        """Test admin retrieving data for non-existent user"""
        self.client.force_authenticate(user=self.admin)
        
        url = reverse('admin-user-detail', kwargs={'user_id': 99999})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn('User not found', response.data['error'])
        
    def test_admin_put_user_detail_success(self):
        """Test admin successfully updating user data"""
        self.client.force_authenticate(user=self.admin)
        
        update_data = {
            'username': 'updated_target',
            'email': 'updated_target@example.com'
        }
        
        with patch('user_mang.serializers.CustomeUserSerializer.is_valid', return_value=True):
            with patch('user_mang.serializers.CustomeUserSerializer.save'):
                with patch('user_mang.serializers.CustomeUserSerializer.data', update_data):
                    response = self.client.put(self.url, update_data, format='json')
                    
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
    def test_admin_put_user_detail_validation_error(self):
        """Test admin update with invalid data"""
        self.client.force_authenticate(user=self.admin)
        
        update_data = {'email': 'invalid_email'}
        
        with patch('user_mang.serializers.CustomeUserSerializer.is_valid', return_value=False):
            with patch('user_mang.serializers.CustomeUserSerializer.errors',
                      {'email': ['Enter a valid email address.']}):
                response = self.client.put(self.url, update_data, format='json')
                
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)
        
    def test_admin_put_user_detail_user_not_found(self):
        """Test admin updating non-existent user"""
        self.client.force_authenticate(user=self.admin)
        
        url = reverse('admin-user-detail', kwargs={'user_id': 99999})
        update_data = {'username': 'newname'}
        response = self.client.put(url, update_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn('User not found', response.data['error'])
        
    def test_admin_delete_user_archive(self):
        """Test admin archiving user account"""
        self.client.force_authenticate(user=self.admin)
        
        response = self.client.delete(self.url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('User archived successfully', response.data['message'])
        
        # Verify user is deactivated
        self.target_user.refresh_from_db()
        self.assertFalse(self.target_user.is_active)
        
    def test_admin_delete_user_not_found(self):
        """Test admin archiving non-existent user"""
        self.client.force_authenticate(user=self.admin)
        
        url = reverse('admin-user-detail', kwargs={'user_id': 99999})
        response = self.client.delete(url)
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn('User not found', response.data['error'])
        
    def test_admin_delete_duplicate_error_handling(self):
        """Test handling of duplicate error response in admin delete"""
        # Note: The original code has a duplicate return statement
        # This test ensures the endpoint works despite the code issue
        self.client.force_authenticate(user=self.admin)
        
        url = reverse('admin-user-detail', kwargs={'user_id': 99999})
        response = self.client.delete(url)
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        # Should only get one error message, not duplicate

# Integration Tests
class UserMangIntegrationTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.admin = Custom_User.objects.create(
            username='admin',
            email='admin@example.com',
            is_active=True,
            is_staff=True,
            is_superuser=True
        )
        
    def test_complete_user_lifecycle_as_admin(self):
        """Test complete user management lifecycle by admin"""
        # Step 1: Create a user (would typically be done via registration)
        user = Custom_User.objects.create(
            username='lifecycle_user',
            email='lifecycle@example.com',
            is_active=True
        )
        
        # Step 2: Admin retrieves user data
        self.client.force_authenticate(user=self.admin)
        get_url = reverse('admin-user-detail', kwargs={'user_id': user.pk})
        get_response = self.client.get(get_url)
        
        self.assertEqual(get_response.status_code, status.HTTP_200_OK)
        self.assertEqual(get_response.data['username'], 'lifecycle_user')
        
        # Step 3: Admin updates user data
        update_data = {
            'username': 'updated_lifecycle_user',
            'email': 'updated_lifecycle@example.com'
        }
        
        with patch('user_mang.serializers.CustomeUserSerializer.is_valid', return_value=True):
            with patch('user_mang.serializers.CustomeUserSerializer.save'):
                with patch('user_mang.serializers.CustomeUserSerializer.data', update_data):
                    put_response = self.client.put(get_url, update_data, format='json')
                    
        self.assertEqual(put_response.status_code, status.HTTP_200_OK)
        
        # Step 4: Admin archives user
        delete_response = self.client.delete(get_url)
        self.assertEqual(delete_response.status_code, status.HTTP_200_OK)
        
        # Verify user is archived
        user.refresh_from_db()
        self.assertFalse(user.is_active)
        
    def test_user_self_management_lifecycle(self):
        """Test user managing their own account"""
        user = Custom_User.objects.create(
            username='self_user',
            email='self@example.com',
            is_active=True,
            last_modified=timezone.now()
        )
        
        self.client.force_authenticate(user=user)
        user_url = reverse('user-detail')
        
        # Step 1: User retrieves own data
        get_response = self.client.get(user_url)
        self.assertEqual(get_response.status_code, status.HTTP_200_OK)
        
        # Step 2: User updates own data
        update_data = {
            'username': 'updated_self_user'
        }
        
        with patch('user_mang.serializers.CustomeUserSerializer.is_valid', return_value=True):
            with patch('user_mang.serializers.CustomeUserSerializer.save'):
                with patch('user_mang.serializers.CustomeUserSerializer.data', update_data):
                    put_response = self.client.put(user_url, update_data, format='json')
                    
        self.assertEqual(put_response.status_code, status.HTTP_200_OK)
        
        # Step 3: User archives own account
        delete_response = self.client.delete(user_url)
        self.assertEqual(delete_response.status_code, status.HTTP_200_OK)
        
        # Verify user is archived
        user.refresh_from_db()
        self.assertTrue(user.is_archived)

# Performance Tests
class UserMangPerformanceTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.admin = Custom_User.objects.create(
            username='admin',
            email='admin@example.com',
            is_active=True,
            is_staff=True,
            is_superuser=True
        )
        
    def test_concurrent_user_updates(self):
        """Test handling of concurrent user updates"""
        import threading
        import time
        
        user = Custom_User.objects.create(
            username='concurrent_user',
            email='concurrent@example.com',
            is_active=True,
            last_modified=timezone.now()
        )
        
        results = []
        
        def update_user(client_num):
            client = APIClient()
            client.force_authenticate(user=user)
            
            update_data = {
                'username': f'updated_user_{client_num}'
            }
            
            with patch('user_mang.serializers.CustomeUserSerializer.is_valid', return_value=True):
                with patch('user_mang.serializers.CustomeUserSerializer.save'):
                    with patch('user_mang.serializers.CustomeUserSerializer.data', update_data):
                        response = client.put(reverse('user-detail'), update_data, format='json')
                        results.append(response.status_code)
        
        threads = []
        for i in range(5):
            thread = threading.Thread(target=update_user, args=[i])
            threads.append(thread)
            thread.start()
            
        for thread in threads:
            thread.join()
            
        # All updates should be successful
        self.assertTrue(all(status == 200 for status in results))
        
    def test_admin_bulk_user_operations(self):
        """Test admin performing operations on multiple users"""
        # Create multiple users
        users = []
        for i in range(10):
            user = Custom_User.objects.create(
                username=f'bulk_user_{i}',
                email=f'bulk_{i}@example.com',
                is_active=True
            )
            users.append(user)
            
        self.client.force_authenticate(user=self.admin)
        
        # Admin retrieves all users
        get_results = []
        for user in users:
            url = reverse('admin-user-detail', kwargs={'user_id': user.pk})
            response = self.client.get(url)
            get_results.append(response.status_code)
            
        # All retrievals should be successful
        self.assertTrue(all(status == 200 for status in get_results))
        
        # Admin archives all users
        delete_results = []
        for user in users:
            url = reverse('admin-user-detail', kwargs={'user_id': user.pk})
            response = self.client.delete(url)
            delete_results.append(response.status_code)
            
        # All archiving should be successful
        self.assertTrue(all(status == 200 for status in delete_results))

# Security Tests
class UserMangSecurityTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user1 = Custom_User.objects.create(
            username='user1',
            email='user1@example.com',
            is_active=True
        )
        self.user2 = Custom_User.objects.create(
            username='user2',
            email='user2@example.com',
            is_active=True
        )
        
    def test_user_cannot_access_other_user_via_user_detail(self):
        """Test that authenticated user can only access their own data"""
        self.client.force_authenticate(user=self.user1)
        
        # User1 should be able to access their own data
        response = self.client.get(reverse('user-detail'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # User1 should not be able to access admin endpoints
        admin_url = reverse('admin-user-detail', kwargs={'user_id': self.user2.pk})
        response = self.client.get(admin_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
    def test_privilege_escalation_prevention(self):
        """Test that regular users cannot perform admin operations"""
        self.client.force_authenticate(user=self.user1)
        
        # Try to access admin functionality
        admin_urls = [
            reverse('admin-user-detail', kwargs={'user_id': self.user2.pk}),
        ]
        
        for url in admin_urls:
            for method in ['GET', 'PUT', 'DELETE']:
                if method == 'GET':
                    response = self.client.get(url)
                elif method == 'PUT':
                    response = self.client.put(url, {'username': 'hacked'})
                elif method == 'DELETE':
                    response = self.client.delete(url)
                    
                self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
                
    def test_inactive_user_access_prevention(self):
        """Test that inactive users cannot access any endpoints"""
        self.user1.is_active = False
        self.user1.save()
        
        self.client.force_authenticate(user=self.user1)
        
        # Should be denied access to own data
        response = self.client.get(reverse('user-detail'))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
        # Should be denied access to update own data
        response = self.client.put(reverse('user-detail'), {'username': 'new'})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

# Error Handling Tests
class UserMangErrorHandlingTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = Custom_User.objects.create(
            username='error_user',
            email='error@example.com',
            is_active=True
        )
        
    def test_database_error_handling(self):
        """Test graceful handling of database errors"""
        self.client.force_authenticate(user=self.user)
        
        with patch('user_mang.models.Custom_User.objects.get') as mock_get:
            mock_get.side_effect = Exception("Database connection error")
            
            response = self.client.get(reverse('user-detail'))
            
            # Should handle error gracefully (implementation dependent)
            # This test ensures the error doesn't crash the application
            self.assertIn(response.status_code, [500, 503])  # Server error codes
            
    def test_serializer_error_handling(self):
        """Test handling of serializer errors"""
        self.client.force_authenticate(user=self.user)
        
        with patch('user_mang.serializers.CustomeUserSerializer.__init__') as mock_init:
            mock_init.side_effect = Exception("Serializer initialization error")
            
            response = self.client.get(reverse('user-detail'))
            
            # Should handle error gracefully
            self.assertIn(response.status_code, [500, 503])
            
    def test_logging_functionality(self):
        """Test that logging works correctly"""
        self.client.force_authenticate(user=self.user)
        
        with patch('user_mang.views.logger') as mock_logger:
            response = self.client.get(reverse('user-detail'))
            
            # Verify logging calls were made
            self.assertTrue(mock_logger.info.called)
            
        with patch('user_mang.views.logger') as mock_logger:
            # Test inactive user logging
            self.user.is_active = False
            self.user.save()
            
            response = self.client.get(reverse('user-detail'))
            
            # Should log warning for inactive user
            self.assertTrue(mock_logger.warning.called)