"""
Comprehensive tests for chat_api views
Testing conversation and message management functionality
"""
import pytest
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from unittest.mock import patch, MagicMock
from user_mang.models.visitor import Visitor
from user_mang.models.custom_user import Custom_User
from chat_api.models import Conversation, Message
from chat_api.models.message_request import MessageRequest
from chat_api.models.message_response import MessageResponse 
from chat_api.models.message_output import MessageOutput
import json
import uuid

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def sample_visitor():
    return Visitor.objects.create(
        device_id='test_device_123',
        anon_id='anon_test_123'
    )

@pytest.fixture
def sample_user():
    return Custom_User.objects.create(
        username='testuser',
        email='test@example.com',
        is_active=True
    )

@pytest.fixture
def sample_conversation(sample_visitor):
    return Conversation.objects.create(
        visitor=sample_visitor,
        title='Test Conversation',
        id=str(uuid.uuid4())
    )

@pytest.fixture
def sample_message(sample_conversation):
    return Message.objects.create(
        conversation=sample_conversation,
        message_id=str(uuid.uuid4()),
        content='Test message content',
        role='user'
    )

class SyncConversationsViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.visitor = Visitor.objects.create(
            device_id='test_device_123',
            anon_id='anon_test_123'
        )
        self.conversation = Conversation.objects.create(
            visitor=self.visitor,
            title='Test Conversation',
            id=str(uuid.uuid4())
        )
        
    def test_sync_conversations_get_by_anon_id(self):
        """Test GET sync conversations by anon_id"""
        url = reverse('sync-conversations-anon', kwargs={'anon_id': self.visitor.anon_id})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('conversations', response.data)
        self.assertEqual(len(response.data['conversations']), 1)
        self.assertEqual(response.data['conversations'][0], self.conversation.id)
        
    def test_sync_conversations_get_by_user_id(self):
        """Test GET sync conversations by user_id"""
        user = Custom_User.objects.create(username='testuser', email='test@example.com')
        self.visitor.user_id = user.pk
        self.visitor.save()
        
        url = reverse('sync-conversations-user', kwargs={'user_id': user.pk})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('conversations', response.data)
        
    def test_sync_conversations_get_visitor_not_found(self):
        """Test GET sync conversations with non-existent visitor"""
        url = reverse('sync-conversations-anon', kwargs={'anon_id': 'non_existent'})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn('Visitor not found', response.data['error'])
        
    def test_sync_conversations_post_success(self):
        """Test POST sync conversations with valid data"""
        url = reverse('sync-conversations-anon', kwargs={'anon_id': self.visitor.anon_id})
        
        # Create test data
        conversation_data = {
            'id': str(uuid.uuid4()),
            'title': 'New Conversation',
            'created_at': '2024-01-01T00:00:00Z',
            'messages': [
                {
                    'message_id': str(uuid.uuid4()),
                    'content': 'Test message',
                    'role': 'user',
                    'timestamp': '2024-01-01T00:00:00Z',
                    'request': {
                        'id': str(uuid.uuid4()),
                        'content': 'Request content',
                        'timestamp': '2024-01-01T00:00:00Z'
                    },
                    'response': {
                        'id': str(uuid.uuid4()),
                        'content': 'Response content',
                        'timestamp': '2024-01-01T00:00:00Z'
                    }
                }
            ]
        }
        
        data = {'conversations': [conversation_data]}
        
        with patch('chat_api.serializers.ConversationSerializer.is_valid', return_value=True):
            with patch('chat_api.serializers.ConversationSerializer.validated_data', 
                      {'visitor': self.visitor.id, 'title': 'New Conversation'}):
                response = self.client.post(url, data, format='json')
                
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('created', response.data)
        self.assertIn('updated', response.data)
        
    def test_sync_conversations_post_invalid_format(self):
        """Test POST sync conversations with invalid data format"""
        url = reverse('sync-conversations-anon', kwargs={'anon_id': self.visitor.anon_id})
        
        # Invalid data - conversations should be a list
        data = {'conversations': 'invalid_format'}
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Invalid conversations format', response.data['error'])
        
    def test_sync_conversations_post_visitor_not_found(self):
        """Test POST sync conversations with non-existent visitor"""
        url = reverse('sync-conversations-anon', kwargs={'anon_id': 'non_existent'})
        
        data = {'conversations': []}
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn('Visitor not found', response.data['error'])
        
    def test_sync_conversations_post_with_messages(self):
        """Test POST sync conversations with nested messages"""
        url = reverse('sync-conversations-anon', kwargs={'anon_id': self.visitor.anon_id})
        
        conversation_id = str(uuid.uuid4())
        message_id = str(uuid.uuid4())
        request_id = str(uuid.uuid4())
        response_id = str(uuid.uuid4())
        output_id = str(uuid.uuid4())
        
        conversation_data = {
            'id': conversation_id,
            'title': 'Test Conversation with Messages',
            'messages': [
                {
                    'message_id': message_id,
                    'content': 'Test message content',
                    'role': 'user',
                    'request': {
                        'id': request_id,
                        'content': 'Request content',
                        'model': 'gpt-4',
                        'temperature': 0.7
                    },
                    'response': {
                        'id': response_id,
                        'content': 'Response content',
                        'model': 'gpt-4',
                        'tokens_used': 150
                    },
                    'output': {
                        'id': output_id,
                        'content': 'Output content',
                        'format': 'text'
                    }
                }
            ]
        }
        
        data = {'conversations': [conversation_data]}
        
        # Mock all serializers to be valid
        with patch('chat_api.serializers.ConversationSerializer.is_valid', return_value=True), \
             patch('chat_api.serializers.ConversationSerializer.validated_data', 
                   {'visitor': self.visitor.id, 'title': 'Test Conversation with Messages'}), \
             patch('chat_api.serializers.MessageRequestSerializer.is_valid', return_value=True), \
             patch('chat_api.serializers.MessageRequestSerializer.validated_data', 
                   {'content': 'Request content'}), \
             patch('chat_api.serializers.MessageResponseSerializer.is_valid', return_value=True), \
             patch('chat_api.serializers.MessageResponseSerializer.validated_data', 
                   {'content': 'Response content'}), \
             patch('chat_api.serializers.MessageOutputSerializer.is_valid', return_value=True), \
             patch('chat_api.serializers.MessageOutputSerializer.validated_data', 
                   {'content': 'Output content'}), \
             patch('chat_api.serializers.MessageSerializer.is_valid', return_value=True), \
             patch('chat_api.serializers.MessageSerializer.validated_data', 
                   {'conversation': conversation_id, 'content': 'Test message content'}):
            
            response = self.client.post(url, data, format='json')
            
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('messages_created', response.data)
        self.assertIn('messages_updated', response.data)

class AssociateDeviceViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse('associate-device')
        self.visitor = Visitor.objects.create(
            device_id='original_device',
            anon_id='anon_test_123',
            related_devices=[]
        )
        
    def test_associate_device_success(self):
        """Test successful device association"""
        data = {
            'anon_id': self.visitor.anon_id,
            'device_id': 'new_device_456'
        }
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('Device associated successfully', response.data['message'])
        
        # Verify device was added
        self.visitor.refresh_from_db()
        self.assertIn('new_device_456', self.visitor.related_devices)
        
    def test_associate_device_duplicate(self):
        """Test associating device that's already associated"""
        # Pre-associate a device
        self.visitor.related_devices = ['existing_device']
        self.visitor.save()
        
        data = {
            'anon_id': self.visitor.anon_id,
            'device_id': 'existing_device'
        }
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Verify device list doesn't have duplicates
        self.visitor.refresh_from_db()
        device_count = self.visitor.related_devices.count('existing_device')
        self.assertEqual(device_count, 1)
        
    def test_associate_device_missing_data(self):
        """Test device association with missing required data"""
        # Missing device_id
        data = {'anon_id': self.visitor.anon_id}
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('anon_id and device_id are required', response.data['error'])
        
        # Missing anon_id
        data = {'device_id': 'new_device'}
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('anon_id and device_id are required', response.data['error'])
        
    def test_associate_device_visitor_not_found(self):
        """Test device association with non-existent visitor"""
        data = {
            'anon_id': 'non_existent_anon_id',
            'device_id': 'new_device'
        }
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn('Visitor not found', response.data['error'])

# Integration Tests
class ChatAPIIntegrationTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.visitor = Visitor.objects.create(
            device_id='integration_test_device',
            anon_id='integration_anon_123'
        )
        
    def test_complete_conversation_flow(self):
        """Test complete conversation creation and synchronization flow"""
        # Step 1: Create initial conversation via sync
        url = reverse('sync-conversations-anon', kwargs={'anon_id': self.visitor.anon_id})
        
        conversation_id = str(uuid.uuid4())
        conversation_data = {
            'id': conversation_id,
            'title': 'Integration Test Conversation',
            'messages': []
        }
        
        sync_data = {'conversations': [conversation_data]}
        
        with patch('chat_api.serializers.ConversationSerializer.is_valid', return_value=True):
            with patch('chat_api.serializers.ConversationSerializer.validated_data',
                      {'visitor': self.visitor.id, 'title': 'Integration Test Conversation'}):
                sync_response = self.client.post(url, sync_data, format='json')
                
        self.assertEqual(sync_response.status_code, status.HTTP_200_OK)
        
        # Step 2: Retrieve conversations
        get_response = self.client.get(url)
        self.assertEqual(get_response.status_code, status.HTTP_200_OK)
        self.assertTrue(len(get_response.data['conversations']) >= 1)
        
        # Step 3: Associate additional device
        associate_url = reverse('associate-device')
        associate_data = {
            'anon_id': self.visitor.anon_id,
            'device_id': 'secondary_device'
        }
        associate_response = self.client.post(associate_url, associate_data, format='json')
        self.assertEqual(associate_response.status_code, status.HTTP_200_OK)
        
        # Verify device association
        self.visitor.refresh_from_db()
        self.assertIn('secondary_device', self.visitor.related_devices)
        
    def test_conversation_with_full_message_lifecycle(self):
        """Test conversation with complete message request/response/output cycle"""
        url = reverse('sync-conversations-anon', kwargs={'anon_id': self.visitor.anon_id})
        
        conversation_id = str(uuid.uuid4())
        message_id = str(uuid.uuid4())
        
        full_conversation = {
            'id': conversation_id,
            'title': 'Full Message Lifecycle Test',
            'messages': [
                {
                    'message_id': message_id,
                    'content': 'User question about AI',
                    'role': 'user',
                    'request': {
                        'id': str(uuid.uuid4()),
                        'content': 'What is artificial intelligence?',
                        'model': 'gpt-4',
                        'temperature': 0.7,
                        'max_tokens': 1000
                    },
                    'response': {
                        'id': str(uuid.uuid4()),
                        'content': 'AI is a branch of computer science...',
                        'model': 'gpt-4',
                        'tokens_used': 150,
                        'finish_reason': 'stop'
                    },
                    'output': {
                        'id': str(uuid.uuid4()),
                        'content': 'Formatted AI explanation',
                        'format': 'markdown',
                        'processed': True
                    }
                }
            ]
        }
        
        data = {'conversations': [full_conversation]}
        
        # Mock all serializers
        with patch('chat_api.serializers.ConversationSerializer.is_valid', return_value=True), \
             patch('chat_api.serializers.ConversationSerializer.validated_data',
                   {'visitor': self.visitor.id, 'title': 'Full Message Lifecycle Test'}), \
             patch('chat_api.serializers.MessageRequestSerializer.is_valid', return_value=True), \
             patch('chat_api.serializers.MessageRequestSerializer.validated_data',
                   {'content': 'What is artificial intelligence?'}), \
             patch('chat_api.serializers.MessageResponseSerializer.is_valid', return_value=True), \
             patch('chat_api.serializers.MessageResponseSerializer.validated_data',
                   {'content': 'AI is a branch of computer science...'}), \
             patch('chat_api.serializers.MessageOutputSerializer.is_valid', return_value=True), \
             patch('chat_api.serializers.MessageOutputSerializer.validated_data',
                   {'content': 'Formatted AI explanation'}), \
             patch('chat_api.serializers.MessageSerializer.is_valid', return_value=True), \
             patch('chat_api.serializers.MessageSerializer.validated_data',
                   {'conversation': conversation_id, 'content': 'User question about AI'}):
            
            response = self.client.post(url, data, format='json')
            
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['created'], 1)
        self.assertEqual(response.data['messages_created'], 1)

# Performance and Edge Case Tests
class ChatAPIPerformanceTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.visitor = Visitor.objects.create(
            device_id='perf_test_device',
            anon_id='perf_anon_123'
        )
        
    def test_bulk_conversation_sync(self):
        """Test syncing multiple conversations at once"""
        url = reverse('sync-conversations-anon', kwargs={'anon_id': self.visitor.anon_id})
        
        # Create 10 conversations with 5 messages each
        conversations = []
        for i in range(10):
            messages = []
            for j in range(5):
                messages.append({
                    'message_id': str(uuid.uuid4()),
                    'content': f'Message {j} in conversation {i}',
                    'role': 'user' if j % 2 == 0 else 'assistant'
                })
            
            conversations.append({
                'id': str(uuid.uuid4()),
                'title': f'Bulk Test Conversation {i}',
                'messages': messages
            })
        
        data = {'conversations': conversations}
        
        # Mock serializers for bulk operation
        with patch('chat_api.serializers.ConversationSerializer.is_valid', return_value=True), \
             patch('chat_api.serializers.ConversationSerializer.validated_data',
                   {'visitor': self.visitor.id, 'title': 'Bulk Test Conversation'}), \
             patch('chat_api.serializers.MessageSerializer.is_valid', return_value=True), \
             patch('chat_api.serializers.MessageSerializer.validated_data',
                   {'conversation': 'test', 'content': 'Test message'}):
            
            response = self.client.post(url, data, format='json')
            
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['created'], 10)
        self.assertEqual(response.data['messages_created'], 50)
        
    def test_empty_conversations_list(self):
        """Test syncing with empty conversations list"""
        url = reverse('sync-conversations-anon', kwargs={'anon_id': self.visitor.anon_id})
        
        data = {'conversations': []}
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['created'], 0)
        self.assertEqual(response.data['updated'], 0)
        
    def test_malformed_conversation_data(self):
        """Test handling of malformed conversation data"""
        url = reverse('sync-conversations-anon', kwargs={'anon_id': self.visitor.anon_id})
        
        # Conversation without ID should be skipped
        conversations = [
            {'title': 'No ID Conversation'},  # Missing ID
            {
                'id': str(uuid.uuid4()),
                'title': 'Valid Conversation'
            }
        ]
        
        data = {'conversations': conversations}
        
        with patch('chat_api.serializers.ConversationSerializer.is_valid', return_value=True), \
             patch('chat_api.serializers.ConversationSerializer.validated_data',
                   {'visitor': self.visitor.id, 'title': 'Valid Conversation'}):
            
            response = self.client.post(url, data, format='json')
            
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Only one conversation should be processed (the one with ID)
        self.assertEqual(response.data['created'], 1)

# Error Handling Tests
class ChatAPIErrorHandlingTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        
    def test_database_error_handling(self):
        """Test graceful handling of database errors"""
        visitor = Visitor.objects.create(
            device_id='error_test_device',
            anon_id='error_anon_123'
        )
        
        url = reverse('sync-conversations-anon', kwargs={'anon_id': visitor.anon_id})
        
        conversation_data = {
            'id': str(uuid.uuid4()),
            'title': 'Error Test Conversation'
        }
        
        data = {'conversations': [conversation_data]}
        
        # Simulate database error
        with patch('chat_api.models.Conversation.objects.update_or_create') as mock_update:
            mock_update.side_effect = Exception("Database connection error")
            
            response = self.client.post(url, data, format='json')
            
        # Should still return 200 but with 0 created/updated
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['created'], 0)
        
    def test_serializer_validation_errors(self):
        """Test handling of serializer validation errors"""
        visitor = Visitor.objects.create(
            device_id='validation_test_device',
            anon_id='validation_anon_123'
        )
        
        url = reverse('sync-conversations-anon', kwargs={'anon_id': visitor.anon_id})
        
        conversation_data = {
            'id': str(uuid.uuid4()),
            'title': 'Validation Test Conversation'
        }
        
        data = {'conversations': [conversation_data]}
        
        # Mock serializer to be invalid
        with patch('chat_api.serializers.ConversationSerializer.is_valid', return_value=False):
            response = self.client.post(url, data, format='json')
            
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['created'], 0)
        self.assertEqual(response.data['updated'], 0)