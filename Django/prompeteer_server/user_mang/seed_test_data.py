import uuid
from django.core.management.base import BaseCommand
from user_mang.models.custom_user import Custom_User
from user_mang.models.visitor import Visitor
from chat_api.models import Conversation, Message
from chat_api.models.message_request import MessageRequest
from chat_api.models.message_response import MessageResponse
from chat_api.models.message_output import MessageOutput

class Command(BaseCommand):
    help = 'Seed the database with test data for conversations, messages, and normalized fields.'

    def handle(self, *args, **options):
        # Create or get a test user and visitor
        user, _ = Custom_User.objects.get_or_create(username='testuser', defaults={'email': 'testuser@example.com'})
        anon_id = uuid.uuid4()
        visitor, _ = Visitor.objects.get_or_create(anon_id=anon_id, defaults={'user': user})

        # Create conversations
        for i in range(2):
            conv, _ = Conversation.objects.get_or_create(
                conversation_id=uuid.uuid4(),
                defaults={
                    'user': user,
                    'visitor': visitor,
                    'title': f'Test Conversation {i+1}',
                    'local_only': False
                }
            )
            # Create messages for each conversation
            for j in range(2):
                # Create normalized request/response/output
                req = MessageRequest.objects.create(
                    request_model='gpt-4',
                    request_messages_system_role='system',
                    request_messages_system_content='You are a helpful assistant.',
                    request_messages_user_role='user',
                    request_messages_user_content=f'Test message {j+1} in conversation {i+1}',
                    request_temperature=0.7,
                    request_top_p=1.0,
                    request_n=1,
                    request_stream=False,
                    request_stop=None,
                    request_max_tokens=128
                )
                res = MessageResponse.objects.create(
                    response_role='assistant',
                    response_content=f'Response to message {j+1} in conversation {i+1}',
                    finish_reason='stop',
                    usage={"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}
                )
                out = MessageOutput.objects.create(
                    output_type='message',
                    output_id=str(uuid.uuid4()),
                    output_status='completed',
                    output_role='assistant',
                    output_content_type='output_text',
                    output_content_text=f'Output for message {j+1} in conversation {i+1}',
                    output_content_annotations='[]'
                )
                Message.objects.create(
                    message_id=uuid.uuid4(),
                    conversation_id=conv,
                    vote=True,
                    metadata={"test": True},
                    embedding={"vector": [0.1, 0.2, 0.3]},
                    request_id=req,
                    response_id=res,
                    output_id=out
                )
        self.stdout.write(self.style.SUCCESS('Database seeded with test conversations, messages, and normalized fields.'))
