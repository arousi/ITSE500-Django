import os
import django
import sys

# Set up Django environment
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'prompeteer_server.settings')
django.setup()



import uuid
from user_mang.models.custom_user import Custom_User
from user_mang.models.visitor import Visitor
from chat_api.models.conversation import Conversation
from chat_api.models.message import Message
from chat_api.models.message_request import MessageRequest
from chat_api.models.message_response import MessageResponse
from chat_api.models.message_output import MessageOutput

def seed():
    # Create or get a test user and visitor
    user, _ = Custom_User.objects.get_or_create(username='testuser', defaults={'email': 'testuser@example.com'})
    try:
        visitor = Visitor.objects.get(username='anon12345')
    except Visitor.DoesNotExist:
        anon_id = uuid.uuid4()
        visitor = Visitor.objects.create(anon_id=anon_id, username='anon12345')

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
                status='stop',
                model='gpt-4',
                usage_input_tokens=10,
                usage_output_tokens=20,
                usage_total_tokens=30,
                metadata={"response_content": f"Response to message {j+1} in conversation {i+1}", "role": "assistant"}
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
    print('Database seeded with test conversations, messages, and normalized fields.')

if __name__ == "__main__":
    seed()