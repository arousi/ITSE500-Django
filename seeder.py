import os
import django
import sys
import uuid
import random
from datetime import timedelta
from django.utils import timezone

# Set up Django environment
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'prompeteer_server.settings')
django.setup()

from user_mang.models.custom_user import Custom_User
from chat_api.models.conversation import Conversation
from chat_api.models.message import Message
from chat_api.models.message_request import MessageRequest
from chat_api.models.message_response import MessageResponse
from chat_api.models.message_output import MessageOutput
from crypto_api.models import UserKeyMaterial
from auth_api.models.oauth_state import OAuthState
from auth_api.models.provider_oauth_token import ProviderOAuthToken
from chat_api.models.attachment import Attachment

def seed():
    # --- USERS ---
    users = []
    for i in range(10):
        is_visitor = (i == 0)
        user, _ = Custom_User.objects.get_or_create(
            username=f'user{i}',
            defaults={
                'email': f'user{i}@example.com',
                'is_visitor': is_visitor,
                'phone_number': f'12345678{i}',
                'biometric_enabled': not is_visitor,
                'user_password': 'hashedpassword',
                'email_verified': not is_visitor,
                'profile_email_verified': not is_visitor,
            }
        )
        users.append(user)

        # --- CRYPTO KEY MATERIAL ---
        UserKeyMaterial.objects.get_or_create(
            user=user,
            defaults={
                'umk_b64': 'dGVzdF9rZXlfYmFzZTY0X2VuY29kZWQ=',
                'version': 1,
            }
        )

        # --- OAUTH STATE ---
        OAuthState.objects.get_or_create(
            state=f'teststate{i}',
            defaults={
                'provider': 'google',
                'code_challenge': 'challenge',
                'code_verifier': 'verifier',
                'redirect_uri': 'http://localhost/callback',
                'mobile_redirect': None,
                'result_payload': None,
                'result_retrieved': False,
                'scope': 'openid email',
                'user': user,
                'expires_at': timezone.now() + timedelta(minutes=10),
                'used': False,
            }
        )

        # --- PROVIDER OAUTH TOKEN ---
        ProviderOAuthToken.objects.get_or_create(
            user=user,
            provider='google',
            defaults={
                'access_token': f'testaccesstoken{i}',
                'refresh_token': f'testrefreshtoken{i}',
                'token_type': 'Bearer',
                'scope': 'openid email',
                'expires_at': timezone.now() + timedelta(days=1),
            }
        )

        # --- CONVERSATIONS & MESSAGES ---
        for c in range(2):
            conv, _ = Conversation.objects.get_or_create(
                conversation_id=uuid.uuid4(),
                defaults={
                    'user_id': user,
                    'title': f'User{i} Conversation {c+1}',
                    'local_only': False
                }
            )
            for m in range(2):
                req = MessageRequest.objects.create(
                    request_model='gpt-4',
                    request_input=f"Input {m+1} for conversation {c+1} user {i}",
                    request_system_role='system',
                    request_system_content='You are a helpful assistant.',
                    request_system_prompt='System prompt here.',
                    request_use_structured_output=False,
                    request_structured_schema='{}',
                    request_user_role='user',
                    request_user_content=f'Test message {m+1} in conversation {c+1} user {i}',
                    request_min_p=0.1,
                    request_temperature=0.7,
                    request_top_p=1.0,
                    request_n=1,
                    request_top_k=40,
                    request_stream=False,
                    request_stop=None,
                    request_max_tokens=128,
                    repeat_penalty=1.1,
                )
                res = MessageResponse.objects.create(
                    response_id=str(uuid.uuid4()),
                    object='chat.completion',
                    created_at=timezone.now(),
                    status='completed',
                    error=None,
                    incomplete_details=None,
                    max_output_tokens=128,
                    model='gpt-4',
                    parallel_tool_calls=False,
                    previous_response_id=None,
                    instructions='Instructions here.',
                    reasoning_effort='Low',
                    reasoning_summary='Summary here.',
                    store=True,
                    temperature=0.7,
                    text_format_type='plain',
                    tool_choice='none',
                    tools='[]',
                    top_p=1.0,
                    truncation=None,
                    usage_input_tokens=10,
                    usage_output_tokens=20,
                    usage_total_tokens=30,
                    user=user.username,
                    metadata={"response_content": f"Response to message {m+1} in conversation {c+1} user {i}", "role": "assistant"}
                )
                out = MessageOutput.objects.create(
                    output_type='message',
                    output_id=str(uuid.uuid4()),
                    output_status='completed',
                    output_role='assistant',
                    output_content_type='output_text',
                    output_content_text=f'Output for message {m+1} in conversation {c+1} user {i}',
                    output_content_annotations='[]'
                )
                msg = Message.objects.create(
                    message_id=uuid.uuid4(),
                    user_id=user,
                    request_id=req,
                    response_id=res,
                    output_id=out,
                    has_image=False,
                    metadata={"test": True, "msg_num": m+1},
                    has_embedding=False,
                    has_document=False,
                    vote=bool(random.getrandbits(1)),
                )
                # Optionally, set the conversation's message_id to the first message
                if m == 0:
                    conv.message_id = msg
                    conv.save()
                # --- ATTACHMENT ---
                Attachment.objects.create(
                    user=user,
                    conversation=conv,
                    message=msg,
                    type='image',
                    mime_type='image/png',
                    file_path=f"/fake/path/{uuid.uuid4()}.png",
                    encrypted_blob=None,
                    size_bytes=12345,
                    width=640,
                    height=480,
                    sha256='deadbeef'*8,
                    is_encrypted=False,
                    enc_algo=None,
                    iv_base64=None,
                    key_ref=None,
                )
                

    print('Database seeded with 10 users, conversations, messages, attachments, crypto keys, and OAuth tokens.')

if __name__ == "__main__":
    seed()