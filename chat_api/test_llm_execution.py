"""SDD + TDD tests for chat_api async LLM execution (Message.status state machine).

State machine (Message.status):
    pending --success--> complete
    pending --failure--> error
    complete / error are terminal (re-execution is a no-op; illegal transitions rejected).

The provider call (chat_api.services.llm.call_provider) is MOCKED — no network, and
litellm/openai need not be installed. Written RED first.
"""
from unittest.mock import patch

from django.test import TestCase
from rest_framework import status as http_status
from rest_framework.test import APIClient

from user_mang.models.custom_user import Custom_User
from chat_api.models.conversation import Conversation
from chat_api.models.message import Message
from chat_api.models.message_request import MessageRequest

FAKE_RESULT = {
    "response_id": "resp_test_123",
    "model": "gpt-4o-mini",
    "output_text": "Hello from the model.",
    "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
}


def _user(name="alice"):
    return Custom_User.objects.create(
        username=name, email=f"{name}@example.com", is_active=True, email_verified=True
    )


class MessageStateMachineTest(TestCase):
    def setUp(self):
        self.user = _user()
        self.conv = Conversation.objects.create(user_id=self.user, title="c")

    def _pending_message(self):
        req = MessageRequest.objects.create(request_model="gpt-4o-mini", request_user_content="Hi")
        return Message.objects.create(
            user_id=self.user, conversation_id=self.conv, request_id=req, status="pending"
        )

    def test_transition_guard_rejects_illegal(self):
        from chat_api.services.state import transition_message, InvalidTransition
        msg = Message.objects.create(user_id=self.user, conversation_id=self.conv, status="complete")
        with self.assertRaises(InvalidTransition):
            transition_message(msg, "pending")  # complete is terminal

    @patch("chat_api.services.llm.call_provider", return_value=FAKE_RESULT)
    def test_pending_to_complete_persists_response_and_output(self, mock_provider):
        from chat_api.services.llm import execute_inference
        msg = self._pending_message()
        execute_inference(msg.pk)
        msg.refresh_from_db()
        self.assertEqual(msg.status, "complete")
        self.assertIsNotNone(msg.response_id)
        self.assertIsNotNone(msg.output_id)
        self.assertEqual(msg.response_id.usage_total_tokens, 15)
        self.assertEqual(msg.response_id.model_name, "gpt-4o-mini")
        self.assertEqual(msg.output_id.output_content_text, "Hello from the model.")
        self.assertEqual(msg.output_id.output_role, "assistant")
        mock_provider.assert_called_once()

    @patch("chat_api.services.llm.call_provider", side_effect=RuntimeError("provider 500"))
    def test_pending_to_error_on_provider_failure(self, mock_provider):
        from chat_api.services.llm import execute_inference
        msg = self._pending_message()
        execute_inference(msg.pk)
        msg.refresh_from_db()
        self.assertEqual(msg.status, "error")

    @patch("chat_api.services.llm.call_provider", return_value=FAKE_RESULT)
    def test_execute_is_idempotent_on_terminal(self, mock_provider):
        from chat_api.services.llm import execute_inference
        msg = Message.objects.create(user_id=self.user, conversation_id=self.conv, status="complete")
        execute_inference(msg.pk)
        mock_provider.assert_not_called()  # a terminal message is never re-executed
        msg.refresh_from_db()
        self.assertEqual(msg.status, "complete")


class SendMessageEndpointTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = _user()
        self.conv = Conversation.objects.create(user_id=self.user, title="c")
        self.client.force_authenticate(self.user)
        self.url = f"/api/v1/chat_api/conversations/{self.conv.pk}/messages/"

    @patch("chat_api.services.llm.call_provider", return_value=FAKE_RESULT)
    def test_send_prompt_runs_inference_and_returns_complete(self, mock_provider):
        resp = self.client.post(
            self.url,
            {"request": {"request_model": "gpt-4o-mini", "request_user_content": "Hi"}},
            format="json",
        )
        self.assertEqual(resp.status_code, http_status.HTTP_201_CREATED)
        msg = Message.objects.get(conversation_id=self.conv)
        self.assertEqual(msg.status, "complete")
        self.assertEqual(msg.output_id.output_content_text, "Hello from the model.")

    def test_plain_message_without_request_stays_complete(self):
        # regression: existing plain-create behavior preserved (no inference triggered)
        resp = self.client.post(self.url, {}, format="json")
        self.assertEqual(resp.status_code, http_status.HTTP_201_CREATED)
        msg = Message.objects.get(conversation_id=self.conv)
        self.assertEqual(msg.status, "complete")
