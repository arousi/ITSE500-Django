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

    @patch("chat_api.services.llm.call_provider", side_effect=RuntimeError("provider 500"))
    def test_error_records_reason(self, mock_provider):
        """The BLOCKER: the failure reason must be recorded, not just the status flip."""
        from chat_api.services.llm import execute_inference
        msg = self._pending_message()
        execute_inference(msg.pk)
        msg.refresh_from_db()
        self.assertEqual(msg.status, "error")
        self.assertIsNotNone(msg.response_id)
        self.assertEqual(msg.response_id.status, "failed")
        self.assertIn("provider 500", msg.response_id.error)

    def test_call_provider_synthesizes_response_id_when_none(self):
        """BLOCKER fix: call_provider must never discard a valid completion just
        because the provider returned no id -- it synthesizes a local one.

        litellm isn't installed in this venv (call_provider imports it lazily),
        so we inject a fake module into sys.modules to exercise the real
        call_provider body without needing the real package installed.
        """
        import sys
        import types
        from chat_api.services.llm import call_provider

        fake_message = types.SimpleNamespace(content="hi")
        fake_choice = types.SimpleNamespace(message=fake_message)
        fake_completion = types.SimpleNamespace(
            id=None,
            model="gpt-4o-mini",
            choices=[fake_choice],
            usage=types.SimpleNamespace(prompt_tokens=1, completion_tokens=1, total_tokens=2),
        )
        fake_litellm = types.SimpleNamespace(completion=lambda **kwargs: fake_completion)
        req = MessageRequest.objects.create(request_model="gpt-4o-mini", request_user_content="Hi")

        with patch.dict(sys.modules, {"litellm": fake_litellm}):
            result = call_provider(req)

        self.assertIsNotNone(result["response_id"])
        self.assertTrue(result["response_id"].startswith("local-"))

    @patch("chat_api.services.llm.call_provider")
    def test_response_id_none_completes(self, mock_provider):
        """A valid completion with no provider-supplied id must still complete
        (never be discarded as an error), and a MessageResponse with a
        synthesized (non-empty) id is linked."""
        from chat_api.services.llm import execute_inference
        mock_provider.return_value = {
            "response_id": f"local-{'0' * 8}-synthesized",
            "model": "gpt-4o-mini",
            "output_text": "hi",
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        }
        msg = self._pending_message()
        execute_inference(msg.pk)
        msg.refresh_from_db()
        self.assertEqual(msg.status, "complete")
        self.assertIsNotNone(msg.response_id)
        self.assertTrue(msg.response_id.pk)  # synthesized id is a non-empty string
        self.assertIsNotNone(msg.output_id)


class DispatchInferenceTest(TestCase):
    """dispatch_inference must fall back to inline execution both when Celery
    is absent (covered implicitly by every other test in this venv, which has
    no celery installed) AND when the broker is unreachable (.delay() raises)."""

    def setUp(self):
        self.user = _user()
        self.conv = Conversation.objects.create(user_id=self.user, title="c")

    def _pending_message(self):
        req = MessageRequest.objects.create(request_model="gpt-4o-mini", request_user_content="Hi")
        return Message.objects.create(
            user_id=self.user, conversation_id=self.conv, request_id=req, status="pending"
        )

    @patch("chat_api.services.llm.call_provider", return_value=FAKE_RESULT)
    def test_broker_down_falls_back_to_inline(self, mock_provider):
        """celery isn't installed in this venv, so `chat_api.tasks` (which does
        `from celery import shared_task`) can't really be imported here either --
        inject a fake `chat_api.tasks` module into sys.modules whose
        `run_inference.delay` raises, to exercise the "import succeeds but the
        broker is unreachable" branch of dispatch_inference."""
        import sys
        import types
        from chat_api.services.llm import dispatch_inference

        msg = self._pending_message()

        fake_run_inference = types.SimpleNamespace(
            delay=lambda message_id: (_ for _ in ()).throw(ConnectionError("broker down"))
        )
        fake_tasks_module = types.SimpleNamespace(run_inference=fake_run_inference)

        with patch.dict(sys.modules, {"chat_api.tasks": fake_tasks_module}):
            dispatch_inference(msg.pk)

        msg.refresh_from_db()
        self.assertEqual(msg.status, "complete")  # ran inline instead of hanging in "pending"
        mock_provider.assert_called_once()


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

    @patch("chat_api.services.llm.call_provider", return_value=FAKE_RESULT)
    def test_message_create_with_request_and_top_level_request_id(self, mock_provider):
        """Pin the behavior when a POST body has BOTH a nested `request` object
        AND a stray top-level `request_id`: the nested-`request` inference path
        wins, the stray top-level `request_id` is ignored (no orphan MessageRequest,
        exactly one MessageRequest ends up linked to the created message)."""
        stray_request = MessageRequest.objects.create(
            request_model="stray-model", request_user_content="should be ignored"
        )
        resp = self.client.post(
            self.url,
            {
                "request_id": str(stray_request.pk),
                "request": {"request_model": "gpt-4o-mini", "request_user_content": "Hi"},
            },
            format="json",
        )
        self.assertEqual(resp.status_code, http_status.HTTP_201_CREATED)
        msg = Message.objects.get(conversation_id=self.conv)
        mock_provider.assert_called_once()
        self.assertEqual(msg.status, "complete")
        # inference ran on the nested `request`, not the stray one
        self.assertNotEqual(msg.request_id_id, stray_request.pk)
        self.assertEqual(msg.request_id.request_model, "gpt-4o-mini")
        # exactly one MessageRequest is linked to this message (no orphan wiring)
        self.assertEqual(MessageRequest.objects.filter(message=msg).count(), 1)
