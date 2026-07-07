"""TDD behavior tests for the chat_api conversation + message REST endpoints.

Written RED first (the endpoints don't exist yet — chat_api routing is disabled).
They pin the contract for this /expand increment:
  * authentication required
  * user-scoped ownership via queryset (another user's resource -> 404, never leaked)
  * pagination envelope on lists
  * create semantics (owned by caller; Message defaults to the "complete" lifecycle state)

LLM execution and attachment upload are deliberately OUT of scope here (later increments).
"""
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient

from user_mang.models.custom_user import Custom_User
from chat_api.models.conversation import Conversation
from chat_api.models.message import Message

CONVS = "/api/v1/chat_api/conversations/"


def _user(name):
    return Custom_User.objects.create(
        username=name, email=f"{name}@example.com", is_active=True, email_verified=True
    )


class ChatConversationEndpointsTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.alice = _user("alice")
        self.bob = _user("bob")
        self.alice_conv = Conversation.objects.create(user_id=self.alice, title="alice-conv")
        self.bob_conv = Conversation.objects.create(user_id=self.bob, title="bob-conv")

    def test_list_requires_auth(self):
        self.assertEqual(self.client.get(CONVS).status_code, status.HTTP_401_UNAUTHORIZED)

    def test_list_returns_only_own_paginated(self):
        self.client.force_authenticate(self.alice)
        resp = self.client.get(CONVS)
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIn("results", resp.data)   # paginated envelope
        self.assertIn("count", resp.data)
        titles = [c["title"] for c in resp.data["results"]]
        self.assertIn("alice-conv", titles)
        self.assertNotIn("bob-conv", titles)  # ownership: never see another user's

    def test_create_owned_by_caller(self):
        self.client.force_authenticate(self.alice)
        resp = self.client.post(CONVS, {"title": "new-conv"}, format="json")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Conversation.objects.get(title="new-conv").user_id_id, self.alice.pk)

    def test_retrieve_own_ok_others_404(self):
        self.client.force_authenticate(self.alice)
        self.assertEqual(self.client.get(f"{CONVS}{self.alice_conv.pk}/").status_code, status.HTTP_200_OK)
        self.assertEqual(self.client.get(f"{CONVS}{self.bob_conv.pk}/").status_code, status.HTTP_404_NOT_FOUND)

    def test_update_own_ok_others_404(self):
        self.client.force_authenticate(self.alice)
        ok = self.client.patch(f"{CONVS}{self.alice_conv.pk}/", {"title": "renamed"}, format="json")
        self.assertEqual(ok.status_code, status.HTTP_200_OK)
        self.alice_conv.refresh_from_db()
        self.assertEqual(self.alice_conv.title, "renamed")
        bad = self.client.patch(f"{CONVS}{self.bob_conv.pk}/", {"title": "hax"}, format="json")
        self.assertEqual(bad.status_code, status.HTTP_404_NOT_FOUND)
        self.bob_conv.refresh_from_db()
        self.assertEqual(self.bob_conv.title, "bob-conv")  # untouched

    def test_delete_own_ok_others_404(self):
        self.client.force_authenticate(self.alice)
        self.assertEqual(
            self.client.delete(f"{CONVS}{self.bob_conv.pk}/").status_code, status.HTTP_404_NOT_FOUND
        )
        self.assertTrue(Conversation.objects.filter(pk=self.bob_conv.pk).exists())
        self.assertEqual(
            self.client.delete(f"{CONVS}{self.alice_conv.pk}/").status_code, status.HTTP_204_NO_CONTENT
        )
        self.assertFalse(Conversation.objects.filter(pk=self.alice_conv.pk).exists())


class ChatMessageEndpointsTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.alice = _user("alice")
        self.bob = _user("bob")
        self.alice_conv = Conversation.objects.create(user_id=self.alice, title="alice-conv")
        self.bob_conv = Conversation.objects.create(user_id=self.bob, title="bob-conv")

    def _msgs(self, conv):
        return f"{CONVS}{conv.pk}/messages/"

    def test_list_messages_in_own_conversation(self):
        Message.objects.create(user_id=self.alice, conversation_id=self.alice_conv)
        self.client.force_authenticate(self.alice)
        resp = self.client.get(self._msgs(self.alice_conv))
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIn("results", resp.data)
        self.assertEqual(resp.data["count"], 1)

    def test_list_messages_in_others_conversation_404(self):
        self.client.force_authenticate(self.alice)
        self.assertEqual(self.client.get(self._msgs(self.bob_conv)).status_code, status.HTTP_404_NOT_FOUND)

    def test_create_message_in_own_conversation(self):
        self.client.force_authenticate(self.alice)
        resp = self.client.post(self._msgs(self.alice_conv), {}, format="json")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        msg = Message.objects.get(conversation_id=self.alice_conv)
        self.assertEqual(msg.user_id_id, self.alice.pk)
        self.assertEqual(msg.status, "complete")  # default lifecycle state

    def test_create_message_in_others_conversation_denied(self):
        self.client.force_authenticate(self.alice)
        resp = self.client.post(self._msgs(self.bob_conv), {}, format="json")
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)
        self.assertFalse(Message.objects.filter(conversation_id=self.bob_conv).exists())
