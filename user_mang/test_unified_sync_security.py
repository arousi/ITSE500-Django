"""Regression tests for the IDOR fixes in UnifiedSyncView.

Covers MODERNIZATION_PLAN.md findings #15 and #16:
  * unauthenticated `allow_public_uuid` GET must no longer read another user's data
  * an authenticated user must not be able to overwrite / reparent another user's
    conversation through the POST upsert (ownership is enforced per item)

These run against the real endpoint (`reverse('user-detail')` -> /api/v1/user_mang/me/);
they intentionally do NOT touch the stale test_views_comprehensive.py suite (which
predates the UnifiedSyncView refactor and needs its own rewrite).
"""
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from user_mang.models.custom_user import Custom_User
from chat_api.models.conversation import Conversation


class UnifiedSyncIDORTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse("user-detail")  # /api/v1/user_mang/me/
        self.victim = Custom_User.objects.create(
            username="victim", email="victim@example.com", is_active=True, email_verified=True,
        )
        self.attacker = Custom_User.objects.create(
            username="attacker", email="attacker@example.com", is_active=True, email_verified=True,
        )
        self.victim_conv = Conversation.objects.create(user_id=self.victim, title="victim-secret")

    # --- IDOR #15: unauthenticated cross-user read ---
    def test_unauthenticated_public_uuid_read_is_rejected(self):
        resp = self.client.get(
            self.url, {"user_id": str(self.victim.pk), "allow_public_uuid": "true"}
        )
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)
        # victim's data must not leak in the body
        self.assertNotIn("victim-secret", str(resp.data))
        self.assertNotIn("victim@example.com", str(resp.data))

    def test_authenticated_user_cannot_read_other_via_public_uuid(self):
        self.client.force_authenticate(user=self.attacker)
        resp = self.client.get(
            self.url, {"user_id": str(self.victim.pk), "allow_public_uuid": "true"}
        )
        # authenticated path resolves request.user only; victim's data must never appear
        self.assertNotIn("victim-secret", str(resp.data))
        self.assertNotIn("victim@example.com", str(resp.data))

    # --- IDOR #16: cross-user overwrite via POST upsert ---
    def test_cross_user_conversation_upsert_is_rejected(self):
        self.client.force_authenticate(user=self.attacker)
        resp = self.client.post(
            self.url,
            {"conversations": [{"conversation_id": str(self.victim_conv.pk), "title": "hijacked"}]},
            format="json",
        )
        # the victim's conversation must be neither reparented nor overwritten
        self.victim_conv.refresh_from_db()
        self.assertEqual(self.victim_conv.user_id_id, self.victim.pk, "conversation was reparented!")
        self.assertEqual(self.victim_conv.title, "victim-secret", "conversation was overwritten!")
        # and the response reports the item as rejected
        self.assertIn("not owned", str(resp.data).lower())

    def test_new_message_status_defaults_to_complete(self):
        # Message.status was added for the async-LLM lifecycle; default keeps prior behavior.
        from chat_api.models.message import Message
        msg = Message.objects.create(user_id=self.victim, conversation_id=self.victim_conv)
        self.assertEqual(msg.status, "complete")

    def test_owner_can_update_own_conversation(self):
        # control: the legitimate self-update path must still work
        self.client.force_authenticate(user=self.victim)
        resp = self.client.post(
            self.url,
            {"conversations": [{"conversation_id": str(self.victim_conv.pk), "title": "renamed"}]},
            format="json",
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.victim_conv.refresh_from_db()
        self.assertEqual(self.victim_conv.title, "renamed")
