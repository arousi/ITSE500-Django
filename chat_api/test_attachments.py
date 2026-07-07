"""TDD behavior tests for chat_api attachment upload/list (message-scoped).

Contract for this /expand increment:
  * auth required
  * ownership through conversation -> message (another user's message -> 404, no leak)
  * upload stores the file and the server computes size_bytes + sha256
  * type is validated (image|embedding|pdf|other)
  * list is paginated

Uses a temp MEDIA_ROOT so uploads don't litter the repo. Storage is the filesystem
fallback here; in production the same code path writes to MinIO via django-storages.
Written RED first (endpoints don't exist yet).
"""
import hashlib
import tempfile

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from rest_framework import status
from rest_framework.test import APIClient

from user_mang.models.custom_user import Custom_User
from chat_api.models.conversation import Conversation
from chat_api.models.message import Message
from chat_api.models.attachment import Attachment


def _user(name="alice"):
    return Custom_User.objects.create(
        username=name, email=f"{name}@example.com", is_active=True, email_verified=True
    )


def _file(content=b"hello-bytes", name="a.bin"):
    return SimpleUploadedFile(name, content, content_type="application/octet-stream")


@override_settings(MEDIA_ROOT=tempfile.mkdtemp())
class AttachmentEndpointTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.alice = _user("alice")
        self.bob = _user("bob")
        self.alice_conv = Conversation.objects.create(user_id=self.alice, title="a")
        self.bob_conv = Conversation.objects.create(user_id=self.bob, title="b")
        self.alice_msg = Message.objects.create(user_id=self.alice, conversation_id=self.alice_conv)
        self.bob_msg = Message.objects.create(user_id=self.bob, conversation_id=self.bob_conv)

    def _url(self, conv, msg):
        return f"/api/v1/chat_api/conversations/{conv.pk}/messages/{msg.pk}/attachments/"

    def test_upload_requires_auth(self):
        resp = self.client.post(
            self._url(self.alice_conv, self.alice_msg),
            {"encrypted_blob": _file(), "type": "other"}, format="multipart",
        )
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_upload_to_own_message_computes_size_and_sha256(self):
        self.client.force_authenticate(self.alice)
        content = b"hello-bytes-12345"
        resp = self.client.post(
            self._url(self.alice_conv, self.alice_msg),
            {"encrypted_blob": _file(content), "type": "other"}, format="multipart",
        )
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        att = Attachment.objects.get(message_id=self.alice_msg)
        self.assertEqual(att.size_bytes, len(content))
        self.assertEqual(att.sha256, hashlib.sha256(content).hexdigest())

    def test_upload_to_others_message_denied(self):
        self.client.force_authenticate(self.alice)
        resp = self.client.post(
            self._url(self.bob_conv, self.bob_msg),
            {"encrypted_blob": _file(), "type": "other"}, format="multipart",
        )
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)
        self.assertFalse(Attachment.objects.filter(message_id=self.bob_msg).exists())

    def test_upload_rejects_invalid_type(self):
        self.client.force_authenticate(self.alice)
        resp = self.client.post(
            self._url(self.alice_conv, self.alice_msg),
            {"encrypted_blob": _file(), "type": "virus"}, format="multipart",
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_list_attachments_for_own_message_paginated(self):
        Attachment.objects.create(message_id=self.alice_msg, type="other")
        self.client.force_authenticate(self.alice)
        resp = self.client.get(self._url(self.alice_conv, self.alice_msg))
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIn("results", resp.data)
        self.assertEqual(resp.data["count"], 1)

    def test_list_attachments_others_message_404(self):
        self.client.force_authenticate(self.alice)
        resp = self.client.get(self._url(self.bob_conv, self.bob_msg))
        self.assertEqual(resp.status_code, status.HTTP_404_NOT_FOUND)
