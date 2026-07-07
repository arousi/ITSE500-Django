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
from unittest.mock import patch

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

    def test_upload_rejects_oversized_file(self):
        """A file whose .size exceeds the cap is rejected with 400 and no
        Attachment row is created. Rather than allocating a real 25MB payload,
        the cap itself is patched down to a few bytes so a small file exceeds
        it -- the request's actual parsed .size can't be spoofed client-side,
        since Django recomputes it server-side from the real upload bytes."""
        self.client.force_authenticate(self.alice)
        with patch("chat_api.views.MAX_ATTACHMENT_UPLOAD_BYTES", 4):
            resp = self.client.post(
                self._url(self.alice_conv, self.alice_msg),
                {"encrypted_blob": _file(b"this-is-more-than-4-bytes"), "type": "other"}, format="multipart",
            )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(Attachment.objects.filter(message_id=self.alice_msg).exists())

    def test_upload_without_file_rejected(self):
        """encrypted_blob is required for this upload endpoint -- an upload
        with no file at all must be rejected (400), not silently create a
        file-less Attachment row."""
        self.client.force_authenticate(self.alice)
        resp = self.client.post(
            self._url(self.alice_conv, self.alice_msg),
            {"type": "other"}, format="multipart",
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(Attachment.objects.filter(message_id=self.alice_msg).exists())
