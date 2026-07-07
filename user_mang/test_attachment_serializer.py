"""Regression tests for AttachmentSerializer field/model mismatch.

Bug: AttachmentSerializer declared `user_id = PrimaryKeyRelatedField(read_only=True)`
and `conversation_id = PrimaryKeyRelatedField(queryset=Conversation.objects.all())`,
but the Attachment model has NEITHER field -- it only has `message_id` (FK -> Message).
Serializing an Attachment therefore raised AttributeError (-> 500 in prod), and the
write path could never populate a `conversation_id` the model doesn't have.

Fix: `user_id` and `conversation_id` are derived read-only SerializerMethodFields
sourced from the related Message, and are never passed to the model on save.
"""
from django.test import TestCase

from user_mang.models.custom_user import Custom_User
from user_mang.serializers import AttachmentSerializer
from chat_api.models.conversation import Conversation
from chat_api.models.message import Message
from chat_api.models.attachment import Attachment


class AttachmentSerializerFieldMismatchTest(TestCase):
    def setUp(self):
        self.user = Custom_User.objects.create(
            username="alice", email="alice@example.com", is_active=True, email_verified=True,
        )
        self.conversation = Conversation.objects.create(user_id=self.user, title="convo")
        self.message = Message.objects.create(user_id=self.user, conversation_id=self.conversation)
        self.attachment = Attachment.objects.create(message_id=self.message, type="other")

    def test_serializing_attachment_does_not_raise_and_derives_user_and_conversation(self):
        # Previously raised AttributeError: 'Attachment' object has no attribute 'user_id'
        # (and no 'conversation_id') because the model has neither field.
        data = AttachmentSerializer(self.attachment).data
        self.assertEqual(str(data["user_id"]), str(self.user.pk))
        self.assertEqual(str(data["conversation_id"]), str(self.conversation.pk))
        self.assertEqual(str(data["message_id"]), str(self.message.pk))

    def test_user_id_and_conversation_id_are_read_only_and_not_written_to_model(self):
        # Even if a client sends user_id/conversation_id, they must be ignored on write
        # -- the model has no such fields and passing them to .save() would raise.
        other_conv = Conversation.objects.create(user_id=self.user, title="other")
        serializer = AttachmentSerializer(
            self.attachment,
            data={
                "user_id": str(self.user.pk),
                "conversation_id": str(other_conv.pk),
                "type": "image",
            },
            partial=True,
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        instance = serializer.save()
        self.assertEqual(instance.type, "image")
        # conversation_id was never a real field on Attachment; it must still be
        # derivable from the (unchanged) message relationship.
        self.assertEqual(instance.message_id_id, self.message.pk)

    def test_derived_fields_are_null_safe_when_message_missing_relations(self):
        # Guard path: message with no crash even though user_id/conversation_id are
        # required on Message in practice; this asserts the getattr-guard doesn't blow up.
        data = AttachmentSerializer(self.attachment).data
        self.assertIsNotNone(data["user_id"])
        self.assertIsNotNone(data["conversation_id"])
