"""chat_api serializers.

Reuse the already-tested Conversation/Message serializers from `user_mang.serializers`
(there is no circular import: user_mang.serializers imports chat_api MODELS, not views).

`MessageWriteSerializer` is a thin subclass used only for POST on the
conversation-scoped message-create endpoint: the parent conversation is resolved
from the URL by the view, so `conversation_id` (and `user_id`) must not be
required from the request body.
"""
from rest_framework import serializers

from user_mang.serializers import ConversationSerializer, MessageSerializer
from .models.attachment import Attachment

__all__ = [
    "ConversationSerializer",
    "MessageSerializer",
    "MessageWriteSerializer",
    "AttachmentUploadSerializer",
]


class MessageWriteSerializer(MessageSerializer):
    """Write-side Message serializer for the nested conversation messages endpoint.

    The conversation is supplied by the view (from the URL), not the client, so
    `conversation_id` is not required in the request body.
    """

    class Meta(MessageSerializer.Meta):
        pass

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["conversation_id"].required = False


class AttachmentUploadSerializer(serializers.ModelSerializer):
    """Write-side Attachment serializer for the message-scoped upload/list endpoint.

    Dedicated to this endpoint only -- does NOT replace or alias
    `user_mang.serializers.AttachmentSerializer`, which the UnifiedSyncView still
    uses unchanged. The parent message is supplied by the view (from the URL),
    and `size_bytes`/`sha256` are computed server-side from the uploaded bytes.
    """

    class Meta:
        model = Attachment
        fields = [
            "attachment_id",
            "message_id",
            "type",
            "mime_type",
            "encrypted_blob",
            "size_bytes",
            "sha256",
            "is_encrypted",
            "enc_algo",
            "iv_base64",
            "key_ref",
            "created_at",
        ]
        read_only_fields = [
            "attachment_id",
            "message_id",
            "size_bytes",
            "sha256",
            "created_at",
        ]

    def validate_type(self, value: str):
        allowed = {"image", "embedding", "pdf", "other"}
        if value and value not in allowed:
            raise serializers.ValidationError(f"type must be one of {sorted(allowed)}")
        return value
