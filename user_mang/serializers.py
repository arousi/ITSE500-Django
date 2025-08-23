# serializers.py
from rest_framework import serializers

from chat_api.models.conversation import Conversation
from chat_api.models.message import Message
from chat_api.models.message_request import MessageRequest
from chat_api.models.message_response import MessageResponse
from chat_api.models.message_output import MessageOutput
from chat_api.models.attachment import Attachment


# -------------------------
# Core leaf serializers
# -------------------------

class MessageRequestSerializer(serializers.ModelSerializer):
    """
    Serialize a single model generation *request* (the user's prompt/config).
    Primary key: `request_id` (UUID).
    Used both to return request details (GET) and to upsert them (POST).
    """

    class Meta:
        model = MessageRequest
        fields = [
            "request_id",
            "request_model",
            "request_input",
            "request_system_role",
            "request_system_content",
            "request_system_prompt",
            "request_use_structured_output",
            "request_structured_schema",
            "request_user_role",
            "request_user_content",
            "request_min_p",
            "request_temperature",
            "request_top_p",
            "request_n",
            "request_top_k",
            "request_stream",
            "request_stop",
            "request_max_tokens",
            "repeat_penalty",
        ]


class MessageResponseSerializer(serializers.ModelSerializer):
    """
    Serialize a provider/model *response* aggregate (metadata + usage + settings).
    Primary key: `response_id` (string).
    """

    class Meta:
        model = MessageResponse
        fields = [
            "response_id",
            "object",
            "created_at",
            "status",
            "error",
            "model_name",
            "parallel_tool_calls",
            "previous_response_id",
            "instructions",
            "reasoning_effort",
            "reasoning_summary",
            "store",
            "temperature",
            "text_format_type",
            "tool_choice",
            "tools",
            "top_p",
            "truncation",
            "usage_input_tokens",
            "usage_output_tokens",
            "usage_total_tokens",
            "user",
            "metadata",
            "incomplete_details",
            "max_output_tokens",
        ]


class MessageOutputSerializer(serializers.ModelSerializer):
    """
    Serialize a normalized *output item* of a response (e.g., final message text).
    Note: model has an implicit AutoField `id`. `output_id` is a provider-side identifier.
    """

    class Meta:
        model = MessageOutput
        fields = [
            "id",                       # DB PK (implicit)
            "output_type",
            "output_id",                # provider/reference id (string)
            "output_status",
            "output_role",
            "output_content_type",
            "output_content_text",
            "output_content_annotations",
        ]


class AttachmentSerializer(serializers.ModelSerializer):
    """
    Serialize an artifact attached to a message (image/pdf/embedding/etc.).
    - `encrypted_blob` and image/file URLs are returned as absolute URLs.
    - Validates `type` against a small allowed set for consistency.
    """

    # Present related FKs as primary keys; write requires valid PKs
    user_id = serializers.PrimaryKeyRelatedField(read_only=True)
    conversation_id = serializers.PrimaryKeyRelatedField(queryset=Conversation.objects.all())
    message_id = serializers.PrimaryKeyRelatedField(queryset=Message.objects.all())

    # File fields -> URLs in output
    encrypted_blob = serializers.FileField(use_url=True, required=False, allow_null=True)

    class Meta:
        model = Attachment
        fields = [
            "attachment_id",
            "user_id",
            "conversation_id",
            "message_id",
            "type",
            "mime_type",
            "file_path",
            "encrypted_blob",
            "size_bytes",
            "width",
            "height",
            "sha256",
            "is_encrypted",
            "enc_algo",
            "iv_base64",
            "key_ref",
            "created_at",
        ]
        read_only_fields = ["attachment_id", "created_at"]

    def validate_type(self, value: str):
        allowed = {"image", "embedding", "pdf", "other"}
        if value and value not in allowed:
            raise serializers.ValidationError(f"type must be one of {sorted(allowed)}")
        return value


# -------------------------
# Message & Conversation
# -------------------------

class MessageSerializer(serializers.ModelSerializer):
    """
    Serialize a chat message.
    - Write: accept PKs for `request_id`, `response_id`, `output_id`, `conversation_id`.
    - Read: also include nested `request`, `response`, `output` for convenience.
    - File fields (`img_Url`, `doc_url`) are rendered as URLs.
    """

    # FK/1-1 fields for writing (accept PKs) ...
    conversation_id = serializers.PrimaryKeyRelatedField(queryset=Conversation.objects.all())
    request_id = serializers.PrimaryKeyRelatedField(
        queryset=MessageRequest.objects.all(), required=False, allow_null=True
    )
    response_id = serializers.PrimaryKeyRelatedField(
        queryset=MessageResponse.objects.all(), required=False, allow_null=True
    )
    output_id = serializers.PrimaryKeyRelatedField(
        queryset=MessageOutput.objects.all(), required=False, allow_null=True
    )

    # ... and nested read-only views
    request = MessageRequestSerializer(source="request_id", read_only=True)
    response = MessageResponseSerializer(source="response_id", read_only=True)
    output = MessageOutputSerializer(source="output_id", read_only=True)

    # Files as URLs when present
    img_Url = serializers.ImageField(use_url=True, required=False, allow_null=True)
    doc_url = serializers.FileField(use_url=True, required=False, allow_null=True)

    class Meta:
        model = Message
        fields = [
            "message_id",
            "user_id",               # set by view; keep read-only to avoid client spoofing
            "conversation_id",
            "request_id",
            "response_id",
            "output_id",
            "timestamp",
            "vote",
            "has_image",
            "img_Url",
            "metadata",
            "has_embedding",
            "has_document",
            "doc_url",
            # nested read-only projections
            "request",
            "response",
            "output",
        ]
        read_only_fields = ["message_id", "timestamp", "user_id"]


class ConversationSerializer(serializers.ModelSerializer):
    """
    Serialize a conversation with nested messages (read-only).
    For writes, clients send a flat conversation object; messages are synced separately.
    """

    user_id = serializers.PrimaryKeyRelatedField(read_only=True)
    messages = MessageSerializer(many=True, read_only=True)

    class Meta:
        model = Conversation
        fields = [
            "conversation_id",
            "user_id",
            "title",
            "created_at",
            "updated_at",
            "local_only",
            "messages",
        ]
        read_only_fields = ["conversation_id", "created_at", "updated_at", "user_id"]
