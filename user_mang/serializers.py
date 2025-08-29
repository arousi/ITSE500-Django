from rest_framework import serializers

from chat_api.models.conversation import Conversation
from chat_api.models.message import Message
from chat_api.models.message_request import MessageRequest
from chat_api.models.message_response import MessageResponse
from chat_api.models.message_output import MessageOutput
from chat_api.models.attachment import Attachment

from user_mang.models.custom_user import Custom_User


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

    # Expose user as read-only PK if present
    user = serializers.PrimaryKeyRelatedField(read_only=True)

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
    - Accepts 'id' in payload as an alias to attachment_id to match the UnifiedSyncView.
    - user_id is read-only and the view should call serializer.save(user=user) on create.
    """

    # Allow clients to send "id" mapping to attachment_id (convenience)
    id = serializers.CharField(source="attachment_id", required=False)
    user_id = serializers.PrimaryKeyRelatedField(read_only=True)
    conversation_id = serializers.PrimaryKeyRelatedField(queryset=Conversation.objects.all())
    message_id = serializers.PrimaryKeyRelatedField(queryset=Message.objects.all())

    encrypted_blob = serializers.FileField(use_url=True, required=False, allow_null=True)

    class Meta:
        model = Attachment
        fields = [
            "id",  # alias -> attachment_id
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
        # allow attachment_id to be set when creating (client-provided id) so not read-only
        read_only_fields = ["created_at"]

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

    request = MessageRequestSerializer(source="request_id", read_only=True)
    response = MessageResponseSerializer(source="response_id", read_only=True)
    output = MessageOutputSerializer(source="output_id", read_only=True)

    img_Url = serializers.ImageField(use_url=True, required=False, allow_null=True)
    doc_url = serializers.FileField(use_url=True, required=False, allow_null=True)

    class Meta:
        model = Message
        fields = [
            "message_id",        # allow client to provide message_id for upsert
            "user_id",           # set by view; kept read-only to avoid spoofing
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
            "request",
            "response",
            "output",
        ]
        # allow message_id to be provided by client (used as external pk for upsert)
        read_only_fields = ["timestamp", "user_id"]


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
            "conversation_id",   # allow client to provide conversation_id for upsert/create
            "user_id",
            "title",
            "created_at",
            "updated_at",
            "local_only",
            "messages",
        ]
        # keep created/updated/user read-only but allow providing conversation_id for upsert
        read_only_fields = ["created_at", "updated_at", "user_id"]


class ProfileSerializer(serializers.ModelSerializer):
    """
    Safe profile serializer for client-driven profile updates.
    Whitelisted writable fields: username, email, phone_number, biometric_enabled.
    Sensitive fields (email_verified, is_staff, is_superuser, user_password, related_devices, etc.)
    are intentionally excluded.
    """
    user_id = serializers.UUIDField(read_only=True)

    class Meta:
        model = Custom_User
        fields = ("user_id", "username", "email", "phone_number", "biometric_enabled")
        read_only_fields = ("user_id",)

    def validate_email(self, value: str):
        if not value:
            return value
        qs = Custom_User.objects.filter(email__iexact=value)
        if self.instance is not None:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise serializers.ValidationError("This email is already in use.")
        return value

    def validate_username(self, value: str):
        if not value:
            return value
        qs = Custom_User.objects.filter(username__iexact=value)
        if self.instance is not None:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise serializers.ValidationError("This username is already in use.")
        return value

    def update(self, instance: Custom_User, validated_data: dict):
        # Apply only whitelisted fields and persist with optimized update_fields
        allowed = ["username", "email", "phone_number", "biometric_enabled"]
        update_fields = []
        for key in allowed:
            if key in validated_data:
                setattr(instance, key, validated_data[key])
                update_fields.append(key)
        if update_fields:
            try:
                instance.save(update_fields=update_fields)
            except Exception:
                instance.save()
        return instance


class FullProfileSerializer(serializers.ModelSerializer):
    """
    Full profile serializer that exposes most editable user fields.
    This allows the UnifiedSyncView to upsert the complete user object.
    Sensitive fields like `is_superuser`, `groups`, and `user_permissions` are intentionally omitted.
    """
    user_id = serializers.UUIDField(read_only=True)
    user_password = serializers.CharField(write_only=True, required=False, allow_blank=True)

    class Meta:
        model = Custom_User
        fields = [
            "user_id",
            "username",
            # use AbstractUser's names
            "first_name",
            "last_name",
            "email",
            "user_password",
            "phone_number",
            "last_modified",
            "devices_id",
            "temp_id",
            "related_devices",
            "email_pin_created",
            "email_verified",
            "is_archived",
            "is_google_user",
            "is_openrouter_user",
            "is_microsoft_user",
            "is_github_user",
            "is_active",
            "is_staff",
        ]
        read_only_fields = ["user_id", "last_modified"]

    def validate(self, attrs):
        """
        Allow missing/blank passwords for OAuth accounts and visitors.
        Enforce password presence/length only for non-OAuth, non-visitor accounts
        when email_verified is True or a password is explicitly provided.
        """
        # Extract incoming password if present (may be blank string)
        pwd = attrs.get("user_password", None)

        # Determine target flags: prefer incoming attrs then existing instance
        is_visitor = attrs.get("is_visitor") if "is_visitor" in attrs else getattr(self.instance, "is_visitor", False)
        is_oauth = any(
            attrs.get(flag) if flag in attrs else getattr(self.instance, flag, False)
            for flag in ("is_google_user", "is_openrouter_user", "is_microsoft_user", "is_github_user")
        )

        email_verified = attrs.get("email_verified") if "email_verified" in attrs else getattr(self.instance, "email_verified", False)

        # Normalize blank password -> None for decision logic
        if isinstance(pwd, str) and pwd.strip() == "":
            pwd = None
            # remove from attrs so update() won't attempt to hash an empty string
            if "user_password" in attrs:
                attrs.pop("user_password")

        # If account is not oauth and not visitor and email_verified, require a password
        if not is_visitor and not is_oauth and email_verified:
            if pwd is None and self.instance is None:
                raise serializers.ValidationError({"user_password": "Password is required for verified accounts."})
            if pwd is not None and len(str(pwd)) < 6:
                raise serializers.ValidationError({"user_password": "Password must be at least 6 characters long."})

        # If password is provided for non-oauth accounts, enforce min length
        if pwd is not None and not (is_visitor or is_oauth):
            if len(str(pwd)) < 6:
                raise serializers.ValidationError({"user_password": "Password must be at least 6 characters long."})

        return attrs

    def validate_email(self, value: str):
        if not value:
            return value
        qs = Custom_User.objects.filter(email__iexact=value)
        if self.instance is not None:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise serializers.ValidationError("This email is already in use.")
        return value

    def validate_username(self, value: str):
        if not value:
            return value
        qs = Custom_User.objects.filter(username__iexact=value)
        if self.instance is not None:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise serializers.ValidationError("This username is already in use.")
        return value

    def update(self, instance: Custom_User, validated_data: dict):  
        # Handle password hashing explicitly
        pwd = validated_data.pop("user_password", None)
        update_fields = []
        if pwd is not None:
            # Hash using same backend salt as CustomUserManager
            import hashlib
            from django.conf import settings as _settings

            backend_salt = getattr(_settings, "BACKEND_PASSWORD_SALT", "fallback_dev_salt")
            salted = (str(pwd) + backend_salt).encode("utf-8")
            instance.user_password = hashlib.sha256(salted).hexdigest()
            update_fields.append("user_password")

        # Assign other allowed fields
        allowed = [
            "username",
            "email",
            "phone_number",
            "biometric_enabled",
            # name fields from AbstractUser
            "first_name",
            "last_name",
            "devices_id",
            "temp_id",
            "related_devices",
            "email_pin",
            "email_pin_created",
            "email_verified",
            "is_archived",
            "login_otp",
            "login_otp_created",
            "login_otp_sent_count",
            "login_otp_last_sent",
            "is_google_user",
            "is_openrouter_user",
            "is_microsoft_user",
            "is_github_user",
            "is_active",
            "is_staff",
        ]

        for key in allowed:
            if key in validated_data:
                setattr(instance, key, validated_data[key])
                update_fields.append(key)

        # Save with update_fields when possible
        if update_fields:
            try:
                instance.save(update_fields=update_fields)
            except Exception:
                instance.save()
        return instance


class FullChatSerializer(serializers.Serializer):
        """
        Composite serializer that returns the complete chat payload for a user.
        Fields:
            - conversations: ConversationSerializer (with nested messages)
            - messages: MessageSerializer (flat list)
            - message_request: MessageRequestSerializer
            - message_response: MessageResponseSerializer
            - message_output: MessageOutputSerializer
            - attachments: AttachmentSerializer

        This serializer is intentionally a non-model `Serializer` since it aggregates
        multiple querysets and models into a single response shape used by
        `UnifiedSyncView.get`.
        """

        conversations = ConversationSerializer(many=True, read_only=True)
        messages = MessageSerializer(many=True, read_only=True)
        message_request = MessageRequestSerializer(many=True, read_only=True)
        message_response = MessageResponseSerializer(many=True, read_only=True)
        message_output = MessageOutputSerializer(many=True, read_only=True)
        attachments = AttachmentSerializer(many=True, read_only=True)

        def to_representation(self, instance):
                """Accept a dict-like instance with keys matching the field names.

                Expected input format (from the view) is a dict:
                        {
                            "conversations": <qs>,
                            "messages": <qs>,
                            "message_request": <qs>,
                            "message_response": <qs>,
                            "message_output": <qs>,
                            "attachments": <qs>,
                        }
                """
                if isinstance(instance, dict):
                        ret = {}
                        for field_name, field in self.fields.items():
                                value = instance.get(field_name) if isinstance(instance, dict) else None
                                # If a queryset or list-like is provided, let the child serializer handle it
                                ret[field_name] = field.to_representation(value) if value is not None else []
                        return ret
                return super().to_representation(instance)