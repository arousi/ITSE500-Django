"""chat_api views: endpoints and scaffolding for chat/conversation features.

English
- Purpose: Provide REST views for conversations, messages, attachments, and sync helpers.
- Notes: This module primarily defines APIView classes in other files; here we keep
	logging setup and architectural notes for syncing across devices.

العربية
- الهدف: واجهات REST لإدارة المحادثات والرسائل والمرفقات والمزامنة بين الأجهزة.
- ملاحظة: هذا الملف يحتوي أساسًا على تهيئة السجل وملاحظات تصميم.
"""

from django.shortcuts import render, get_object_or_404

import hashlib
import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from .models import Conversation
from .models import Message
from .models.attachment import Attachment
from rest_framework import viewsets, permissions
from .models.message_request import MessageRequest
from .models.message_response import MessageResponse
from .models.message_output import MessageOutput
from .serializers import (
    ConversationSerializer,
    MessageSerializer,
    MessageWriteSerializer,
    AttachmentUploadSerializer,
)
from .services.llm import dispatch_inference
from django.db import transaction
from django.utils import timezone

# Configure logger for this module
logger = logging.getLogger(__name__)

# Create your views here (see app-specific submodules where applicable).

# Design note:
# How do we connect a visitor across two devices to sync conversations/messages?
# Answer: assign each visitor a stable UUID on first contact; the Flutter app can
# provide this UUID to the React app to fetch/sync data without exposing PII.


class ConversationListCreateView(ListCreateAPIView):
    """List the caller's own conversations, or create a new one owned by the caller."""

    permission_classes = [IsAuthenticated]
    serializer_class = ConversationSerializer

    def get_queryset(self):
        return Conversation.objects.filter(user_id=self.request.user).order_by('-updated_at')

    def perform_create(self, serializer):
        conversation = serializer.save(user_id=self.request.user)
        logger.info(
            "conversation.created",
            extra={"user_id": str(self.request.user.pk), "conversation_id": str(conversation.pk)},
        )


class ConversationDetailView(RetrieveUpdateDestroyAPIView):
    """Retrieve/update/delete a conversation owned by the caller.

    Uses a user-scoped queryset so another user's conversation resolves to 404
    (never 403) -- this avoids leaking whether the resource exists at all.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = ConversationSerializer
    lookup_field = 'conversation_id'
    lookup_url_kwarg = 'conversation_id'

    def get_queryset(self):
        return Conversation.objects.filter(user_id=self.request.user)

    def perform_update(self, serializer):
        conversation = serializer.save()
        logger.info(
            "conversation.updated",
            extra={"user_id": str(self.request.user.pk), "conversation_id": str(conversation.pk)},
        )

    def perform_destroy(self, instance):
        conversation_id = str(instance.pk)
        instance.delete()
        logger.info(
            "conversation.deleted",
            extra={"user_id": str(self.request.user.pk), "conversation_id": conversation_id},
        )


class MessageListCreateView(ListCreateAPIView):
    """List or create messages within a conversation owned by the caller.

    The parent conversation is resolved with a user-scoped lookup, so a missing
    OR non-owned conversation both yield 404 (covers the cross-user case without
    revealing existence of another user's conversation).
    """

    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return MessageWriteSerializer
        return MessageSerializer

    def _get_conversation(self):
        return get_object_or_404(
            Conversation,
            conversation_id=self.kwargs['conversation_id'],
            user_id=self.request.user,
        )

    def get_queryset(self):
        conversation = self._get_conversation()
        return Message.objects.filter(conversation_id=conversation).order_by('timestamp')

    # Fields recognized on the nested `request` object when a client asks us to
    # run LLM inference (as opposed to a plain synced-message create).
    _REQUEST_FIELDS = [
        "request_model",
        "request_input",
        "request_system_role",
        "request_system_content",
        "request_system_prompt",
        "request_user_structured_output",
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

    def create(self, request, *args, **kwargs):
        """Create a message, optionally kicking off async LLM inference.

        - If the body contains a `request` object, build a MessageRequest from
          its recognized fields, create the Message with status="pending", and
          dispatch inference (async via Celery when available, inline
          otherwise). The (re-loaded) message is returned with a 201.
        - Otherwise, preserve the existing plain-create behavior unchanged
          (status defaults to "complete", no inference triggered).
        """
        request_payload = request.data.get("request") if hasattr(request.data, "get") else None

        if request_payload:
            conversation = self._get_conversation()
            request_kwargs = {
                key: request_payload[key]
                for key in self._REQUEST_FIELDS
                if key in request_payload
            }
            message_request = MessageRequest.objects.create(**request_kwargs)
            message = Message.objects.create(
                conversation_id=conversation,
                user_id=request.user,
                request_id=message_request,
                status="pending",
            )
            logger.info(
                "message.created",
                extra={
                    "user_id": str(request.user.pk),
                    "conversation_id": str(conversation.pk),
                    "message_id": str(message.pk),
                },
            )

            dispatch_inference(message.pk)

            message.refresh_from_db()
            serializer = MessageSerializer(message, context=self.get_serializer_context())
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

        return super().create(request, *args, **kwargs)

    def perform_create(self, serializer):
        conversation = self._get_conversation()
        message = serializer.save(conversation_id=conversation, user_id=self.request.user)
        logger.info(
            "message.created",
            extra={
                "user_id": str(self.request.user.pk),
                "conversation_id": str(conversation.pk),
                "message_id": str(message.pk),
            },
        )


# Max accepted upload size for message attachments (25 MB).
MAX_ATTACHMENT_UPLOAD_BYTES = 25 * 1024 * 1024


class AttachmentListCreateView(ListCreateAPIView):
    """List or upload attachments belonging to a message owned by the caller.

    The parent message is resolved with a user-scoped lookup (through its
    conversation's owner), so a missing OR non-owned message/conversation both
    yield 404 -- never leaking existence of another user's data.

    Uses a dedicated `AttachmentUploadSerializer` for this endpoint only; the
    `user_mang.serializers.AttachmentSerializer` used by `UnifiedSyncView` is
    untouched.
    """

    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]
    serializer_class = AttachmentUploadSerializer

    def _get_message(self):
        return get_object_or_404(
            Message,
            message_id=self.kwargs['message_id'],
            conversation_id__conversation_id=self.kwargs['conversation_id'],
            conversation_id__user_id=self.request.user,
        )

    def get_queryset(self):
        message = self._get_message()
        return Attachment.objects.filter(message_id=message).order_by('created_at')

    def create(self, request, *args, **kwargs):
        message = self._get_message()

        uploaded_file = request.data.get('encrypted_blob')
        if uploaded_file is not None and hasattr(uploaded_file, 'size'):
            if uploaded_file.size > MAX_ATTACHMENT_UPLOAD_BYTES:
                return Response(
                    {"encrypted_blob": ["Upload exceeds the 25 MB size limit."]},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        size_bytes = None
        sha256_hex = None
        if uploaded_file is not None:
            hasher = hashlib.sha256()
            for chunk in uploaded_file.chunks():
                hasher.update(chunk)
            sha256_hex = hasher.hexdigest()
            size_bytes = uploaded_file.size
            # Rewind so the FileField save below doesn't persist an empty blob.
            uploaded_file.seek(0)

        attachment = serializer.save(
            message_id=message,
            size_bytes=size_bytes,
            sha256=sha256_hex,
        )
        logger.info(
            "attachment.created",
            extra={
                "user_id": str(request.user.pk),
                "message_id": str(message.pk),
                "attachment_id": str(attachment.pk),
            },
        )
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)