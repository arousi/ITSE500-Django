import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework_simplejwt.authentication import JWTAuthentication
from .models import Custom_User
from user_mang.serializers import (ConversationSerializer,                                    AttachmentSerializer,
                                    MessageSerializer,
                                    MessageRequestSerializer,
                                    MessageResponseSerializer,
                                    MessageOutputSerializer)
from chat_api.models.attachment import Attachment
from chat_api.models.message import Message
from chat_api.models.conversation import Conversation
from chat_api.models.message_request import MessageRequest
from chat_api.models.message_response import MessageResponse
from chat_api.models.message_output import MessageOutput
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import os
import shutil
import tempfile
import csv
import json
import logging
import zipfile
from user_mang.models.custom_user import Custom_User
from django.db import transaction
from django.utils import timezone
from django.core.mail import EmailMessage
from django.http import FileResponse
import logging
import json
from auth_api.models import ProviderOAuthToken  
import csv
import tempfile
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from datetime import datetime, timedelta
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from prompeteer_server.utils.emailer import send_verified_email

logger = logging.getLogger('user_mang')

def resolve_flags(request):
    """Utility to resolve profile/chat flags from query or body."""
    profile_flag = (
        request.query_params.get("profile") == "true"
        or request.data.get("profile") is True
    )
    chat_flag = (
        request.query_params.get("chat") == "true"
        or request.data.get("chat") is True
    )
    return profile_flag, chat_flag

#TODO: break into profile sync and chat sync seperate views
#* easier to understand and maintain

class UnifiedSyncView(APIView):
    # Accept JWT auth but allow explicit unauthenticated visitor flows controlled by resolve_user
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]
    """
    A secure, unified API endpoint for managing both chat data (conversations, messages, attachments, etc.)
    and user profile data for both visitors and registered users. Supports GET, POST, and DELETE methods,
    and can handle chat, profile, or both, based on query parameters or request body.

    Key Features:
    - Exports user data as an ephemeral CSV file and emails it only to verified emails (via Zeruh).
    - Soft deletes (sets is_deleted=True) instead of permanent deletes for all supported models.
    - Uses consistent serializer context and user_id handling.
    - Improved logging with stack traces for errors.
    - Uses a resolve_flags() utility for robust flag logic.
    - Coordinator view delegates to sub-views/functions for modularity.

    Query Parameters or JSON Body Flags:
        - profile: true/false (whether to include or operate on user profile data)
        - chat: true/false (whether to include or operate on chat data)

    If neither flag is provided, both chat and profile are handled by default.

    ------------------------------------------------------------------------
    Elements
    ------------------------------------------------------------------------
    - user_id: UUID of the user (visitor or registered)
    - is_new: Boolean, true if a new visitor was created
    - temp_id: Temporary ID for visitors (if applicable)
    - profile: User profile data (username, email, is_visitor, etc.)
    - conversations: List of user's conversations (with nested messages)
    - attachments: List of user's attachments (images, files, etc.)
    - summary: Summary of upsert operations (POST)
    - errors: Detailed errors for each upserted model (POST)
    - message: Status message (DELETE)
    - deleted/archived: Stats on deleted/archived objects (DELETE)

    Security:
    - Data exports are only sent to verified emails.
    - CSV exports are handled in ephemeral temp files and not stored permanently.
    - All deletions are soft deletes where possible.
    """


    def export_user_data_pdf(self, user):
        tmp = tempfile.NamedTemporaryFile(mode="w+b", suffix=".pdf", delete=False)
        c = canvas.Canvas(tmp.name, pagesize=letter)
        width, height = letter
        y = height - 40

        def draw_line(label, value):
            nonlocal y
            text = f"{label}: {value}"
            c.drawString(40, y, text)
            y -= 14
            if y < 60:
                c.showPage()
                y = height - 40

        c.setFont("Helvetica-Bold", 14)
        c.drawString(40, y, f"User export for {user.username} ({user.user_id})")
        y -= 24
        c.setFont("Helvetica", 10)

        draw_line("Exported at", timezone.now().isoformat())
        draw_line("Username", user.username)
        draw_line("Email", user.email)
        draw_line("Phone", getattr(user, "phone_number", ""))
        draw_line("Is visitor", user.is_visitor)
        draw_line("Is archived", getattr(user, "is_archived", False))
        y -= 8

        # Conversations header
        c.setFont("Helvetica-Bold", 12)
        c.drawString(40, y, "Conversations")
        y -= 18
        c.setFont("Helvetica", 9)
        for conv in Conversation.objects.filter(user_id=user).order_by("created_at"):
            draw_line("Conversation", f"{getattr(conv,'conversation_id', conv.pk)} - {conv.title}")
            # optionally list a few messages
            for msg in Message.objects.filter(conversation_id=conv).order_by("created_at")[:5]:
                draw_line("  Msg", (getattr(msg, "content", "") or "")[:120])
        c.save()
        tmp.seek(0)
        return tmp

    def _create_visitor(self, temp_id: str):
        user = Custom_User(
            username=f"visitor_{temp_id[:8]}",
            email=f"{temp_id}@visitor.local",
            is_visitor=True,
            temp_id=temp_id,
        )
        try:
            user.full_clean(exclude=["user_password"])
        except Exception:
            pass
        user.save()
        return user

    def _associate_device(self, user, device_id: str):
        try:
            devices = user.related_devices if isinstance(user.related_devices, list) else []
        except Exception:
            try:
                devices = json.loads(str(user.related_devices or "[]"))
            except Exception:
                devices = []
        if device_id not in devices:
            devices.append(device_id)
            try:
                user.related_devices = devices
            except Exception:
                user.related_devices = json.dumps(devices)
            user.device_id = device_id
            user.last_login = timezone.now()
            user.save()

    def resolve_user(self, request):
        """Resolve the user for this request.

        Behavior summary:
        - Authenticated requests operate on `request.user`. Any client-supplied `user_id` is ignored for write
            operations to prevent privilege escalation.
        - Unauthenticated requests may create or lookup a visitor by `temp_id`. When `device_id` is provided the
            visitor will be associated with that device.
        - A limited unauthenticated GET-by-UUID is allowed only when `allow_public_uuid=true` and the method is GET.

        Returns a 4-tuple: (user, is_new_visitor, error_response_or_none, temp_id_or_none)

        Notes:
        - Caller should short-circuit and return `error_response_or_none` when it is not None.
        - This helper enforces the current security model where writes require authentication or a valid `temp_id`.
        """
        user = None
        is_new_visitor = False
        temp_id = request.data.get("temp_id") or request.query_params.get("temp_id")
        device_id = request.data.get("device_id") or request.query_params.get("device_id")

        # Authenticated path: always operate on request.user
        if hasattr(request, "user") and getattr(request.user, "is_authenticated", False):
            user = request.user
            if not isinstance(user, Custom_User):
                try:
                    user = Custom_User.objects.filter(user_id=getattr(user, "user_id", None)).first() or user
                except Exception:
                    pass

            if temp_id and (not getattr(user, "temp_id", None) or user.temp_id != temp_id):
                user.temp_id = temp_id
                try:
                    user.save(update_fields=["temp_id"])
                except Exception:
                    user.save()

            if device_id:
                self._associate_device(user, device_id)

            return user, is_new_visitor, None, temp_id

        # Unauthenticated path: allow visitor creation/lookup via temp_id only
        if temp_id:
            user = Custom_User.objects.filter(temp_id=temp_id).first()
            if not user:
                user = self._create_visitor(temp_id)
                is_new_visitor = True
            if device_id:
                self._associate_device(user, device_id)
            return user, is_new_visitor, None, temp_id

        # Allow unauthenticated limited GET-by-UUID only when explicitly requested
        user_id = request.query_params.get("user_id") or request.data.get("user_id")
        allow_public_uuid = (
            request.query_params.get("allow_public_uuid") == "true"
            or request.data.get("allow_public_uuid") is True
        )
        if request.method == "GET" and allow_public_uuid and user_id:
            user = Custom_User.objects.filter(user_id=user_id).first()
            if not user:
                return None, False, Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND), None
            return user, False, None, None

        # Deny other unauthenticated access
        return None, False, Response({"error": "Authentication required"}, status=status.HTTP_401_UNAUTHORIZED), temp_id

    def export_user_data_csv(self, user):
        """
        Export user profile, conversations, and attachments to a CSV file.
        Returns the file path.
        """
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".csv", mode="w", newline='', encoding="utf-8")
        writer = csv.writer(tmp)
        # Profile
        writer.writerow(["Section", "Field", "Value"])
        writer.writerow(["Profile", "user_id", user.user_id])
        writer.writerow(["Profile", "username", user.username])
        writer.writerow(["Profile", "email", user.email])
        writer.writerow(["Profile", "is_visitor", user.is_visitor])
        writer.writerow(["Profile", "is_active", user.is_active])
        writer.writerow(["Profile", "is_archived", getattr(user, "is_archived", False)])
        # Conversations
        conversations = Conversation.objects.filter(user_id=user)
        writer.writerow([])
        writer.writerow(["Section", "conversation_id", "title"])
        for conv in conversations:
            writer.writerow(["Conversation", conv.conversation_id, conv.title])
    # Attachments
        attachments = Attachment.objects.filter(message_id__user_id=user)
        writer.writerow([])
        writer.writerow(["Section", "id", "type", "file_path"])
        for att in attachments:
            writer.writerow(["Attachment", att.attachment_id, att.type, att.file_path])
        tmp.close()
        return tmp.name

    def email_user_data_csv(self, user, csv_path):
        """
        Email the CSV export to the user's email address using Zeruh verification.
        Only sends to verified emails.
        """
        subject = "Your Data Export"
        message = "Attached is your requested data export. This file will be deleted in 30 days."
        send_verified_email(
            subject=subject,
            message=message,
            recipient_list=[user.email],
            from_email=None,
            html_message=None,
            verify_with_zeruh=True,
            zeruh_min_score=70,
            fail_silently=False,
            attachments=[(csv_path, "user_data_export.csv", "text/csv")]
        )

    def soft_delete_queryset(self, queryset):
        """Soft delete for queryset (set is_deleted=True if field exists)."""
        for obj in queryset:
            if hasattr(obj, "is_deleted"):
                obj.is_deleted = True
                obj.save(update_fields=["is_deleted"])
            else:
                obj.delete()

    def get(self, request):
        """GET

        Returns a nested payload containing `profile` and/or `chat` depending on flags.

        Response shape (high level):
            {
                "user_id": <uuid>,
                "is_new": <bool>,
                "temp_id": <str|null>,
                "profile": { ... } ,          # present when profile=true or by default
                "chat": {                     # present when chat=true or by default
                    "conversations": [...],
                    "messages": [...],
                    "message_request": [...],
                    "message_response": [...],
                    "message_output": [...],
                    "attachments": [...]
                }
            }

        Notes / implementation details:
        - Serializers: when available the view uses `FullProfileSerializer` and `FullChatSerializer` to produce the
          canonical output. If serializers fail the view falls back to minimal manual assembly.
        - Attachments returned in `chat.attachments` always include a `user_id` field (derived from the related
          message) to make ownership explicit for clients.

        Example Request:
            GET /api/v1/unified-sync/?user_id=123e4567-e89b-12d3-a456-426614174000&profile=true&chat=true

        Example Response (simplified):
            {
                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                "is_new": false,
                "temp_id": null,
                "profile": {
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "username": "john_doe",
                    "email": "john@example.com",
                    "is_visitor": false,
                    "is_active": true,
                    "is_archived": false
                },
                "chat": {
                    "conversations": [
                        {
                            "conversation_id": "c1",
                            "title": "My Conversation",
                            "messages": [ {"message_id": "m1", "content": "Hello!"} ]
                        }
                    ],
                    "messages": [ {"message_id": "m1", "content": "Hello!"} ],
                    "attachments": [
                        {
                            "id": 1,
                            "type": "image",
                            "file_path": "/media/attachments/1.png",
                            "user_id": "123e4567-e89b-12d3-a456-426614174000"
                        }
                    ]
                }
            }
        """
        user, is_new_visitor, error_response, temp_id = self.resolve_user(request)
        if error_response:
            return error_response

        # If unauthenticated visitor requested a token via temp_id, issue JWTs for sync
        try:
            is_auth = hasattr(request, "user") and getattr(request.user, "is_authenticated", False)
        except Exception:
            is_auth = False

        if (not is_auth) and temp_id and user is not None and getattr(user, "is_visitor", False):
            # Issue visitor sync tokens with shorter, configurable lifetimes
            refresh = RefreshToken.for_user(user)

            # Configurable lifetimes (seconds) via settings; defaults: 5m access, 1h refresh
            access_life = int(getattr(settings, "VISITOR_ACCESS_TOKEN_LIFETIME_SECONDS", 300))
            refresh_life = int(getattr(settings, "VISITOR_REFRESH_TOKEN_LIFETIME_SECONDS", 3600))

            now = datetime.utcnow()
            # Set custom expiration claims (epoch seconds)
            access_token = refresh.access_token
            access_token["exp"] = int((now + timedelta(seconds=access_life)).timestamp())
            refresh["exp"] = int((now + timedelta(seconds=refresh_life)).timestamp())

            access = str(access_token)
            refresh_token = str(refresh)
            return Response({
                "user_id": str(user.user_id),
                "is_new": is_new_visitor,
                "temp_id": temp_id,
                "tokens": {"access": access, "refresh": refresh_token}
            }, status=status.HTTP_200_OK)

        profile_flag, chat_flag = resolve_flags(request)

        response_data = {
            "user_id": str(user.user_id) if user and getattr(user, "user_id", None) is not None else None,
            "is_new": is_new_visitor,
            "temp_id": temp_id,
        }

        if profile_flag:
            # Use the FullProfileSerializer to return the complete profile when requested
            try:
                from user_mang.serializers import FullProfileSerializer

                profile_serializer = FullProfileSerializer(user, context={"request": request})
                response_data["profile"] = profile_serializer.data
            except Exception:
                # Fallback to minimal profile if serializer is not available or fails
                response_data["profile"] = {
                    "username": str(user.username) if user and getattr(user, "username", None) is not None else None,
                    "email": str(user.email) if user and getattr(user, "email", None) is not None else None,
                    "is_visitor": user.is_visitor if user and getattr(user, "is_visitor", None) is not None else None,
                    "is_active": user.is_active if user and getattr(user, "is_active", None) is not None else None,
                    "is_archived": getattr(user, "is_archived", False),
                }

        if chat_flag:
            # Include full chat data nested under 'chat'
            conversations = Conversation.objects.filter(user_id=user).prefetch_related("messages")
            conv_serializer = ConversationSerializer(conversations, many=True, context={"request": request})

            messages = Message.objects.filter(user_id=user).select_related("request_id", "response_id", "output_id", "conversation")

            # Collect related ids for request/response/output
            request_ids = list(messages.exclude(request_id__isnull=True).values_list("request_id", flat=True))
            response_ids = list(messages.exclude(response_id__isnull=True).values_list("response_id", flat=True))
            output_ids = list(messages.exclude(output_id__isnull=True).values_list("output_id", flat=True))

            message_requests = MessageRequest.objects.filter(request_id__in=request_ids) if request_ids else MessageRequest.objects.none()
            message_responses = MessageResponse.objects.filter(response_id__in=response_ids) if response_ids else MessageResponse.objects.none()
            message_outputs = MessageOutput.objects.filter(output_id__in=output_ids) if output_ids else MessageOutput.objects.none()

            attachments_qs = Attachment.objects.filter(message_id__user_id=user).select_related("message_id__user_id")

            # Use composite serializer to build the nested chat payload
            try:
                from user_mang.serializers import FullChatSerializer

                chat_instance = {
                    "conversations": conversations,
                    "messages": messages,
                    "message_request": message_requests,
                    "message_response": message_responses,
                    "message_output": message_outputs,
                    "attachments": attachments_qs,
                }
                chat_serializer = FullChatSerializer(chat_instance, context={"request": request})
                chat_data = chat_serializer.data
            except Exception:
                # Fallback to the previous manual assembly if serializer not available
                conv_serializer = ConversationSerializer(conversations, many=True, context={"request": request})
                msg_serializer = MessageSerializer(messages, many=True, context={"request": request})
                req_serializer = MessageRequestSerializer(message_requests, many=True, context={"request": request})
                resp_serializer = MessageResponseSerializer(message_responses, many=True, context={"request": request})
                out_serializer = MessageOutputSerializer(message_outputs, many=True, context={"request": request})
                attach_serializer = AttachmentSerializer(attachments_qs, many=True, context={"request": request})
                chat_data = {
                    "conversations": conv_serializer.data,
                    "messages": msg_serializer.data,
                    "message_request": req_serializer.data,
                    "message_response": resp_serializer.data,
                    "message_output": out_serializer.data,
                    "attachments": attach_serializer.data,
                }

            # Build attachments list separately, inject user_id from related message,
            # then overwrite whatever attachments the chat serializer returned.
            attach_serializer = AttachmentSerializer(attachments_qs, many=True, context={"request": request})
            attachments_data = list(attach_serializer.data)
            for inst, data in zip(attachments_qs, attachments_data):
                try:
                    data["user_id"] = str(getattr(inst.message_id.user_id, "user_id", inst.message_id.user_id))
                except Exception:
                    data["user_id"] = None

            try:
                if isinstance(chat_data, dict):
                    chat_data["attachments"] = attachments_data
                else:
                    # best-effort: wrap into dict if serializer produced a non-dict
                    chat_data = dict(chat_data)
                    chat_data["attachments"] = attachments_data
            except Exception:
                # fallback: attach a top-level attachments key
                chat_data = {**({} if not isinstance(chat_data, dict) else chat_data), "attachments": attachments_data}

            response_data["chat"] = chat_data

        if not (profile_flag or chat_flag):
            # Default behavior: return both profile and chat using serializers
            conversations = Conversation.objects.filter(user_id=user).prefetch_related("messages")
            conv_serializer = ConversationSerializer(conversations, many=True, context={"request": request})

            messages = Message.objects.filter(user_id=user).select_related("request_id", "response_id", "output_id", "conversation")

            request_ids = list(messages.exclude(request_id__isnull=True).values_list("request_id", flat=True))
            response_ids = list(messages.exclude(response_id__isnull=True).values_list("response_id", flat=True))
            output_ids = list(messages.exclude(output_id__isnull=True).values_list("output_id", flat=True))

            message_requests = MessageRequest.objects.filter(request_id__in=request_ids) if request_ids else MessageRequest.objects.none()
            message_responses = MessageResponse.objects.filter(response_id__in=response_ids) if response_ids else MessageResponse.objects.none()
            message_outputs = MessageOutput.objects.filter(output_id__in=output_ids) if output_ids else MessageOutput.objects.none()

            attachments_qs = Attachment.objects.filter(message_id__user_id=user).select_related("message_id__user_id")

            try:
                from user_mang.serializers import FullChatSerializer

                chat_instance = {
                    "conversations": conversations,
                    "messages": messages,
                    "message_request": message_requests,
                    "message_response": message_responses,
                    "message_output": message_outputs,
                    "attachments": attachments_qs,
                }
                chat_serializer = FullChatSerializer(chat_instance, context={"request": request})
                chat_data = chat_serializer.data
            except Exception:
                conv_serializer = ConversationSerializer(conversations, many=True, context={"request": request})
                msg_serializer = MessageSerializer(messages, many=True, context={"request": request})
                req_serializer = MessageRequestSerializer(message_requests, many=True, context={"request": request})
                resp_serializer = MessageResponseSerializer(message_responses, many=True, context={"request": request})
                out_serializer = MessageOutputSerializer(message_outputs, many=True, context={"request": request})
                attach_serializer = AttachmentSerializer(attachments_qs, many=True, context={"request": request})
                chat_data = {
                    "conversations": conv_serializer.data,
                    "messages": msg_serializer.data,
                    "message_request": req_serializer.data,
                    "message_response": resp_serializer.data,
                    "message_output": out_serializer.data,
                    "attachments": attach_serializer.data,
                }

            # Build attachments list separately, inject user_id from related message,
            # then overwrite whatever attachments the chat serializer returned.
            attach_serializer = AttachmentSerializer(attachments_qs, many=True, context={"request": request})
            attachments_data = list(attach_serializer.data)
            for inst, data in zip(attachments_qs, attachments_data):
                try:
                    data["user_id"] = str(getattr(inst.message_id.user_id, "user_id", inst.message_id.user_id))
                except Exception:
                    data["user_id"] = None

            try:
                if isinstance(chat_data, dict):
                    chat_data["attachments"] = attachments_data
                else:
                    chat_data = dict(chat_data)
                    chat_data["attachments"] = attachments_data
            except Exception:
                chat_data = {**({} if not isinstance(chat_data, dict) else chat_data), "attachments": attachments_data}

            response_data["chat"] = chat_data
            try:
                from user_mang.serializers import FullProfileSerializer

                profile_serializer = FullProfileSerializer(user, context={"request": request})
                response_data["profile"] = profile_serializer.data
            except Exception:
                response_data["profile"] = {
                    "username": str(user.username) if user and getattr(user, "username", None) is not None else None,
                    "email": str(user.email) if user and getattr(user, "email", None) is not None else None,
                    "is_visitor": user.is_visitor if user and getattr(user, "is_visitor", None) is not None else None,
                    "is_active": user.is_active if user and getattr(user, "is_active", None) is not None else None,
                    "is_archived": getattr(user, "is_archived", False),
                }

        return Response(response_data, status=status.HTTP_200_OK)

    def post(self, request):
        """
        POST

                Upserts (creates or updates) user profile and/or chat data.

                Behavior / notes:
                - Profile updates are validated with `FullProfileSerializer` when provided. Invalid profile data aborts the
                    request with a 400 and validation details.
                - Chat model lists (conversations, messages, message_requests, message_responses, message_outputs,
                    attachments) are validated per-item via their respective serializers.
                - The endpoint performs upserts inside a database transaction; on failure no partial changes are applied.

                Example Request (upsert profile + chat):
                        POST /api/v1/unified-sync/
                        {
                                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                                "profile": {"username": "john_doe_updated", "email": "john_new@example.com"},
                                "conversations": [{"conversation_id": "c1", "title": "Updated Conversation"}],
                                "messages": [{"message_id": "m1", "conversation_id": "c1", "content": "Hello again!"}],
                                "attachments": [{"id": 1, "type": "image", "file_path": "/media/attachments/1.png"}],
                                "profile": true,
                                "chat": true
                        }


        Example Response (successful upsert):
                        {
                                "summary": { ...counts... },
                                "errors": { ...per-model-errors-or-empty-arrays... },
                                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                                "temp_id": null,
                                "profile": { ...FullProfileSerializer output... },
                                "chat": { ...FullChatSerializer output..., "attachments": [ {"id":1, ..., "user_id": "..."}, ... ] }
                        }

                The response includes the canonical `profile` and `chat` payloads (when requested or by default). Attachments
                in the returned `chat.attachments` array include `user_id` for client convenience.
        """
        user, is_new_visitor, error_response, temp_id = self.resolve_user(request)
        if error_response:
            return error_response

        profile_flag, chat_flag = resolve_flags(request)

        summary = {}
        errors = {}

        # Profile upsert - use ProfileSerializer for validation and safe updates
        if profile_flag or not (profile_flag or chat_flag):
            profile_data = request.data.get("profile", {})
            if profile_data:
                if user is None:
                    logger.warning("UnifiedSyncView.post: Attempted to update profile for None user.")
                    return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
                # Use serializer to validate and apply full profile updates
                from user_mang.serializers import FullProfileSerializer

                serializer = FullProfileSerializer(user, data=profile_data, partial=True, context={"request": request})
                if serializer.is_valid():
                    serializer.save()
                    summary["profile_updated"] = True
                else:
                    # Return validation errors for profile and do not proceed with chat upserts
                    return Response({"error": "Invalid profile data", "details": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
            else:
                summary["profile_updated"] = False

        # Chat upsert
        if chat_flag or not (profile_flag or chat_flag):
            conversations_data = request.data.get("conversations", [])
            messages_data = request.data.get("messages", [])
            reqs_data = request.data.get("message_requests", [])
            resps_data = request.data.get("message_responses", [])
            outs_data = request.data.get("message_outputs", [])
            attachments_data = request.data.get("attachments", [])

            if not all(isinstance(lst, list) for lst in [conversations_data, messages_data, reqs_data, resps_data, outs_data, attachments_data]):
                return Response({"error": "Invalid format for one or more model lists."},
                                status=status.HTTP_400_BAD_REQUEST)

            created, updated = dict(conv=0, msg=0, req=0, resp=0, out=0, att=0), dict(conv=0, msg=0, req=0, resp=0, out=0, att=0)
            errors = {k: [] for k in ["conversations", "messages", "message_requests", "message_responses", "message_outputs", "attachments"]}

            try:
                with transaction.atomic():
                    # Conversations
                    for conv in conversations_data:
                        conv_id = conv.get("conversation_id") or conv.get("id")
                        if not conv_id:
                            errors["conversations"].append({"data": conv, "error": "Missing conversation_id"})
                            continue
                        if user is None:
                            errors["conversations"].append({"data": conv, "error": "User is None"})
                            continue
                        conv["user_id"] = user.pk
                        instance = Conversation.objects.filter(conversation_id=conv_id).first()
                        serializer = ConversationSerializer(instance, data=conv, partial=True, context={"request": request})
                        if serializer.is_valid():
                            # Conversation.user_id is read-only on the serializer; ensure the FK is set via save(kwargs)
                            serializer.save(user_id=user)
                            (created if instance is None else updated)["conv"] += 1
                        else:
                            errors["conversations"].append(serializer.errors)

                    # Requests
                    for req in reqs_data:
                        req_id = req.get("request_id")
                        if not req_id:
                            errors["message_requests"].append({"data": req, "error": "Missing id"})
                            continue
                        instance = MessageRequest.objects.filter(request_id=req_id).first()
                        serializer = MessageRequestSerializer(instance, data=req, partial=True, context={"request": request})
                        if serializer.is_valid():
                            serializer.save()
                            (created if instance is None else updated)["req"] += 1
                        else:
                            errors["message_requests"].append(serializer.errors)

                    # Responses
                    for resp in resps_data:
                        resp_id = resp.get("response_id")
                        if not resp_id:
                            errors["message_responses"].append({"data": resp, "error": "Missing id"})
                            continue
                        instance = MessageResponse.objects.filter(response_id=resp_id).first()
                        serializer = MessageResponseSerializer(instance, data=resp, partial=True, context={"request": request})
                        if serializer.is_valid():
                            serializer.save()
                            (created if instance is None else updated)["resp"] += 1
                        else:
                            errors["message_responses"].append(serializer.errors)

                    # Outputs
                    for out in outs_data:
                        out_id = out.get("output_id")
                        if not out_id:
                            errors["message_outputs"].append({"data": out, "error": "Missing id"})
                            continue
                        instance = MessageOutput.objects.filter(output_id=out_id).first()
                        serializer = MessageOutputSerializer(instance, data=out, partial=True, context={"request": request})
                        if serializer.is_valid():
                            serializer.save()
                            (created if instance is None else updated)["out"] += 1
                        else:
                            errors["message_outputs"].append(serializer.errors)

                    # Messages
                    for msg in messages_data:
                        msg_id = msg.get("message_id")
                        if not msg_id:
                            errors["messages"].append({"data": msg, "error": "Missing message_id"})
                            continue
                        if user is None:
                            errors["messages"].append({"data": msg, "error": "User is None"})
                            continue
                        msg["user_id"] = user.pk
                        instance = Message.objects.filter(message_id=msg_id).first()
                        serializer = MessageSerializer(instance, data=msg, partial=True, context={"request": request})
                        if serializer.is_valid():
                            # Message.user_id is read-only on the serializer; pass the user instance to save()
                            serializer.save(user_id=user)
                            (created if instance is None else updated)["msg"] += 1
                        else:
                            errors["messages"].append(serializer.errors)

                    # Attachments
                    for att in attachments_data:
                        att_id = att.get("id")
                        if not att_id:
                            errors["attachments"].append({"data": att, "error": "Missing id"})
                            continue
                        if user is not None:
                            # ensure the incoming payload uses 'user_id' key for clarity, but pass the user to save()
                            att["user_id"] = user.pk
                        else:
                            errors["attachments"].append({"data": att, "error": "User is None"})
                            continue
                        instance = Attachment.objects.filter(pk=att_id).first()
                        serializer = AttachmentSerializer(instance, data=att, partial=True, context={"request": request})
                        if serializer.is_valid():
                            # Attachment.user_id is read-only; set FK on save
                            serializer.save(user_id=user)
                            (created if instance is None else updated)["att"] += 1
                        else:
                            errors["attachments"].append(serializer.errors)

            except Exception as e:
                logger.error("Transaction failed", exc_info=True)
                return Response({
                    "error": "Transaction failed. No changes were applied.",
                    "details": str(e),
                    "errors": errors
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            attachments = Attachment.objects.filter(message_id__user_id=user)
            attach_serializer = AttachmentSerializer(attachments, many=True, context={"request": request})

            summary.update({
                "conversations_created": created["conv"], "conversations_updated": updated["conv"],
                "messages_created": created["msg"], "messages_updated": updated["msg"],
                "requests_created": created["req"], "requests_updated": updated["req"],
                "responses_created": created["resp"], "responses_updated": updated["resp"],
                "outputs_created": created["out"], "outputs_updated": updated["out"],
                "attachments_created": created["att"], "attachments_updated": updated["att"],
            })
            errors = errors

        # Build final serialized profile/chat payload for the response
        response_payload = {
            "summary": summary,
            "errors": errors,
            "user_id": str(user.user_id) if user else None,
            "temp_id": temp_id,
        }

        # Include profile when requested (or by default)
        if profile_flag or not (profile_flag or chat_flag):
            try:
                from user_mang.serializers import FullProfileSerializer

                profile_serializer = FullProfileSerializer(user, context={"request": request})
                response_payload["profile"] = profile_serializer.data
            except Exception:
                response_payload["profile"] = {
                    "username": str(user.username) if user and getattr(user, "username", None) is not None else None,
                    "email": str(user.email) if user and getattr(user, "email", None) is not None else None,
                    "is_visitor": user.is_visitor if user and getattr(user, "is_visitor", None) is not None else None,
                    "is_active": user.is_active if user and getattr(user, "is_active", None) is not None else None,
                    "is_archived": getattr(user, "is_archived", False),
                }

        # Include chat when requested (or by default)
        if chat_flag or not (profile_flag or chat_flag):
            conversations = Conversation.objects.filter(user_id=user).prefetch_related("messages")
            messages = Message.objects.filter(user_id=user).select_related("request_id", "response_id", "output_id", "conversation")

            request_ids = list(messages.exclude(request_id__isnull=True).values_list("request_id", flat=True))
            response_ids = list(messages.exclude(response_id__isnull=True).values_list("response_id", flat=True))
            output_ids = list(messages.exclude(output_id__isnull=True).values_list("output_id", flat=True))

            message_requests = MessageRequest.objects.filter(request_id__in=request_ids) if request_ids else MessageRequest.objects.none()
            message_responses = MessageResponse.objects.filter(response_id__in=response_ids) if response_ids else MessageResponse.objects.none()
            message_outputs = MessageOutput.objects.filter(output_id__in=output_ids) if output_ids else MessageOutput.objects.none()

            attachments_qs = Attachment.objects.filter(message_id__user_id=user).select_related("message_id__user_id")

            try:
                from user_mang.serializers import FullChatSerializer

                chat_instance = {
                    "conversations": conversations,
                    "messages": messages,
                    "message_request": message_requests,
                    "message_response": message_responses,
                    "message_output": message_outputs,
                    "attachments": attachments_qs,
                }
                chat_serializer = FullChatSerializer(chat_instance, context={"request": request})
                chat_data = chat_serializer.data
            except Exception:
                conv_serializer = ConversationSerializer(conversations, many=True, context={"request": request})
                msg_serializer = MessageSerializer(messages, many=True, context={"request": request})
                req_serializer = MessageRequestSerializer(message_requests, many=True, context={"request": request})
                resp_serializer = MessageResponseSerializer(message_responses, many=True, context={"request": request})
                out_serializer = MessageOutputSerializer(message_outputs, many=True, context={"request": request})
                attach_serializer = AttachmentSerializer(attachments_qs, many=True, context={"request": request})
                chat_data = {
                    "conversations": conv_serializer.data,
                    "messages": msg_serializer.data,
                    "message_request": req_serializer.data,
                    "message_response": resp_serializer.data,
                    "message_output": out_serializer.data,
                    "attachments": attach_serializer.data,
                }

            # Ensure attachments include user_id
            attach_serializer = AttachmentSerializer(attachments_qs, many=True, context={"request": request})
            attachments_data = list(attach_serializer.data)
            for inst, data in zip(attachments_qs, attachments_data):
                try:
                    data["user_id"] = str(getattr(inst.message_id.user_id, "user_id", inst.message_id.user_id))
                except Exception:
                    data["user_id"] = None

            try:
                if isinstance(chat_data, dict):
                    chat_data["attachments"] = attachments_data
                else:
                    chat_data = dict(chat_data)
                    chat_data["attachments"] = attachments_data
            except Exception:
                chat_data = {**({} if not isinstance(chat_data, dict) else chat_data), "attachments": attachments_data}

            response_payload["chat"] = chat_data

        return Response(response_payload, status=status.HTTP_200_OK)

    def patch(self, request):
        """
        PATCH

        Allow field-by-field, authenticated partial updates to the user's profile. This is intended for the
        single-user "me" endpoint used by the SPA. The view accepts either a top-level set of profile fields
        (e.g. {"username":"x"}) or a nested `profile` dict (e.g. {"profile": {"username":"x"}}).

        Behavior:
        - Requires authentication for writes unless a valid `temp_id` visitor flow is used (handled by resolve_user).
        - Uses the safe `ProfileSerializer` which whitelists writable fields to avoid accidental exposure of
          sensitive fields.
        - Returns 200 with the updated profile on success, or 400 with validation errors.
        """
        user, _, error_response, temp_id = self.resolve_user(request)
        if error_response:
            return error_response

        # Accept either { profile: {...} } or direct field keys
        profile_data = request.data.get("profile") if isinstance(request.data.get("profile"), dict) else request.data

        if not profile_data:
            return Response({"error": "No profile data provided"}, status=status.HTTP_400_BAD_REQUEST)

        # Use the safe, whitelisted serializer for partial updates
        try:
            from user_mang.serializers import ProfileSerializer
        except Exception:
            logger.exception("Failed to import ProfileSerializer")
            return Response({"error": "Server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        serializer = ProfileSerializer(user, data=profile_data, partial=True, context={"request": request})
        if serializer.is_valid():
            serializer.save()
            return Response({"profile": serializer.data}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid profile data", "details": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        """DELETE

        Delete or archive a user's profile and/or chat data.

        Important behavior changes:
            - The ``action`` parameter is now restricted to "delete" or "archive". Other values are rejected.
            - On any successful delete or archive operation this endpoint will always generate BOTH a CSV and a
              PDF export of the user's data.
            - Exports are saved under MEDIA_ROOT/exports/<user_id> and emailed to the user's verified address when
              available.
            - If the caller provides ``download_now`` (truthy: 1/true/yes) the view will zip the CSV+PDF and
              immediately return the zip file as a FileResponse. If ``download_now`` is falsy the files are kept on
              disk and the response will include URLs the client can use to download them.

        Parameters (body or query):
            - action: "delete" | "archive"  (required)
            - profile: true/false
            - chat: true/false
            - download_now: true/false or 1/0 — when true return a zip (csv+pdf) immediately; when false save and
              return URLs instead
            - reason: optional string for audit logs

        Returns (examples):

        Example Request (delete + return URLs):
            DELETE /api/v1/unified-sync/
            {
                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                "action": "delete",
                "profile": true,
                "chat": true,
                "download_now": false
            }

        Example Response (delete, saved exports):
            HTTP 200
            {
                "message": "User and all related data deleted successfully",
                "deleted": { "attachments": 2, "messages": 5, "conversations": 1, "tokens": 1, "user": 1 },
                "export_urls": {
                    "csv": "https://example.com/media/exports/<user_id>/user_export_20250829123000.csv",
                    "pdf": "https://example.com/media/exports/<user_id>/user_export_20250829123000.pdf"
                },
                "profile": { /* FullProfileSerializer output or minimal fallback */ },
                "chat": { /* FullChatSerializer output or minimal fallback */ }
            }

        Example Request (archive + immediate download):
            DELETE /api/v1/unified-sync/
            {
                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                "action": "archive",
                "profile": true,
                "download_now": true
            }

        Example Response (archive, immediate zip):
            HTTP 200
            (A FileResponse serving an attachment named "user_export_<user_id>.zip" containing both CSV and PDF)

        Notes:
            - Exporting and emailing are best-effort. Failures while creating or sending exports are logged and do
              not prevent the delete/archive from completing.
            - The response will include ``export_urls`` when files are saved and not directly returned.
        """
        user, _, error_response, temp_id = self.resolve_user(request)
        if error_response:
            return error_response

        profile_flag, chat_flag = resolve_flags(request)
        action = (request.data.get('action') or request.query_params.get('action') or '').lower()
        reason = request.data.get('reason') if hasattr(request, 'data') else None
        reason = reason or request.query_params.get('reason')

        # export options
        # Note: action is reserved to 'delete' or 'archive'. Exports (both CSV and PDF) are always created for
        # successful delete/archive operations. The request may include `download_now` to request immediate return
        # of the files (as a zip); otherwise the files are saved and URLs are returned in the final response.
        export_format = (request.data.get('export') or request.query_params.get('export') or 'csv').lower()
        # New: support explicit `download_now` flag (body or query). Fall back to existing `download` param for
        # backward compatibility. Truthy values: 1, true, yes
        raw_download_now = None
        try:
            raw_download_now = request.data.get('download_now') if hasattr(request, 'data') else None
        except Exception:
            raw_download_now = None
        if raw_download_now is None:
            raw_download_now = request.query_params.get('download_now') or request.query_params.get('download') or (request.data.get('download') if hasattr(request, 'data') else None)
        download_now = (str(raw_download_now).lower() in ['1', 'true', 'yes']) if raw_download_now is not None else False

        # export_urls will hold saved file URLs when download_now is False
        export_urls = None

        # Validate action: only 'delete' or 'archive' allowed
        if action not in ['delete', 'archive']:
            return Response({"error": "Invalid action. Use 'delete' or 'archive'."}, status=status.HTTP_400_BAD_REQUEST)

        stats = {}

        # Export and save user data before deletion/archive (only when profile/chat requested)
        if (profile_flag or chat_flag) and (action in ['delete', 'archive']):
            if user:
                try:
                    # create export directory under MEDIA_ROOT/exports/<user_id>/
                    export_subdir = os.path.join(getattr(settings, 'MEDIA_ROOT', 'media'), 'exports', str(user.user_id))
                    os.makedirs(export_subdir, exist_ok=True)

                    # Always generate CSV and PDF exports
                    csv_src = None
                    pdf_tmp = None
                    try:
                        csv_src = self.export_user_data_csv(user)
                    except Exception:
                        csv_src = None
                        logger.exception('Failed to generate CSV export')

                    try:
                        pdf_tmp = self.export_user_data_pdf(user)
                        pdf_src = pdf_tmp.name
                    except Exception:
                        pdf_src = None
                        logger.exception('Failed to generate PDF export')

                    dst_name_csv = f"user_export_{user.user_id}_{timezone.now().strftime('%Y%m%d%H%M%S')}.csv"
                    dst_path_csv = os.path.join(export_subdir, dst_name_csv)
                    if csv_src:
                        try:
                            shutil.move(csv_src, dst_path_csv)
                        except Exception:
                            logger.exception('Failed to move CSV export')

                    dst_name_pdf = f"user_export_{user.user_id}_{timezone.now().strftime('%Y%m%d%H%M%S')}.pdf"
                    dst_path_pdf = os.path.join(export_subdir, dst_name_pdf)
                    if pdf_src:
                        try:
                            shutil.move(pdf_src, dst_path_pdf)
                        except Exception:
                            logger.exception('Failed to move PDF export')

                    # Optionally email both files right away
                    try:
                        attachments = []
                        if pdf_src and os.path.exists(dst_path_pdf):
                            attachments.append((dst_path_pdf, dst_name_pdf, 'application/pdf'))
                        if csv_src and os.path.exists(dst_path_csv):
                            attachments.append((dst_path_csv, dst_name_csv, 'text/csv'))
                        if attachments:
                            send_verified_email(
                                subject="Your Data Export",
                                message="Attached are your requested data exports.",
                                recipient_list=[user.email] if getattr(user, 'email', None) else [],
                                from_email=None,
                                html_message=None,
                                verify_with_zeruh=True,
                                zeruh_min_score=70,
                                fail_silently=True,
                                attachments=attachments
                            )
                    except Exception:
                        logger.exception("Failed to send export email; continuing")

                    # If frontend requested immediate download (download_now), return a zip containing both files
                    if download_now:
                        try:
                            zip_tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
                            with zipfile.ZipFile(zip_tmp.name, 'w') as zf:
                                if os.path.exists(dst_path_pdf):
                                    zf.write(dst_path_pdf, dst_name_pdf)
                                if os.path.exists(dst_path_csv):
                                    zf.write(dst_path_csv, dst_name_csv)
                            return FileResponse(open(zip_tmp.name, 'rb'), as_attachment=True, filename=f"user_export_{user.user_id}.zip", content_type='application/zip')
                        except Exception:
                            logger.exception('Failed to create/send zip export')

                    # Otherwise build URLs the frontend can use to fetch the saved exports
                    media_url = getattr(settings, 'MEDIA_URL', '/media/')
                    urls = {}
                    if os.path.exists(dst_path_csv):
                        urls['csv'] = request.build_absolute_uri(os.path.join(media_url, 'exports', str(user.user_id), dst_name_csv))
                    if os.path.exists(dst_path_pdf):
                        urls['pdf'] = request.build_absolute_uri(os.path.join(media_url, 'exports', str(user.user_id), dst_name_pdf))
                    if urls:
                        export_urls = urls
                except Exception:
                    logger.exception("Failed to create/save export; proceeding without it")

        # Chat delete/archive (soft delete if possible)
        if chat_flag or not (profile_flag or chat_flag):
            attachments = Attachment.objects.filter(user_id=user)
            messages = Message.objects.filter(user_id=user)
            conversations = Conversation.objects.filter(user_id=user)
            tokens = ProviderOAuthToken.objects.filter(user_id=user)

            stats.update({
                "attachments": attachments.count(),
                "messages": messages.count(),
                "conversations": conversations.count(),
                "tokens": tokens.count(),
            })

            if action == 'delete':
                self.soft_delete_queryset(attachments)
                self.soft_delete_queryset(messages)
                self.soft_delete_queryset(conversations)
                tokens.delete()
            elif action == 'archive':
                tokens.delete()

        # Profile delete/archive (soft delete if possible)
        if profile_flag or not (profile_flag or chat_flag):
            stats["user"] = 1
            if action == 'delete':
                if user is not None:
                    # Model uses is_archived for soft-archive; use that instead of is_deleted
                    if hasattr(user, "is_archived"):
                        user.is_archived = True
                        user.is_active = False
                        try:
                            user.save(update_fields=["is_archived", "is_active"])
                        except Exception:
                            user.save()
                    else:
                        user.delete()
                    logger.info(f"UnifiedSyncView: User {user.pk} and all related data deleted.")
                else:
                    logger.warning("UnifiedSyncView: Attempted to delete a None user object.")
                # Include final serialized profile/chat in the response for convenience
                payload = {"message": "User and all related data deleted successfully", "deleted": stats}
                try:
                    from user_mang.serializers import FullProfileSerializer, FullChatSerializer
                    payload["profile"] = FullProfileSerializer(user, context={"request": request}).data
                    # minimal chat assembly
                    conversations = Conversation.objects.filter(user_id=user).prefetch_related("messages")
                    messages = Message.objects.filter(user_id=user)
                    message_requests = MessageRequest.objects.filter(request_id__in=messages.values_list("request_id", flat=True))
                    message_responses = MessageResponse.objects.filter(response_id__in=messages.values_list("response_id", flat=True))
                    message_outputs = MessageOutput.objects.filter(output_id__in=messages.values_list("output_id", flat=True))
                    attachments_qs = Attachment.objects.filter(message_id__user_id=user)
                    chat_instance = {
                        "conversations": conversations,
                        "messages": messages,
                        "message_request": message_requests,
                        "message_response": message_responses,
                        "message_output": message_outputs,
                        "attachments": attachments_qs,
                    }
                    payload["chat"] = FullChatSerializer(chat_instance, context={"request": request}).data
                except Exception:
                    # ignore serialization errors and return minimal payload
                    pass
                return Response(payload)
            elif action == 'archive':
                if user is not None:
                    user.is_archived, user.is_active = True, False
                    flags = ["is_google_user", "is_openrouter_user", "is_github_user", "is_microsoft_user"]
                    for flag in flags:
                        if getattr(user, flag, False):
                            setattr(user, flag, False)
                    user.save(update_fields=["is_archived", "is_active"] + flags)
                    logger.info(f"UnifiedSyncView: User {user.pk} archived; tokens purged.")
                    # Include serialized profile (archived) and minimal chat summary
                    payload = {"message": "User archived successfully", "archived": stats}
                    try:
                        from user_mang.serializers import FullProfileSerializer, FullChatSerializer
                        payload["profile"] = FullProfileSerializer(user, context={"request": request}).data
                        conversations = Conversation.objects.filter(user_id=user).prefetch_related("messages")
                        messages = Message.objects.filter(user_id=user)
                        message_requests = MessageRequest.objects.filter(request_id__in=messages.values_list("request_id", flat=True))
                        message_responses = MessageResponse.objects.filter(request_id__in=messages.values_list("response_id", flat=True))
                        message_outputs = MessageOutput.objects.filter(output_id__in=messages.values_list("output_id", flat=True))
                        attachments_qs = Attachment.objects.filter(message_id__user_id=user)

                    except Exception:
                        logger.exception('Failed to serialize archived profile/chat')
                    return Response(payload)
                else:
                    logger.warning("UnifiedSyncView: Attempted to archive a None user object.")
                    return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        return Response({"error": "Specify action=delete, archive or export in query or body."},
            status=status.HTTP_400_BAD_REQUEST)
    