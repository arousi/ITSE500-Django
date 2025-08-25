import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from .models import Custom_User
from user_mang.serializers import (ConversationSerializer,  # <-- Add this import
                                    AttachmentSerializer,
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
from user_mang.models.custom_user import Custom_User
from django.db import transaction
from django.utils import timezone
import logging
import json
from auth_api.models import ProviderOAuthToken  # lazy import

# Get a logger specific to the user_mang app
logger = logging.getLogger('user_mang')

class UnifiedSyncView(APIView):
    """
    UnifiedSyncView

    A unified API endpoint for managing both chat data (conversations, messages, attachments, etc.)
    and user profile data for both visitors and registered users. This endpoint supports GET, POST,
    and DELETE methods, and can handle chat, profile, or both, based on query parameters or request body.

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
    """

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
        user_id = request.data.get("user_id") or request.query_params.get("user_id")
        anon_id = request.data.get("anon_id") or request.query_params.get("anon_id")
        temp_id = request.data.get("temp_id") or request.query_params.get("temp_id")
        device_id = request.data.get("device_id") or request.query_params.get("device_id")

        user = None
        is_new_visitor = False

        if user_id:
            user = Custom_User.objects.filter(user_id=user_id).first()
        elif anon_id:
            user = Custom_User.objects.filter(user_id=anon_id, is_visitor=True).first()
        elif temp_id:
            user = Custom_User.objects.filter(temp_id=temp_id).first()
            if not user:
                user = self._create_visitor(temp_id)
                is_new_visitor = True

        if not user:
            return None, False, Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND), temp_id

        if temp_id and (not user.temp_id or user.temp_id != temp_id):
            user.temp_id = temp_id
            user.save(update_fields=["temp_id"])

        if device_id:
            self._associate_device(user, device_id)

        return user, is_new_visitor, None, temp_id

    def get(self, request):
        """
        ------------------------------------------------------------------------
        GET
        ------------------------------------------------------------------------
        Returns user profile, chat data (conversations, messages, attachments), or both.

        Example Request:
            GET /api/v1/unified-sync/?user_id=123e4567-e89b-12d3-a456-426614174000&profile=true&chat=true

        Example Response:
            {
                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                "is_new": false,
                "temp_id": null,
                "profile": {
                    "username": "john_doe",
                    "email": "john@example.com",
                    "is_visitor": false,
                    "is_active": true,
                    "is_archived": false
                },
                "conversations": [
                    {
                        "conversation_id": "c1",
                        "title": "My Conversation",
                        "messages": [
                            {
                                "message_id": "m1",
                                "content": "Hello!"
                            }
                        ]
                    }
                ],
                "attachments": [
                    {
                        "id": 1,
                        "type": "image",
                        "file_path": "/media/attachments/1.png"
                    }
                ]
            }
        """
        user, is_new_visitor, error_response, temp_id = self.resolve_user(request)
        if error_response:
            return error_response

        profile_flag = (
            request.query_params.get("profile") == "true"
            or request.data.get("profile") is True
        )
        chat_flag = (
            request.query_params.get("chat") == "true"
            or request.data.get("chat") is True
        )

        response_data = {
            "user_id": str(user.user_id) if user and getattr(user, "user_id", None) is not None else None,
            "is_new": is_new_visitor,
            "temp_id": temp_id,
        }

        if profile_flag:
            response_data["profile"] = {
                "username": str(user.username) if user and getattr(user, "username", None) is not None else None,
                "email": str(user.email) if user and getattr(user, "email", None) is not None else None,
                "is_visitor": user.is_visitor if user and getattr(user, "is_visitor", None) is not None else None,
                "is_active": user.is_active if user and getattr(user, "is_active", None) is not None else None,
                "is_archived": getattr(user, "is_archived", False),
                # Add more profile fields as needed
            }

        if chat_flag:
            conversations = Conversation.objects.filter(user_id=user).prefetch_related("messages")
            conv_serializer = ConversationSerializer(conversations, many=True)
            attachments = Attachment.objects.filter(user_id=user)
            attach_serializer = AttachmentSerializer(attachments, many=True)
            response_data["conversations"] = conv_serializer.data
            response_data["attachments"] = attach_serializer.data

        if not (profile_flag or chat_flag):
            conversations = Conversation.objects.filter(user_id=user).prefetch_related("messages")
            conv_serializer = ConversationSerializer(conversations, many=True)
            attachments = Attachment.objects.filter(user_id=user)
            attach_serializer = AttachmentSerializer(attachments, many=True)
            response_data["conversations"] = conv_serializer.data
            response_data["attachments"] = attach_serializer.data
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
            --------------------------------------------------------------------
            POST
            --------------------------------------------------------------------
            Upserts (creates or updates) user profile, chat data, or both.

            Example Request:
                POST /api/v1/unified-sync/
                {
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "profile": {
                        "username": "john_doe_updated",
                        "email": "john_new@example.com"
                    },
                    "conversations": [
                        {
                            "conversation_id": "c1",
                            "title": "Updated Conversation"
                        }
                    ],
                    "messages": [
                        {
                            "message_id": "m1",
                            "conversation_id": "c1",
                            "content": "Hello again!"
                        }
                    ],
                    "attachments": [
                        {
                            "id": 1,
                            "type": "image",
                            "file_path": "/media/attachments/1.png"
                        }
                    ],
                    "profile": true,
                    "chat": true
                }

            Example Response:
                {
                    "summary": {
                        "profile_updated": true,
                        "conversations_created": 0,
                        "conversations_updated": 1,
                        "messages_created": 0,
                        "messages_updated": 1,
                        "requests_created": 0,
                        "requests_updated": 0,
                        "responses_created": 0,
                        "responses_updated": 0,
                        "outputs_created": 0,
                        "outputs_updated": 0,
                        "attachments_created": 0,
                        "attachments_updated": 1
                    },
                    "errors": {
                        "conversations": [],
                        "messages": [],
                        "message_requests": [],
                        "message_responses": [],
                        "message_outputs": [],
                        "attachments": []
                    },
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "attachments": [
                        {
                            "id": 1,
                            "type": "image",
                            "file_path": "/media/attachments/1.png"
                        }
                    ],
                    "temp_id": null
                }
        """
        user, is_new_visitor, error_response, temp_id = self.resolve_user(request)
        if error_response:
            return error_response

        profile_flag = (
            request.query_params.get("profile") == "true"
            or request.data.get("profile") is True
        )
        chat_flag = (
            request.query_params.get("chat") == "true"
            or request.data.get("chat") is True
        )

        summary = {}
        errors = {}

        # Profile upsert
        if profile_flag or not (profile_flag or chat_flag):
            profile_data = request.data.get("profile", {})
            if profile_data:
                if user is None:
                    logger.warning("UnifiedSyncView.post: Attempted to update profile for None user.")
                    return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
                for field in ["username", "email"]:
                    if field in profile_data:
                        setattr(user, field, profile_data[field])
                user.save()
                summary["profile_updated"] = True
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
                        serializer = ConversationSerializer(instance, data=conv, partial=True)
                        if serializer.is_valid():
                            serializer.save()
                            (created if instance is None else updated)["conv"] += 1
                        else:
                            errors["conversations"].append(serializer.errors)

                    # Requests
                    for req in reqs_data:
                        req_id = req.get("request_id")
                        if not req_id:
                            errors["message_requests"].append({"data": req, "error": "Missing id"})
                            continue
                        instance = MessageRequest.objects.filter(id=req_id).first()
                        serializer = MessageRequestSerializer(instance, data=req, partial=True)
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
                        instance = MessageResponse.objects.filter(id=resp_id).first()
                        serializer = MessageResponseSerializer(instance, data=resp, partial=True)
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
                        instance = MessageOutput.objects.filter(id=out_id).first()
                        serializer = MessageOutputSerializer(instance, data=out, partial=True)
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
                        serializer = MessageSerializer(instance, data=msg, partial=True)
                        if serializer.is_valid():
                            serializer.save()
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
                            att["user"] = user.pk
                        else:
                            errors["attachments"].append({"data": att, "error": "User is None"})
                            continue
                        instance = Attachment.objects.filter(id=att_id).first()
                        serializer = AttachmentSerializer(instance, data=att, partial=True)
                        if serializer.is_valid():
                            serializer.save()
                            (created if instance is None else updated)["att"] += 1
                        else:
                            errors["attachments"].append(serializer.errors)

            except Exception as e:
                logger.error(f"Transaction failed: {str(e)}")
                return Response({
                    "error": "Transaction failed. No changes were applied.",
                    "details": str(e),
                    "errors": errors
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            attachments = Attachment.objects.filter(user_id=user)
            attach_serializer = AttachmentSerializer(attachments, many=True)

            summary.update({
                "conversations_created": created["conv"], "conversations_updated": updated["conv"],
                "messages_created": created["msg"], "messages_updated": updated["msg"],
                "requests_created": created["req"], "requests_updated": updated["req"],
                "responses_created": created["resp"], "responses_updated": updated["resp"],
                "outputs_created": created["out"], "outputs_updated": updated["out"],
                "attachments_created": created["att"], "attachments_updated": updated["att"],
            })
            errors = errors

        return Response({
            "summary": summary,
            "errors": errors,
            "user_id": str(user.user_id) if user else None,
            "attachments": AttachmentSerializer(Attachment.objects.filter(user_id=user), many=True).data,
            "temp_id": temp_id,
        }, status=status.HTTP_200_OK)

    def delete(self, request):
        """
        ------------------------------------------------------------------------
        DELETE
        ------------------------------------------------------------------------
        Deletes or archives user profile, chat data, or both, depending on the 'action' parameter.

        Example Request (delete all):
            DELETE /api/v1/unified-sync/
            {
                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                "action": "delete",
                "profile": true,
                "chat": true
            }

        Example Response (delete):
            {
                "message": "User and all related data deleted successfully",
                "deleted": {
                    "attachments": 2,
                    "messages": 5,
                    "conversations": 1,
                    "tokens": 1,
                    "user": 1
                }
            }

        Example Request (archive profile only):
            DELETE /api/v1/unified-sync/
            {
                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                "action": "archive",
                "profile": true
            }

        Example Response (archive):
            {
                "message": "User archived successfully",
                "archived": {
                    "user": 1
                }
            }
        """
        user, _, error_response, temp_id = self.resolve_user(request)
        if error_response:
            return error_response

        profile_flag = (
            request.query_params.get("profile") == "true"
            or request.data.get("profile") is True
        )
        chat_flag = (
            request.query_params.get("chat") == "true"
            or request.data.get("chat") is True
        )
        action = request.data.get('action', '').lower() or request.query_params.get('action', '').lower()
        reason = request.data.get('reason') if hasattr(request, 'data') else None
        reason = reason or request.query_params.get('reason')

        stats = {}

        # Chat delete/archive
        if chat_flag or not (profile_flag or chat_flag):
            attachments = Attachment.objects.filter(user_id=user)
            messages = Message.objects.filter(user_id=user)
            conversations = Conversation.objects.filter(user_id=user)
            tokens = ProviderOAuthToken.objects.filter(user=user)

            stats.update({
                "attachments": attachments.count(),
                "messages": messages.count(),
                "conversations": conversations.count(),
                "tokens": tokens.count(),
            })

            if action == 'delete':
                attachments.delete()
                messages.delete()
                conversations.delete()
                tokens.delete()
            elif action == 'archive':
                tokens.delete()

        # Profile delete/archive
        if profile_flag or not (profile_flag or chat_flag):
            stats["user"] = 1
            if action == 'delete':
                if user is not None:
                    user.delete()
                    logger.info(f"UnifiedSyncView: User {user.pk} and all related data deleted.")
                else:
                    logger.warning("UnifiedSyncView: Attempted to delete a None user object.")
                return Response({"message": "User and all related data deleted successfully", "deleted": stats})
            elif action == 'archive':
                if user is not None:
                    user.is_archived, user.is_active = True, False
                    flags = ["is_google_user", "is_openrouter_user", "is_github_user", "is_microsoft_user"]
                    for flag in flags:
                        if getattr(user, flag, False):
                            setattr(user, flag, False)
                    user.save(update_fields=["is_archived", "is_active"] + flags)
                    logger.info(f"UnifiedSyncView: User {user.pk} archived; tokens purged.")
                    return Response({"message": "User archived successfully", "archived": stats})
                else:
                    logger.warning("UnifiedSyncView: Attempted to archive a None user object.")
                    return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        return Response({"error": "Specify action=delete or action=archive in query or body."},
                        status=status.HTTP_400_BAD_REQUEST)