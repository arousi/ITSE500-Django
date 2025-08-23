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
    Unified endpoint for syncing conversations/messages for both visitors and registered users.
    - GET: Returns all conversations with nested messages for the resolved user.
    - POST: Upserts conversations/messages/requests/responses/outputs for the resolved user.
    - DELETE: Purges or archives all user data (attachments, messages, conversations, tokens).
    """

    # ---------- USER RESOLUTION HELPERS ----------

    def _create_visitor(self, temp_id: str):
        """Create a new visitor if none exists for the given temp_id."""
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
        """Associate device_id with the user (keeps JSON/list compatibility)."""
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
        """
        Resolves user by user_id, anon_id, or temp_id (for visitors).
        Also associates device if device_id is provided.
        Returns (user, is_new_visitor, error_response).
        """
        user_id = request.data.get("user_id") or request.query_params.get("user_id")
        anon_id = request.data.get("anon_id") or request.query_params.get("anon_id")
        temp_id = request.data.get("temp_id") or request.query_params.get("temp_id")
        device_id = request.data.get("device_id") or request.query_params.get("device_id")

        user = None
        is_new_visitor = False

        if user_id:
            user = Custom_User.objects.filter(user_id=user_id, is_visitor=False).first()
        elif anon_id:
            user = Custom_User.objects.filter(user_id=anon_id, is_visitor=True).first()
        elif temp_id:
            user = Custom_User.objects.filter(temp_id=temp_id).first()
            if not user:
                user = self._create_visitor(temp_id)
                is_new_visitor = True

        if not user:
            return None, False, Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        if device_id:
            self._associate_device(user, device_id)

        return user, is_new_visitor, None

    # ---------- ENDPOINTS ----------

    def get(self, request):
        """
        Return all conversations and nested messages for the resolved user (visitor or registered).
        """
        user, is_new_visitor, error_response = self.resolve_user(request)
        if error_response:
            return error_response

        if user is None:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        conversations = Conversation.objects.filter(user_id=user).prefetch_related("messages")
        serializer = ConversationSerializer(conversations, many=True)

        return Response({
            "user_id": str(user.user_id),
            "is_new": is_new_visitor,
            "conversations": serializer.data,
        }, status=status.HTTP_200_OK)

    def post(self, request):
        """
        Accepts lists of all normalized models from the frontend and stores/updates them.
        Handles both visitors and registered users.
        """
        user, is_new_visitor, error_response = self.resolve_user(request)
        if error_response:
            return error_response

        conversations_data = request.data.get("conversations", [])
        messages_data = request.data.get("messages", [])
        reqs_data = request.data.get("message_requests", [])
        resps_data = request.data.get("message_responses", [])
        outs_data = request.data.get("message_outputs", [])

        if not all(isinstance(lst, list) for lst in [conversations_data, messages_data, reqs_data, resps_data, outs_data]):
            return Response({"error": "Invalid format for one or more model lists."},
                            status=status.HTTP_400_BAD_REQUEST)

        created, updated = dict(conv=0, msg=0, req=0, resp=0, out=0), dict(conv=0, msg=0, req=0, resp=0, out=0)
        errors = {k: [] for k in ["conversations", "messages", "message_requests", "message_responses", "message_outputs"]}

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

        except Exception as e:
            logger.error(f"Transaction failed: {str(e)}")
            return Response({
                "error": "Transaction failed. No changes were applied.",
                "details": str(e),
                "errors": errors
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({
            "summary": {
                "conversations_created": created["conv"], "conversations_updated": updated["conv"],
                "messages_created": created["msg"], "messages_updated": updated["msg"],
                "requests_created": created["req"], "requests_updated": updated["req"],
                "responses_created": created["resp"], "responses_updated": updated["resp"],
                "outputs_created": created["out"], "outputs_updated": updated["out"],
            },
            "errors": errors
        }, status=status.HTTP_200_OK)

    def delete(self, request):
        """
        Purge or archive all user data, including attachments, messages, and conversations.
        - action=delete → permanently delete all user data.
        - action=archive → archive user and related data.
        """
        user, _, error_response = self.resolve_user(request)
        if error_response:
            return error_response

        action = request.data.get('action', '').lower() or request.query_params.get('action', '').lower()
        reason = request.data.get('reason') if hasattr(request, 'data') else None
        reason = reason or request.query_params.get('reason')

        attachments = Attachment.objects.filter(user_id=user)
        messages = Message.objects.filter(user_id=user)
        conversations = Conversation.objects.filter(user_id=user)
        tokens = ProviderOAuthToken.objects.filter(user=user)

        stats = {
            "attachments": attachments.count(),
            "messages": messages.count(),
            "conversations": conversations.count(),
            "tokens": tokens.count(),
            "user": 1,
        }

        if action == 'delete':
            attachments.delete()
            messages.delete()
            conversations.delete()
            tokens.delete()
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
                tokens.delete()
                logger.info(f"UnifiedSyncView: User {user.pk} archived; tokens purged.")
                return Response({"message": "User archived successfully", "archived": stats})
            else:
                logger.warning("UnifiedSyncView: Attempted to archive a None user object.")
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        return Response({"error": "Specify action=delete or action=archive in query or body."},
                        status=status.HTTP_400_BAD_REQUEST)

