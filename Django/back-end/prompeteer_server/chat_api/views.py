from django.shortcuts import render

import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Conversation
from .models import Message
from .serializers import MessageSerializer, ConversationSerializer
from .serializers import MessageRequestSerializer, MessageResponseSerializer, MessageOutputSerializer, AttachmentSerializer
from .models.attachment import Attachment
from rest_framework import viewsets, permissions
from .models.message_request import MessageRequest
from .models.message_response import MessageResponse
from .models.message_output import MessageOutput
from django.db import transaction
from django.utils import timezone

# Configure logger for this module
logger = logging.getLogger(__name__)

# Create your views here.

# how would we connect a 'visitor' 2 devices together so we can sync his conversations and messages?


class SyncConversationsView(APIView):
    """
    API endpoint for syncing conversations and messages for a registered user.
    GET: Returns all conversations with nested messages and normalized fields.
    POST: Accepts and stores/updates conversations and nested messages for the user.
    """

    def get(self, request, anon_id=None, user_id=None):
        """Return all conversations and nested messages for the resolved user."""
        logger.info("GET SyncConversationsView called with user_id=%s anon_id=%s", user_id, anon_id)
        from user_mang.models.custom_user import Custom_User
        user = None
        if anon_id:
            user = Custom_User.objects.filter(user_id=anon_id, is_visitor=True).first()
        elif user_id:
            user = Custom_User.objects.filter(user_id=user_id, is_visitor=False).first()
        if not user:
            logger.warning("User not found for anon_id=%s, user_id=%s", anon_id, user_id)
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        conversations = Conversation.objects.filter(user_id=user)
        result = []
        for conv in conversations:
            conv_data = {
                "conversation_id": str(conv.conversation_id),
                "user_id": str(user.user_id),
                "title": conv.title,
                "created_at": conv.created_at,
                "updated_at": conv.updated_at,
                "local_only": conv.local_only,
            }
            conv_messages = []
            for msg in conv.messages.all():
                msg_data = {
                    "message_id": str(msg.message_id),
                    "conversation_id": str(conv.conversation_id),
                    "user_id": str(user.user_id),
                    "request_id": str(msg.request_id.id) if msg.request_id else None,
                    "response_id": str(msg.response_id.id) if msg.response_id else None,
                    "output_id": str(msg.output_id.id) if msg.output_id else None,
                    "timestamp": msg.timestamp,
                    "vote": bool(msg.vote),
                    "has_image": bool(msg.has_image),
                    "img_Url": msg.img_Url.url if msg.img_Url else None,
                    "metadata": msg.metadata,
                    "has_embedding": bool(msg.has_embedding),
                    "has_document": bool(msg.has_document),
                    "doc_url": msg.doc_url.url if msg.doc_url else None,
                }
                if msg.request_id:
                    msg_data["request"] = MessageRequestSerializer(msg.request_id).data
                if msg.response_id:
                    msg_data["response"] = MessageResponseSerializer(msg.response_id).data
                if msg.output_id:
                    msg_data["output"] = MessageOutputSerializer(msg.output_id).data
                conv_messages.append(msg_data)
            conv_data["messages"] = conv_messages
            result.append(conv_data)

        logger.info("Returning %d conversations for user %s", len(result), user.user_id)
        return Response({"conversations": result}, status=status.HTTP_200_OK)

    def post(self, request, anon_id=None, user_id=None):
        """
        Accepts lists of all normalized models from the frontend and stores/updates them in their designated tables.
        Expects:
        {
            "conversations": [ ... ],
            "messages": [ ... ],
            "message_requests": [ ... ],
            "message_responses": [ ... ],
            "message_outputs": [ ... ]
        }
        Handles only registered users (user_id).
        """
        logger.info("POST SyncConversationsView called with user_id=%s", user_id)
        from user_mang.models.custom_user import Custom_User
        user = None
        if anon_id:
            user = Custom_User.objects.filter(user_id=anon_id, is_visitor=True).first()
        elif user_id:
            user = Custom_User.objects.filter(user_id=user_id, is_visitor=False).first()
        if not user:
            logger.warning("User not found for anon_id=%s, user_id=%s", anon_id, user_id)
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        conversations_data = request.data.get("conversations", [])
        messages_data = request.data.get("messages", [])
        message_requests_data = request.data.get("message_requests", [])
        message_responses_data = request.data.get("message_responses", [])
        message_outputs_data = request.data.get("message_outputs", [])

        if not isinstance(conversations_data, list) or not isinstance(messages_data, list) or not isinstance(message_requests_data, list) or not isinstance(message_responses_data, list) or not isinstance(message_outputs_data, list):
            logger.error("Invalid format for one or more model lists.")
            return Response({"error": "Invalid format for one or more model lists."}, status=status.HTTP_400_BAD_REQUEST)

        created, updated = 0, 0
        msg_created, msg_updated = 0, 0
        req_created, req_updated = 0, 0
        res_created, res_updated = 0, 0
        out_created, out_updated = 0, 0

        errors = {
            "conversations": [],
            "message_requests": [],
            "message_responses": [],
            "message_outputs": [],
            "messages": []
        }

        try:
            with transaction.atomic():
                # Store conversations
                for conv_data in conversations_data:
                    conv_id = conv_data.get("conversation_id") or conv_data.get("id")
                    if not conv_id:
                        error_msg = f"Missing 'id'"
                        logger.warning(f"Conversation {conv_data} failed: {error_msg}")
                        errors["conversations"].append({"data": conv_data, "error": error_msg})
                        continue
                    defaults = {
                        "user_id": user,
                        "title": conv_data.get("title"),
                        "local_only": bool(conv_data.get("local_only", False)),
                    }
                    conv, created_flag = Conversation.objects.update_or_create(
                        conversation_id=conv_id,
                        defaults=defaults
                    )
                    if created_flag:
                        created += 1
                    else:
                        updated += 1

                # Store message_requests
                for req_data in message_requests_data:
                    req_id = req_data.get("id")
                    if not req_id:
                        error_msg = f"Missing 'id'"
                        logger.warning(f"MessageRequest {req_data} failed: {error_msg}")
                        errors["message_requests"].append({"data": req_data, "error": error_msg})
                        continue
                    req_serializer = MessageRequestSerializer(data=req_data)
                    if req_serializer.is_valid():
                        req_obj, created_flag = MessageRequest.objects.update_or_create(
                            id=req_id,
                            defaults=req_serializer.validated_data
                        )
                        if created_flag:
                            req_created += 1
                        else:
                            req_updated += 1
                    else:
                        error_msg = str(req_serializer.errors)
                        logger.error(f"MessageRequest {req_data} failed: {error_msg}")
                        errors["message_requests"].append({"data": req_data, "error": error_msg})

                # Store message_responses
                for res_data in message_responses_data:
                    res_id = res_data.get("id")
                    if not res_id:
                        error_msg = f"Missing 'id'"
                        logger.warning(f"MessageResponse {res_data} failed: {error_msg}")
                        errors["message_responses"].append({"data": res_data, "error": error_msg})
                        continue
                    res_serializer = MessageResponseSerializer(data=res_data)
                    if res_serializer.is_valid():
                        res_obj, created_flag = MessageResponse.objects.update_or_create(
                            id=res_id,
                            defaults=res_serializer.validated_data
                        )
                        if created_flag:
                            res_created += 1
                        else:
                            res_updated += 1
                    else:
                        error_msg = str(res_serializer.errors)
                        logger.error(f"MessageResponse {res_data} failed: {error_msg}")
                        errors["message_responses"].append({"data": res_data, "error": error_msg})

                # Store message_outputs
                for out_data in message_outputs_data:
                    out_id = out_data.get("id")
                    if not out_id:
                        error_msg = f"Missing 'id'"
                        logger.warning(f"MessageOutput {out_data} failed: {error_msg}")
                        errors["message_outputs"].append({"data": out_data, "error": error_msg})
                        continue
                    out_serializer = MessageOutputSerializer(data=out_data)
                    if out_serializer.is_valid():
                        out_obj, created_flag = MessageOutput.objects.update_or_create(
                            id=out_id,
                            defaults=out_serializer.validated_data
                        )
                        if created_flag:
                            out_created += 1
                        else:
                            out_updated += 1
                    else:
                        error_msg = str(out_serializer.errors)
                        logger.error(f"MessageOutput {out_data} failed: {error_msg}")
                        errors["message_outputs"].append({"data": out_data, "error": error_msg})

                # Store messages
                for msg_data in messages_data:
                    msg_id = msg_data.get("message_id")
                    if not msg_id:
                        error_msg = f"Missing 'message_id'"
                        logger.warning(f"Message {msg_data} failed: {error_msg}")
                        errors["messages"].append({"data": msg_data, "error": error_msg})
                        continue
                    conv_ref = msg_data.get("conversation_id") or msg_data.get("conversation")
                    conv_obj = None
                    if conv_ref:
                        conv_obj = Conversation.objects.filter(conversation_id=conv_ref, user_id=user).first()
                        if not conv_obj:
                            error_msg = f"Conversation {conv_ref} not found for user {user.user_id}"
                            logger.warning(f"Message {msg_data} failed: {error_msg}")
                            errors["messages"].append({"data": msg_data, "error": error_msg})
                            continue
                    # Resolve normalized refs
                    def _resolve(model_cls, ref):
                        if not ref:
                            return None
                        return model_cls.objects.filter(id=ref).first()
                    req_obj = _resolve(MessageRequest, msg_data.get("request_id") or msg_data.get("request"))
                    res_obj = _resolve(MessageResponse, msg_data.get("response_id") or msg_data.get("response"))
                    out_obj = _resolve(MessageOutput, msg_data.get("output_id") or msg_data.get("output"))

                    defaults = {
                        "user_id": user,
                        "conversation_id": conv_obj,
                        "request_id": req_obj,
                        "response_id": res_obj,
                        "output_id": out_obj,
                        "vote": bool(msg_data.get("vote", False)),
                        "has_image": bool(msg_data.get("has_image", False)),
                        "metadata": msg_data.get("metadata"),
                        "has_embedding": bool(msg_data.get("has_embedding", False)),
                        "has_document": bool(msg_data.get("has_document", False)),
                    }
                    msg_obj, created_flag = Message.objects.update_or_create(
                        message_id=msg_id,
                        defaults=defaults
                    )
                    if created_flag:
                        msg_created += 1
                    else:
                        msg_updated += 1

        except Exception as e:
            logger.error(f"Transaction failed: {str(e)}")
            return Response({
                "error": "Transaction failed. No changes were applied.",
                "details": str(e),
                "errors": errors
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        logger.info("POST SyncConversationsView: %d conversations created, %d updated. %d messages created, %d updated. %d requests created, %d updated. %d responses created, %d updated. %d outputs created, %d updated.", created, updated, msg_created, msg_updated, req_created, req_updated, res_created, res_updated, out_created, out_updated)
        return Response({
            "message": f"{created} conversations created, {updated} updated. {msg_created} messages created, {msg_updated} updated. {req_created} requests created, {req_updated} updated. {res_created} responses created, {res_updated} updated. {out_created} outputs created, {out_updated} updated.",
            "conversations_created": created,
            "conversations_updated": updated,
            "messages_created": msg_created,
            "messages_updated": msg_updated,
            "requests_created": req_created,
            "requests_updated": req_updated,
            "responses_created": res_created,
            "responses_updated": res_updated,
            "outputs_created": out_created,
            "outputs_updated": out_updated,
            "errors": errors
        }, status=status.HTTP_200_OK)

class AssociateDeviceView(APIView):
    """
    API endpoint to associate a device with a visitor or user (by user_id or temp_id).
    """


class AttachmentViewSet(viewsets.ModelViewSet):
    """CRUD + filtered listing of encrypted (or plaintext) attachments.

    Typical client flow (phase 0 encryption):
    1. Client encrypts file locally with UMK, uploads ciphertext path reference.
    2. Server stores metadata only; does not decrypt.
    3. Client fetches metadata + encrypted bytes later and decrypts locally.
    """
    serializer_class = AttachmentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = Attachment.objects.filter(user=self.request.user)
        conv_id = self.request.query_params.get('conversation_id')
        msg_id = self.request.query_params.get('message_id')
        if conv_id:
            qs = qs.filter(conversation__conversation_id=conv_id)
        if msg_id:
            qs = qs.filter(message__message_id=msg_id)
        return qs.order_by('-created_at')

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
    # AttachmentViewSet end
    def post(self, request, anon_id=None, user_id=None):
        logger.info("POST AssociateDeviceView called")
        provided_user_id = request.data.get("user_id")
        temp_id = request.data.get("temp_id")
        device_id = request.data.get("device_id")

        if not device_id or (not provided_user_id and not temp_id):
            logger.warning("user_id/temp_id or device_id missing in request: user_id=%s, temp_id=%s, device_id=%s", provided_user_id, temp_id, device_id)
            return Response({"error": "user_id or temp_id and device_id are required"}, status=status.HTTP_400_BAD_REQUEST)

        target = None
        from user_mang.models.custom_user import Custom_User
        if provided_user_id:
            target = Custom_User.objects.filter(user_id=provided_user_id).first()
        elif temp_id:
            target = Custom_User.objects.filter(temp_id=temp_id).first()
        if not target:
            logger.warning("User not found for user_id=%s, temp_id=%s", provided_user_id, temp_id)
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Normalize related_devices to list
        try:
            devices = target.related_devices if isinstance(target.related_devices, list) else []
        except Exception:
            import json
            try:
                devices = json.loads(target.related_devices or "[]")
            except Exception:
                devices = []
        if device_id not in devices:
            devices.append(device_id)
            try:
                target.related_devices = devices
            except Exception:
                import json
                target.related_devices = json.dumps(devices)
            target.device_id = device_id
            target.save()
            logger.info("Device %s associated with user %s", device_id, target.user_id)
        else:
            logger.info("Device %s already associated with user %s", device_id, target.user_id)

        return Response({"message": "Device associated successfully"}, status=status.HTTP_200_OK)


class SyncOrRegisterVisitorView(APIView):
    """
    New endpoint that accepts only device information and a temp_id from the client.
    Flow:
      - Client sends { temp_id, device_id }
      - If a Custom_User with this temp_id exists: treat as same visitor on a new device
          - Ensure device_id is recorded in related_devices
          - Aggregate conversations/messages for that user and return them
      - Else: create a new Custom_User with is_visitor=True and temp_id, attach device
          - Return the generated user_id (server UUID) and empty data
    This avoids requiring two columns (anon_id/user_id) on first contact.
    """

    def post(self, request):
        from user_mang.models.custom_user import Custom_User
        temp_id = (request.data.get("temp_id") or "").strip()
        device_id = (request.data.get("device_id") or "").strip()
        if not temp_id or not device_id:
            return Response({"error": "temp_id and device_id are required"}, status=status.HTTP_400_BAD_REQUEST)

        user = Custom_User.objects.filter(temp_id=temp_id).first()
        created_user = False
        if not user:
            # New visitor
            user = Custom_User(
                username=f"visitor_{temp_id[:8]}",
                email=f"{temp_id}@visitor.local",
                is_visitor=True,
                temp_id=temp_id,
            )
            # Bypass strict validation for email/password at this stage
            try:
                user.full_clean(exclude=["user_password"])  # allow missing password
            except Exception:
                pass
            user.save()
            created_user = True

        # Ensure device is recorded
        try:
            devices = user.related_devices if isinstance(user.related_devices, list) else []
        except Exception:
            # related_devices stored as text JSON
            import json
            try:
                devices = json.loads(user.related_devices or "[]")
            except Exception:
                devices = []
        if device_id not in devices:
            devices.append(device_id)
            try:
                user.related_devices = devices
            except Exception:
                import json
                user.related_devices = json.dumps(devices)
            user.device_id = device_id  # keep legacy field updated with last seen device
            user.last_login = timezone.now()
            user.save()

        # Gather data if existing visitor
        conversations = []
        if not created_user:
            for conv in Conversation.objects.filter(user_id=user):
                conv_data = {
                    "conversation_id": str(conv.conversation_id),
                    "user_id": str(user.user_id),
                    "title": conv.title,
                    "created_at": conv.created_at,
                    "updated_at": conv.updated_at,
                    "local_only": conv.local_only,
                }
                msgs = []
                for msg in conv.messages.all():
                    msg_data = {
                        "message_id": str(msg.message_id),
                        "conversation_id": str(conv.conversation_id),
                        "user_id": str(user.user_id),
                        "request_id": str(msg.request_id.id) if msg.request_id else None,
                        "response_id": str(msg.response_id.id) if msg.response_id else None,
                        "output_id": str(msg.output_id.id) if msg.output_id else None,
                        "timestamp": msg.timestamp,
                        "vote": bool(msg.vote),
                        "has_image": bool(msg.has_image),
                        "img_Url": msg.img_Url.url if msg.img_Url else None,
                        "metadata": msg.metadata,
                        "has_embedding": bool(msg.has_embedding),
                        "has_document": bool(msg.has_document),
                        "doc_url": msg.doc_url.url if msg.doc_url else None,
                    }
                    if msg.request_id:
                        msg_data["request"] = MessageRequestSerializer(msg.request_id).data
                    if msg.response_id:
                        msg_data["response"] = MessageResponseSerializer(msg.response_id).data
                    if msg.output_id:
                        msg_data["output"] = MessageOutputSerializer(msg.output_id).data
                    msgs.append(msg_data)
                conv_data["messages"] = msgs
                conversations.append(conv_data)

        return Response({
            "user_id": str(user.user_id),
            "is_new": created_user,
            "conversations": conversations,
        }, status=status.HTTP_200_OK)
