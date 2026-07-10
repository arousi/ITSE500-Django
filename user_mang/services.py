"""Synchronous domain logic for the django-bolt port of user_mang (and the
login/register first-sync payloads in auth_api).

These functions replace the DRF serializers/views 1:1 and run blocking ORM code;
Bolt handlers call them through asgiref.sync.sync_to_async. Output dicts keep the
exact JSON keys the DRF serializers declared (e.g. `request_use_structured_output`,
which maps to the model field `request_user_structured_output`).

All values are JSON-native (str/int/bool/None/dict/list): UUIDs and datetimes are
stringified here so the Bolt/msgspec encoder never sees ORM objects.
"""
from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
import shutil
import tempfile
import zipfile
from typing import Any, Optional

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from auth_api.models import ProviderOAuthToken
from chat_api.models.attachment import Attachment
from chat_api.models.conversation import Conversation
from chat_api.models.message import Message
from chat_api.models.message_output import MessageOutput
from chat_api.models.message_request import MessageRequest
from chat_api.models.message_response import MessageResponse
from user_mang.models.custom_user import Custom_User

logger = logging.getLogger("user_mang")


# --------------------------------------------------------------------------
# Primitives
# --------------------------------------------------------------------------

def _dt(value) -> Optional[str]:
    if value is None:
        return None
    try:
        return value.isoformat().replace("+00:00", "Z")
    except Exception:
        return str(value)


def _file_url(f) -> Optional[str]:
    try:
        return f.url if f else None
    except Exception:
        return None


def _s(value) -> Optional[str]:
    return None if value is None else str(value)


# --------------------------------------------------------------------------
# Serializers (dict builders matching the DRF serializer output shapes)
# --------------------------------------------------------------------------

def ser_message_request(obj: Optional[MessageRequest]) -> Optional[dict]:
    if obj is None:
        return None
    return {
        "request_id": _s(obj.request_id),
        "request_model": obj.request_model,
        "request_input": obj.request_input,
        "request_system_role": obj.request_system_role,
        "request_system_content": obj.request_system_content,
        "request_system_prompt": obj.request_system_prompt,
        # Declared API key; model field is request_user_structured_output
        "request_use_structured_output": obj.request_user_structured_output,
        "request_structured_schema": obj.request_structured_schema,
        "request_user_role": obj.request_user_role,
        "request_user_content": obj.request_user_content,
        "request_min_p": obj.request_min_p,
        "request_temperature": obj.request_temperature,
        "request_top_p": obj.request_top_p,
        "request_n": obj.request_n,
        "request_top_k": obj.request_top_k,
        "request_stream": obj.request_stream,
        "request_stop": obj.request_stop,
        "request_max_tokens": obj.request_max_tokens,
        "repeat_penalty": obj.repeat_penalty,
    }


def ser_message_response(obj: Optional[MessageResponse]) -> Optional[dict]:
    if obj is None:
        return None
    return {
        "response_id": obj.response_id,
        "object": obj.object,
        "created_at": _dt(obj.created_at),
        "status": obj.status,
        "error": obj.error,
        "model_name": obj.model_name,
        "parallel_tool_calls": obj.parallel_tool_calls,
        "previous_response_id": obj.previous_response_id,
        "instructions": obj.instructions,
        "reasoning_effort": obj.reasoning_effort,
        "reasoning_summary": obj.reasoning_summary,
        "store": obj.store,
        "temperature": obj.temperature,
        "text_format_type": obj.text_format_type,
        "tool_choice": obj.tool_choice,
        "tools": obj.tools,
        "top_p": obj.top_p,
        "truncation": obj.truncation,
        "usage_input_tokens": obj.usage_input_tokens,
        "usage_output_tokens": obj.usage_output_tokens,
        "usage_total_tokens": obj.usage_total_tokens,
        "user": obj.user,
        "metadata": obj.metadata,
        "incomplete_details": obj.incomplete_details,
        "max_output_tokens": obj.max_output_tokens,
    }


def ser_message_output(obj: Optional[MessageOutput]) -> Optional[dict]:
    if obj is None:
        return None
    return {
        "id": obj.id,
        "output_type": obj.output_type,
        "output_id": obj.output_id,
        "output_status": obj.output_status,
        "output_role": obj.output_role,
        "output_content_type": obj.output_content_type,
        "output_content_text": obj.output_content_text,
        "output_content_annotations": obj.output_content_annotations,
    }


def ser_message(msg: Message, nested: bool = True) -> dict:
    data = {
        "message_id": _s(msg.message_id),
        "user_id": _s(msg.user_id_id),
        "conversation_id": _s(msg.conversation_id_id),
        "request_id": _s(msg.request_id_id),
        "response_id": msg.response_id_id,
        "output_id": msg.output_id_id,
        "timestamp": _dt(msg.timestamp),
        "vote": msg.vote,
        "has_image": msg.has_image,
        "img_Url": _file_url(msg.img_Url),
        "metadata": msg.metadata,
        "has_embedding": msg.has_embedding,
        "has_document": msg.has_document,
        "doc_url": _file_url(msg.doc_url),
    }
    if nested:
        data["request"] = ser_message_request(msg.request_id)
        data["response"] = ser_message_response(msg.response_id)
        data["output"] = ser_message_output(msg.output_id)
    return data


def ser_conversation(conv: Conversation) -> dict:
    return {
        "conversation_id": _s(conv.conversation_id),
        "user_id": _s(conv.user_id_id),
        "title": conv.title,
        "created_at": _dt(conv.created_at),
        "updated_at": _dt(conv.updated_at),
        "local_only": conv.local_only,
        "messages": [ser_message(m) for m in conv.messages.all()],
    }


def ser_attachment(att: Attachment) -> dict:
    msg = att.message_id
    return {
        "id": _s(att.attachment_id),
        "attachment_id": _s(att.attachment_id),
        "user_id": _s(getattr(msg, "user_id_id", None)),
        "conversation_id": _s(getattr(msg, "conversation_id_id", None)),
        "message_id": _s(att.message_id_id),
        "type": att.type,
        "mime_type": att.mime_type,
        "file_path": att.file_path,
        "encrypted_blob": _file_url(att.encrypted_blob),
        "size_bytes": att.size_bytes,
        "width": att.width,
        "height": att.height,
        "sha256": att.sha256,
        "is_encrypted": att.is_encrypted,
        "enc_algo": att.enc_algo,
        "iv_base64": att.iv_base64,
        "key_ref": att.key_ref,
        "created_at": _dt(att.created_at),
    }


def build_profile_payload(user: Custom_User) -> dict:
    """FullProfileSerializer read shape (user_password is write-only)."""
    return {
        "user_id": _s(user.user_id),
        "username": user.username,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email,
        "phone_number": user.phone_number,
        "last_modified": _dt(user.last_modified),
        "devices_id": user.devices_id,
        "temp_id": user.temp_id,
        "related_devices": user.get_related_devices(),
        "email_pin_created": _dt(user.email_pin_created),
        "email_verified": user.email_verified,
        "is_archived": user.is_archived,
        "is_google_user": user.is_google_user,
        "is_openrouter_user": user.is_openrouter_user,
        "is_microsoft_user": user.is_microsoft_user,
        "is_github_user": user.is_github_user,
        "is_active": user.is_active,
        "is_staff": user.is_staff,
    }


def _chat_querysets(user: Custom_User):
    conversations = Conversation.objects.filter(user_id=user).prefetch_related("messages")
    messages = Message.objects.filter(user_id=user).select_related(
        "request_id", "response_id", "output_id", "conversation_id"
    )
    request_ids = list(messages.exclude(request_id__isnull=True).values_list("request_id", flat=True))
    response_ids = list(messages.exclude(response_id__isnull=True).values_list("response_id", flat=True))
    output_ids = list(messages.exclude(output_id__isnull=True).values_list("output_id", flat=True))
    message_requests = MessageRequest.objects.filter(request_id__in=request_ids) if request_ids else MessageRequest.objects.none()
    message_responses = MessageResponse.objects.filter(response_id__in=response_ids) if response_ids else MessageResponse.objects.none()
    message_outputs = MessageOutput.objects.filter(output_id__in=output_ids) if output_ids else MessageOutput.objects.none()
    attachments = Attachment.objects.filter(message_id__user_id=user).select_related("message_id")
    return conversations, messages, message_requests, message_responses, message_outputs, attachments


def build_chat_payload(user: Custom_User) -> dict:
    """FullChatSerializer shape: nested conversations + flat lists + attachments."""
    conversations, messages, reqs, resps, outs, attachments = _chat_querysets(user)
    return {
        "conversations": [ser_conversation(c) for c in conversations],
        "messages": [ser_message(m) for m in messages],
        "message_request": [ser_message_request(r) for r in reqs],
        "message_response": [ser_message_response(r) for r in resps],
        "message_output": [ser_message_output(o) for o in outs],
        "attachments": [ser_attachment(a) for a in attachments],
    }


def build_login_sync_payload(user: Custom_User) -> tuple[list, list]:
    """LoginView's first-sync payload: (conversations, attachments)."""
    conversations = Conversation.objects.filter(user_id=user).prefetch_related("messages")
    attachments = Attachment.objects.filter(message_id__user_id=user).select_related("message_id")
    return [ser_conversation(c) for c in conversations], [ser_attachment(a) for a in attachments]


def build_register_conversations(user: Custom_User) -> list:
    """RegisterView's flat first-sync shape (messages without nested request/response/output)."""
    result = []
    for conv in Conversation.objects.filter(user_id=user).prefetch_related("messages"):
        conv_data = ser_conversation(conv)
        for m in conv_data["messages"]:
            m.pop("request", None)
            m.pop("response", None)
            m.pop("output", None)
        result.append(conv_data)
    return result


# --------------------------------------------------------------------------
# Visitor / device / user resolution (UnifiedSyncView.resolve_user port)
# --------------------------------------------------------------------------

def create_visitor(temp_id: str) -> Custom_User:
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


def associate_device(user: Custom_User, device_id: str) -> None:
    devices = user.get_related_devices()
    if device_id not in devices:
        devices.append(device_id)
        user.set_related_devices(devices)
        user.device_id = device_id
        user.last_login = timezone.now()
        user.save()


def resolve_user(auth_user_id: Optional[str], method: str, params: dict) -> tuple:
    """Port of UnifiedSyncView.resolve_user.

    Returns (user, is_new_visitor, error(status, payload) | None, temp_id).
    """
    temp_id = params.get("temp_id")
    device_id = params.get("device_id")

    if auth_user_id:
        user = Custom_User.objects.filter(pk=auth_user_id).first()
        if user is None:
            return None, False, (401, {"error": "Authentication required"}), temp_id
        if temp_id and (not user.temp_id or user.temp_id != temp_id):
            user.temp_id = temp_id
            try:
                user.save(update_fields=["temp_id"])
            except Exception:
                user.save()
        if device_id:
            associate_device(user, device_id)
        return user, False, None, temp_id

    if temp_id:
        user = Custom_User.objects.filter(temp_id=temp_id).first()
        is_new = False
        if not user:
            user = create_visitor(temp_id)
            is_new = True
        if device_id:
            associate_device(user, device_id)
        return user, is_new, None, temp_id

    user_id = params.get("user_id")
    allow_public_uuid = params.get("allow_public_uuid") in (True, "true")
    if method == "GET" and allow_public_uuid and user_id:
        user = Custom_User.objects.filter(user_id=user_id).first()
        if not user:
            return None, False, (404, {"error": "User not found"}), None
        # Never expose profile/chat on the unauthenticated public-UUID path.
        return None, False, (200, {"exists": True, "is_visitor": bool(user.is_visitor)}), None

    return None, False, (401, {"error": "Authentication required"}), temp_id


# --------------------------------------------------------------------------
# Profile updates
# --------------------------------------------------------------------------

def _unique_check(user: Custom_User, field: str, value: str) -> bool:
    qs = Custom_User.objects.filter(**{f"{field}__iexact": value})
    if user is not None and user.pk:
        qs = qs.exclude(pk=user.pk)
    return not qs.exists()


def update_profile_safe(user: Custom_User, data: dict) -> tuple[bool, dict]:
    """ProfileSerializer port: whitelisted partial update. Returns (ok, payload|errors)."""
    errors: dict[str, list] = {}
    if data.get("email"):
        if not _unique_check(user, "email", data["email"]):
            errors["email"] = ["This email is already in use."]
    if data.get("username"):
        if not _unique_check(user, "username", data["username"]):
            errors["username"] = ["This username is already in use."]
    if errors:
        return False, errors
    allowed = ["username", "email", "phone_number", "biometric_enabled"]
    update_fields = []
    for key in allowed:
        if key in data:
            setattr(user, key, data[key])
            update_fields.append(key)
    if update_fields:
        try:
            user.save(update_fields=update_fields)
        except Exception:
            user.save()
    return True, {
        "user_id": _s(user.user_id),
        "username": user.username,
        "email": user.email,
        "phone_number": user.phone_number,
        "biometric_enabled": user.biometric_enabled,
    }


def update_profile_full(user: Custom_User, data: dict) -> tuple[bool, dict]:
    """FullProfileSerializer port (partial update). Returns (ok, errors)."""
    errors: dict[str, list] = {}
    pwd = data.get("user_password")
    if isinstance(pwd, str) and pwd.strip() == "":
        pwd = None
    is_visitor = data.get("is_visitor", getattr(user, "is_visitor", False))
    is_oauth = any(
        data.get(flag, getattr(user, flag, False))
        for flag in ("is_google_user", "is_openrouter_user", "is_microsoft_user", "is_github_user")
    )
    if pwd is not None and not (is_visitor or is_oauth) and len(str(pwd)) < 6:
        errors["user_password"] = ["Password must be at least 6 characters long."]
    if data.get("email") and not _unique_check(user, "email", data["email"]):
        errors["email"] = ["This email is already in use."]
    if data.get("username") and not _unique_check(user, "username", data["username"]):
        errors["username"] = ["This username is already in use."]
    if errors:
        return False, errors

    update_fields = []
    if pwd is not None:
        backend_salt = getattr(settings, "BACKEND_PASSWORD_SALT", "fallback_dev_salt")
        user.user_password = hashlib.sha256((str(pwd) + backend_salt).encode("utf-8")).hexdigest()
        update_fields.append("user_password")

    allowed = [
        "username", "email", "phone_number", "biometric_enabled",
        "first_name", "last_name", "devices_id", "temp_id", "related_devices",
        "email_pin", "email_pin_created", "email_verified", "is_archived",
        "login_otp", "login_otp_created", "login_otp_sent_count", "login_otp_last_sent",
        "is_google_user", "is_openrouter_user", "is_microsoft_user", "is_github_user",
        "is_active", "is_staff",
    ]
    for key in allowed:
        if key in data:
            setattr(user, key, data[key])
            update_fields.append(key)
    if update_fields:
        try:
            user.save(update_fields=update_fields)
        except Exception:
            user.save()
    return True, {}


# --------------------------------------------------------------------------
# Chat upsert (UnifiedSyncView.post port — transaction + IDOR guards)
# --------------------------------------------------------------------------

_ATTACHMENT_TYPES = {"image", "embedding", "pdf", "other"}


def _linked_owner_pk(obj):
    """Owner pk of the Message linked (reverse O2O 'message') to a
    request/response/output row, or None when unlinked (caller may claim it)."""
    try:
        return obj.message.user_id_id
    except Exception:
        return None


def _apply_fields(instance, data: dict, fields: list[str]) -> None:
    for f in fields:
        if f in data:
            setattr(instance, f, data[f])


def upsert_chat(user: Custom_User, data: dict) -> tuple[Optional[dict], Optional[dict], Optional[str]]:
    """Returns (summary, errors, fatal_error). On fatal_error the transaction rolled back."""
    conversations_data = data.get("conversations", [])
    messages_data = data.get("messages", [])
    reqs_data = data.get("message_requests", [])
    resps_data = data.get("message_responses", [])
    outs_data = data.get("message_outputs", [])
    attachments_data = data.get("attachments", [])

    if not all(isinstance(lst, list) for lst in [conversations_data, messages_data, reqs_data, resps_data, outs_data, attachments_data]):
        return None, None, "Invalid format for one or more model lists."

    created = dict(conv=0, msg=0, req=0, resp=0, out=0, att=0)
    updated = dict(conv=0, msg=0, req=0, resp=0, out=0, att=0)
    errors: dict[str, list] = {k: [] for k in [
        "conversations", "messages", "message_requests", "message_responses", "message_outputs", "attachments"
    ]}

    REQ_FIELDS = [
        "request_model", "request_input", "request_system_role", "request_system_content",
        "request_system_prompt", "request_structured_schema", "request_user_role",
        "request_user_content", "request_min_p", "request_temperature", "request_top_p",
        "request_n", "request_top_k", "request_stream", "request_stop", "request_max_tokens",
        "repeat_penalty",
    ]
    RESP_FIELDS = [
        "object", "created_at", "status", "error", "model_name", "parallel_tool_calls",
        "previous_response_id", "instructions", "reasoning_effort", "reasoning_summary",
        "store", "temperature", "text_format_type", "tool_choice", "tools", "top_p",
        "truncation", "usage_input_tokens", "usage_output_tokens", "usage_total_tokens",
        "metadata", "incomplete_details", "max_output_tokens",
    ]
    OUT_FIELDS = [
        "output_type", "output_id", "output_status", "output_role",
        "output_content_type", "output_content_text", "output_content_annotations",
    ]
    MSG_FIELDS = ["vote", "has_image", "metadata", "has_embedding", "has_document"]
    ATT_FIELDS = [
        "type", "mime_type", "file_path", "size_bytes", "width", "height", "sha256",
        "is_encrypted", "enc_algo", "iv_base64", "key_ref",
    ]

    try:
        with transaction.atomic():
            # Conversations
            for conv in conversations_data:
                conv_id = conv.get("conversation_id") or conv.get("id")
                if not conv_id:
                    errors["conversations"].append({"data": conv, "error": "Missing conversation_id"})
                    continue
                # IDOR guard: an id owned by another user must never be upserted by this caller.
                if Conversation.objects.filter(conversation_id=conv_id).exclude(user_id=user).exists():
                    errors["conversations"].append({"data": conv, "error": "Conversation not found or not owned by this user"})
                    continue
                instance = Conversation.objects.filter(conversation_id=conv_id, user_id=user).first()
                if instance is None:
                    instance = Conversation(conversation_id=conv_id, user_id=user)
                    _apply_fields(instance, conv, ["title", "local_only"])
                    instance.save()
                    created["conv"] += 1
                else:
                    _apply_fields(instance, conv, ["title", "local_only"])
                    instance.save()
                    updated["conv"] += 1

            # Requests
            for req in reqs_data:
                req_id = req.get("request_id")
                if not req_id:
                    errors["message_requests"].append({"data": req, "error": "Missing id"})
                    continue
                instance = MessageRequest.objects.filter(request_id=req_id).first()
                if instance is not None and _linked_owner_pk(instance) not in (None, user.pk):
                    errors["message_requests"].append({"data": req, "error": "Not found or not owned by this user"})
                    continue
                is_create = instance is None
                if is_create:
                    instance = MessageRequest(request_id=req_id)
                _apply_fields(instance, req, REQ_FIELDS)
                # API alias -> model field
                if "request_use_structured_output" in req:
                    instance.request_user_structured_output = req["request_use_structured_output"]
                elif "request_user_structured_output" in req:
                    instance.request_user_structured_output = req["request_user_structured_output"]
                instance.save()
                (created if is_create else updated)["req"] += 1

            # Responses
            for resp in resps_data:
                resp_id = resp.get("response_id")
                if not resp_id:
                    errors["message_responses"].append({"data": resp, "error": "Missing id"})
                    continue
                instance = MessageResponse.objects.filter(response_id=resp_id).first()
                if instance is not None and _linked_owner_pk(instance) not in (None, user.pk):
                    errors["message_responses"].append({"data": resp, "error": "Not found or not owned by this user"})
                    continue
                is_create = instance is None
                if is_create:
                    instance = MessageResponse(response_id=resp_id)
                _apply_fields(instance, resp, RESP_FIELDS)
                instance.save()
                (created if is_create else updated)["resp"] += 1

            # Outputs
            for out in outs_data:
                out_id = out.get("output_id")
                if not out_id:
                    errors["message_outputs"].append({"data": out, "error": "Missing id"})
                    continue
                instance = MessageOutput.objects.filter(output_id=out_id).first()
                if instance is not None and _linked_owner_pk(instance) not in (None, user.pk):
                    errors["message_outputs"].append({"data": out, "error": "Not found or not owned by this user"})
                    continue
                is_create = instance is None
                if is_create:
                    instance = MessageOutput()
                _apply_fields(instance, out, OUT_FIELDS)
                instance.save()
                (created if is_create else updated)["out"] += 1

            # Messages
            for msg in messages_data:
                msg_id = msg.get("message_id")
                if not msg_id:
                    errors["messages"].append({"data": msg, "error": "Missing message_id"})
                    continue
                # IDOR guards: no attaching into someone else's conversation; no
                # claiming someone else's message_id.
                _conv_ref = msg.get("conversation_id")
                if _conv_ref and not Conversation.objects.filter(conversation_id=_conv_ref, user_id=user).exists():
                    errors["messages"].append({"data": msg, "error": "conversation_id not found or not owned by this user"})
                    continue
                if Message.objects.filter(message_id=msg_id).exclude(user_id=user).exists():
                    errors["messages"].append({"data": msg, "error": "Message not found or not owned by this user"})
                    continue
                # FK existence checks (DRF PrimaryKeyRelatedField parity)
                fk_error = None
                for key, model in (("request_id", MessageRequest), ("response_id", MessageResponse), ("output_id", MessageOutput)):
                    ref = msg.get(key)
                    if ref is not None and not model.objects.filter(pk=ref).exists():
                        fk_error = f"{key} does not exist"
                        break
                if fk_error:
                    errors["messages"].append({"data": msg, "error": fk_error})
                    continue
                instance = Message.objects.filter(message_id=msg_id, user_id=user).first()
                is_create = instance is None
                if is_create:
                    instance = Message(message_id=msg_id, user_id=user)
                _apply_fields(instance, msg, MSG_FIELDS)
                if _conv_ref:
                    instance.conversation_id_id = _conv_ref
                for key in ("request_id", "response_id", "output_id"):
                    if key in msg:
                        setattr(instance, f"{key}_id", msg[key])
                instance.save()
                (created if is_create else updated)["msg"] += 1

            # Attachments
            for att in attachments_data:
                att_id = att.get("id") or att.get("attachment_id")
                if not att_id:
                    errors["attachments"].append({"data": att, "error": "Missing id"})
                    continue
                _msg_ref = att.get("message_id")
                if _msg_ref and not Message.objects.filter(message_id=_msg_ref, user_id=user).exists():
                    errors["attachments"].append({"data": att, "error": "message_id not found or not owned by this user"})
                    continue
                if Attachment.objects.filter(pk=att_id).exclude(message_id__user_id=user).exists():
                    errors["attachments"].append({"data": att, "error": "Attachment not found or not owned by this user"})
                    continue
                a_type = att.get("type")
                if a_type and a_type not in _ATTACHMENT_TYPES:
                    errors["attachments"].append({"data": att, "error": f"type must be one of {sorted(_ATTACHMENT_TYPES)}"})
                    continue
                instance = Attachment.objects.filter(pk=att_id, message_id__user_id=user).first()
                is_create = instance is None
                if is_create:
                    if not _msg_ref:
                        errors["attachments"].append({"data": att, "error": "message_id is required"})
                        continue
                    instance = Attachment(attachment_id=att_id, message_id_id=_msg_ref)
                elif _msg_ref:
                    instance.message_id_id = _msg_ref
                _apply_fields(instance, att, ATT_FIELDS)
                instance.save()
                (created if is_create else updated)["att"] += 1

    except Exception as e:
        logger.error("Transaction failed", exc_info=True)
        return None, errors, str(e)

    summary = {
        "conversations_created": created["conv"], "conversations_updated": updated["conv"],
        "messages_created": created["msg"], "messages_updated": updated["msg"],
        "requests_created": created["req"], "requests_updated": updated["req"],
        "responses_created": created["resp"], "responses_updated": updated["resp"],
        "outputs_created": created["out"], "outputs_updated": updated["out"],
        "attachments_created": created["att"], "attachments_updated": updated["att"],
    }
    return summary, errors, None


# --------------------------------------------------------------------------
# Exports + delete/archive (UnifiedSyncView.delete port)
# --------------------------------------------------------------------------

def export_user_data_csv(user: Custom_User) -> str:
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".csv", mode="w", newline="", encoding="utf-8")
    writer = csv.writer(tmp)
    writer.writerow(["Section", "Field", "Value"])
    writer.writerow(["Profile", "user_id", user.user_id])
    writer.writerow(["Profile", "username", user.username])
    writer.writerow(["Profile", "email", user.email])
    writer.writerow(["Profile", "is_visitor", user.is_visitor])
    writer.writerow(["Profile", "is_active", user.is_active])
    writer.writerow(["Profile", "is_archived", user.is_archived])
    writer.writerow([])
    writer.writerow(["Section", "conversation_id", "title"])
    for conv in Conversation.objects.filter(user_id=user):
        writer.writerow(["Conversation", conv.conversation_id, conv.title])
    writer.writerow([])
    writer.writerow(["Section", "id", "type", "file_path"])
    for att in Attachment.objects.filter(message_id__user_id=user):
        writer.writerow(["Attachment", att.attachment_id, att.type, att.file_path])
    tmp.close()
    return tmp.name


def export_user_data_pdf(user: Custom_User) -> str:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    tmp = tempfile.NamedTemporaryFile(mode="w+b", suffix=".pdf", delete=False)
    c = canvas.Canvas(tmp.name, pagesize=letter)
    width, height = letter
    y = height - 40

    def draw_line(label, value):
        nonlocal y
        c.drawString(40, y, f"{label}: {value}")
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
    draw_line("Is archived", user.is_archived)
    y -= 8
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Conversations")
    y -= 18
    c.setFont("Helvetica", 9)
    for conv in Conversation.objects.filter(user_id=user).order_by("created_at"):
        draw_line("Conversation", f"{conv.conversation_id} - {conv.title}")
        for msg in Message.objects.filter(conversation_id=conv).order_by("timestamp")[:5]:
            draw_line("  Msg", (getattr(msg, "content", "") or "")[:120])
    c.save()
    tmp.close()
    return tmp.name


def soft_delete_queryset(queryset) -> None:
    for obj in queryset:
        if hasattr(obj, "is_deleted"):
            obj.is_deleted = True
            obj.save(update_fields=["is_deleted"])
        else:
            obj.delete()


def create_exports(user: Custom_User, base_url: str) -> tuple[Optional[dict], Optional[str]]:
    """Generate CSV+PDF exports, save under MEDIA_ROOT/exports/<user_id>, email them.

    Returns (export_urls | None, zip_builder_dir_info). Zip creation is done by the
    caller (delete_or_archive) when download_now was requested.
    """
    from prompeteer_server.utils.emailer import send_verified_email

    export_subdir = os.path.join(getattr(settings, "MEDIA_ROOT", "media"), "exports", str(user.user_id))
    os.makedirs(export_subdir, exist_ok=True)

    csv_src = pdf_src = None
    try:
        csv_src = export_user_data_csv(user)
    except Exception:
        logger.exception("Failed to generate CSV export")
    try:
        pdf_src = export_user_data_pdf(user)
    except Exception:
        logger.exception("Failed to generate PDF export")

    stamp = timezone.now().strftime("%Y%m%d%H%M%S")
    dst_name_csv = f"user_export_{user.user_id}_{stamp}.csv"
    dst_path_csv = os.path.join(export_subdir, dst_name_csv)
    dst_name_pdf = f"user_export_{user.user_id}_{stamp}.pdf"
    dst_path_pdf = os.path.join(export_subdir, dst_name_pdf)
    if csv_src:
        try:
            shutil.move(csv_src, dst_path_csv)
        except Exception:
            logger.exception("Failed to move CSV export")
    if pdf_src:
        try:
            shutil.move(pdf_src, dst_path_pdf)
        except Exception:
            logger.exception("Failed to move PDF export")

    try:
        attachments = []
        if os.path.exists(dst_path_pdf):
            attachments.append((dst_path_pdf, dst_name_pdf, "application/pdf"))
        if os.path.exists(dst_path_csv):
            attachments.append((dst_path_csv, dst_name_csv, "text/csv"))
        if attachments and getattr(user, "email", None):
            send_verified_email(
                subject="Your Data Export",
                message="Attached are your requested data exports.",
                recipient_list=[user.email],
                from_email=None,
                html_message=None,
                verify_with_zeruh=True,
                zeruh_min_score=70,
                fail_silently=True,
                attachments=attachments,
            )
    except Exception:
        logger.exception("Failed to send export email; continuing")

    media_url = getattr(settings, "MEDIA_URL", "/media/")
    urls = {}
    if os.path.exists(dst_path_csv):
        urls["csv"] = f"{base_url}{media_url}exports/{user.user_id}/{dst_name_csv}" if base_url else f"{media_url}exports/{user.user_id}/{dst_name_csv}"
    if os.path.exists(dst_path_pdf):
        urls["pdf"] = f"{base_url}{media_url}exports/{user.user_id}/{dst_name_pdf}" if base_url else f"{media_url}exports/{user.user_id}/{dst_name_pdf}"

    zip_path = None
    return (urls or None), _build_zip(user, dst_path_csv, dst_name_csv, dst_path_pdf, dst_name_pdf)


def _build_zip(user, dst_path_csv, dst_name_csv, dst_path_pdf, dst_name_pdf) -> Optional[str]:
    try:
        zip_tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
        zip_tmp.close()
        with zipfile.ZipFile(zip_tmp.name, "w") as zf:
            if os.path.exists(dst_path_pdf):
                zf.write(dst_path_pdf, dst_name_pdf)
            if os.path.exists(dst_path_csv):
                zf.write(dst_path_csv, dst_name_csv)
        return zip_tmp.name
    except Exception:
        logger.exception("Failed to create zip export")
        return None


def delete_or_archive(user: Custom_User, action: str, profile_flag: bool, chat_flag: bool,
                      download_now: bool, base_url: str) -> tuple[int, Any, Optional[str]]:
    """Port of UnifiedSyncView.delete after resolve_user/validation.

    Returns (status, payload, zip_path_or_None). When zip_path is set the caller
    returns it as a file download instead of the JSON payload.
    """
    stats: dict[str, Any] = {}
    export_urls = None
    zip_path = None

    if profile_flag or chat_flag:
        try:
            export_urls, zip_path = create_exports(user, base_url)
        except Exception:
            logger.exception("Failed to create/save export; proceeding without it")
    if not download_now:
        zip_path = None

    if chat_flag or not (profile_flag or chat_flag):
        attachments = Attachment.objects.filter(message_id__user_id=user)
        messages = Message.objects.filter(user_id=user)
        conversations = Conversation.objects.filter(user_id=user)
        tokens = ProviderOAuthToken.objects.filter(user_id=user)
        stats.update({
            "attachments": attachments.count(),
            "messages": messages.count(),
            "conversations": conversations.count(),
            "tokens": tokens.count(),
        })
        if action == "delete":
            soft_delete_queryset(attachments)
            soft_delete_queryset(messages)
            soft_delete_queryset(conversations)
            tokens.delete()
        elif action == "archive":
            tokens.delete()

    if profile_flag or not (profile_flag or chat_flag):
        stats["user"] = 1
        if action == "delete":
            user.is_archived = True
            user.is_active = False
            try:
                user.save(update_fields=["is_archived", "is_active"])
            except Exception:
                user.save()
            logger.info(f"UnifiedSync: User {user.pk} and all related data deleted.")
            payload = {"message": "User and all related data deleted successfully", "deleted": stats}
            if export_urls:
                payload["export_urls"] = export_urls
            try:
                payload["profile"] = build_profile_payload(user)
                payload["chat"] = build_chat_payload(user)
            except Exception:
                pass
            return 200, payload, zip_path
        elif action == "archive":
            user.is_archived, user.is_active = True, False
            flags = ["is_google_user", "is_openrouter_user", "is_github_user", "is_microsoft_user"]
            for flag in flags:
                if getattr(user, flag, False):
                    setattr(user, flag, False)
            user.save(update_fields=["is_archived", "is_active"] + flags)
            logger.info(f"UnifiedSync: User {user.pk} archived; tokens purged.")
            payload = {"message": "User archived successfully", "archived": stats}
            if export_urls:
                payload["export_urls"] = export_urls
            try:
                payload["profile"] = build_profile_payload(user)
            except Exception:
                logger.exception("Failed to serialize archived profile")
            return 200, payload, zip_path

    return 400, {"error": "Specify action=delete, archive or export in query or body."}, None
