"""chat_api views: endpoints and scaffolding for chat/conversation features.

English
- Purpose: Provide REST views for conversations, messages, attachments, and sync helpers.
- Notes: This module primarily defines APIView classes in other files; here we keep
	logging setup and architectural notes for syncing across devices.

العربية
- الهدف: واجهات REST لإدارة المحادثات والرسائل والمرفقات والمزامنة بين الأجهزة.
- ملاحظة: هذا الملف يحتوي أساسًا على تهيئة السجل وملاحظات تصميم.
"""

from django.shortcuts import render

import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Conversation
from .models import Message
from .models.attachment import Attachment
from rest_framework import viewsets, permissions
from .models.message_request import MessageRequest
from .models.message_response import MessageResponse
from .models.message_output import MessageOutput
from django.db import transaction
from django.utils import timezone

# Configure logger for this module
logger = logging.getLogger(__name__)

# Create your views here (see app-specific submodules where applicable).

# Design note:
# How do we connect a visitor across two devices to sync conversations/messages?
# Answer: assign each visitor a stable UUID on first contact; the Flutter app can
# provide this UUID to the React app to fetch/sync data without exposing PII.