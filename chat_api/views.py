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
#* Answer, provide a UUID to any visitor who registers, making it possible to get his data by inputting his UUID from flutter into REACT, this would solve the problem of privacy + sync