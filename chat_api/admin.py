from django.contrib import admin
from .models.conversation import Conversation
from .models.message import Message
from .models.attachment import Attachment
from .models.message_request import MessageRequest
from .models.message_response import MessageResponse
from .models.message_output import MessageOutput


@admin.register(Conversation)
class ConversationAdmin(admin.ModelAdmin):
	list_display = ('conversation_id', 'user_id', 'title', 'created_at', 'updated_at', 'local_only')
	list_filter = ('local_only', 'created_at')
	search_fields = ('conversation_id', 'title', 'user_id__username', 'user_id__email')
	ordering = ('-updated_at',)


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
	list_display = ('message_id', 'conversation_id', 'user_id', 'timestamp', 'vote', 'has_image', 'has_document')
	list_filter = ('has_image', 'has_document', 'timestamp')
	search_fields = ('message_id', 'conversation_id__conversation_id', 'user_id__username', 'user_id__email')
	ordering = ('-timestamp',)


@admin.register(Attachment)
class AttachmentAdmin(admin.ModelAdmin):
	list_display = ('attachment_id', 'message_id', 'type', 'mime_type', 'size_bytes', 'created_at')
	list_filter = ('type', 'created_at')
	search_fields = ('attachment_id', 'message_id__message_id')
	ordering = ('-created_at',)


@admin.register(MessageRequest)
class MessageRequestAdmin(admin.ModelAdmin):
	list_display = ('request_id', 'request_model', 'created_at') if hasattr(MessageRequest, 'created_at') else ('request_id', 'request_model')
	search_fields = ('request_id', 'request_model')


@admin.register(MessageResponse)
class MessageResponseAdmin(admin.ModelAdmin):
	list_display = ('response_id', 'status', 'model_name', 'created_at')
	list_filter = ('status', 'model_name')
	search_fields = ('response_id', 'model_name')


@admin.register(MessageOutput)
class MessageOutputAdmin(admin.ModelAdmin):
	list_display = ('output_id', 'output_type', 'output_status')
	list_filter = ('output_type',)
	search_fields = ('output_id',)

