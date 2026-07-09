from django.contrib import admin
from django.db.models import Exists, OuterRef, Q
from .models.conversation import Conversation
from .models.message import Message
from .models.attachment import Attachment
from .models.message_request import MessageRequest
from .models.message_response import MessageResponse
from .models.message_output import MessageOutput


class MessageInline(admin.TabularInline):
	model = Message
	fk_name = 'conversation_id'
	extra = 0
	fields = ('message_id', 'user_id', 'timestamp', 'has_image', 'has_document', 'has_embedding', 'vote')
	readonly_fields = ('message_id', 'timestamp')
	show_change_link = True
	can_delete = False


class AttachmentInline(admin.TabularInline):
	model = Attachment
	fk_name = 'message_id'
	extra = 0
	fields = ('attachment_id', 'type', 'mime_type', 'size_bytes', 'is_encrypted', 'created_at')
	readonly_fields = ('attachment_id', 'created_at')
	show_change_link = True
	can_delete = False


class ConversationAttachmentFilter(admin.SimpleListFilter):
	title = 'attachments'
	parameter_name = 'has_attachments'

	def lookups(self, request, model_admin):
		return [
			('yes', 'With attachments'),
			('no', 'Without attachments'),
		]

	def queryset(self, request, queryset):
		has_attachments = Attachment.objects.filter(message_id__conversation_id=OuterRef('pk'))
		queryset = queryset.annotate(_has_attachments=Exists(has_attachments))
		if self.value() == 'yes':
			return queryset.filter(_has_attachments=True)
		if self.value() == 'no':
			return queryset.filter(_has_attachments=False)
		return queryset


class MessageMediaFilter(admin.SimpleListFilter):
	title = 'media triage'
	parameter_name = 'media_triage'

	def lookups(self, request, model_admin):
		return [
			('images', 'Images'),
			('documents', 'Documents'),
			('both', 'Images and documents'),
			('none', 'No media'),
		]

	def queryset(self, request, queryset):
		if self.value() == 'images':
			return queryset.filter(has_image=True)
		if self.value() == 'documents':
			return queryset.filter(has_document=True)
		if self.value() == 'both':
			return queryset.filter(has_image=True, has_document=True)
		if self.value() == 'none':
			return queryset.filter(has_image=False, has_document=False)
		return queryset


class ResponseStatusBucketFilter(admin.SimpleListFilter):
	title = 'status bucket'
	parameter_name = 'status_bucket'

	def lookups(self, request, model_admin):
		return [
			('success', 'Success'),
			('pending', 'Pending'),
			('incomplete', 'Incomplete'),
			('error', 'Error'),
			('other', 'Other'),
		]

	def queryset(self, request, queryset):
		status = self.value()

		def _match(values):
			query = Q()
			for value in values:
				query |= Q(status__iexact=value)
			return queryset.filter(query)

		if status == 'success':
			return _match(['success', 'succeeded', 'completed', 'done', 'ok'])
		if status == 'pending':
			return _match(['pending', 'processing', 'running', 'queued'])
		if status == 'incomplete':
			return _match(['incomplete', 'partial'])
		if status == 'error':
			return _match(['error', 'failed', 'failure', 'cancelled', 'canceled'])
		if status == 'other':
			known_values = ['success', 'succeeded', 'completed', 'done', 'ok', 'pending', 'processing', 'running', 'queued', 'incomplete', 'partial', 'error', 'failed', 'failure', 'cancelled', 'canceled']
			query = Q()
			for value in known_values:
				query |= Q(status__iexact=value)
			return queryset.exclude(query)
		return queryset


@admin.register(Conversation)
class ConversationAdmin(admin.ModelAdmin):
	list_display = ('conversation_id', 'user_id', 'title', 'created_at', 'updated_at', 'local_only', 'message_count')
	list_filter = ('local_only', ConversationAttachmentFilter, 'created_at', 'updated_at')
	search_fields = ('conversation_id', 'title', 'user_id__username', 'user_id__email')
	search_help_text = 'Search by conversation id, title, username, or email.'
	ordering = ('-updated_at',)
	date_hierarchy = 'created_at'
	autocomplete_fields = ('user_id',)
	list_per_page = 50
	inlines = (MessageInline,)
	readonly_fields = ('conversation_id', 'created_at', 'updated_at')
	fieldsets = (
		('Conversation', {'fields': ('conversation_id', 'user_id', 'title', 'local_only')}),
		('Metadata', {'fields': ('created_at', 'updated_at')}),
	)

	def message_count(self, obj):
		return obj.messages.count()
	message_count.short_description = 'Messages'


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
	list_display = ('message_id', 'conversation_id', 'user_id', 'timestamp', 'vote', 'has_image', 'has_document', 'has_embedding')
	list_filter = (MessageMediaFilter, 'has_image', 'has_document', 'has_embedding', 'vote', 'timestamp')
	search_fields = ('message_id', 'conversation_id__conversation_id', 'conversation_id__title', 'user_id__username', 'user_id__email')
	search_help_text = 'Search by message id, conversation, username, or email.'
	ordering = ('-timestamp',)
	autocomplete_fields = ('conversation_id', 'user_id', 'request_id', 'response_id', 'output_id')
	list_per_page = 50
	inlines = (AttachmentInline,)
	readonly_fields = ('message_id', 'timestamp')
	fieldsets = (
		('Message', {'fields': ('message_id', 'conversation_id', 'user_id', 'vote')}),
		('Content Flags', {'fields': ('has_image', 'img_Url', 'has_embedding', 'metadata', 'has_document', 'doc_url')}),
		('Linked Records', {'fields': ('request_id', 'response_id', 'output_id')}),
		('Metadata', {'fields': ('timestamp',)}),
	)


@admin.register(Attachment)
class AttachmentAdmin(admin.ModelAdmin):
	list_display = ('attachment_id', 'message_id', 'type', 'mime_type', 'size_bytes', 'is_encrypted', 'created_at')
	list_filter = ('type', 'is_encrypted', 'created_at')
	search_fields = ('attachment_id', 'message_id__message_id', 'message_id__conversation_id__conversation_id')
	search_help_text = 'Search by attachment id, message id, or conversation id.'
	ordering = ('-created_at',)
	autocomplete_fields = ('message_id',)
	readonly_fields = ('attachment_id', 'created_at')
	fieldsets = (
		('Attachment', {'fields': ('attachment_id', 'message_id', 'type', 'mime_type', 'file_path', 'encrypted_blob', 'size_bytes')}),
		('Image / Shape', {'fields': ('width', 'height', 'sha256')}),
		('Encryption', {'fields': ('is_encrypted', 'enc_algo', 'iv_base64', 'key_ref')}),
		('Metadata', {'fields': ('created_at',)}),
	)


@admin.register(MessageRequest)
class MessageRequestAdmin(admin.ModelAdmin):
	list_display = ('request_id', 'request_model', 'request_stream', 'request_temperature', 'request_top_p', 'request_max_tokens')
	list_filter = ('request_stream', 'request_model')
	search_fields = ('request_id', 'request_model', 'request_user_content', 'request_system_prompt')
	search_help_text = 'Search by request id, model, or prompt text.'
	ordering = ('-request_id',)
	readonly_fields = ('request_id',)
	fieldsets = (
		('Model and Roles', {'fields': ('request_id', 'request_model', 'request_system_role', 'request_system_content', 'request_system_prompt')}),
		('User Input', {'fields': ('request_user_role', 'request_user_content', 'request_input')}),
		('Generation', {'fields': ('request_min_p', 'request_temperature', 'request_top_p', 'request_n', 'request_top_k', 'request_stream', 'request_stop', 'request_max_tokens', 'repeat_penalty')}),
		('Structured Output', {'fields': ('request_user_structured_output', 'request_structured_schema')}),
	)


@admin.register(MessageResponse)
class MessageResponseAdmin(admin.ModelAdmin):
	list_display = ('response_id', 'status', 'model_name', 'created_at', 'usage_total_tokens', 'user')
	list_filter = (ResponseStatusBucketFilter, 'status', 'model_name', 'store', 'parallel_tool_calls')
	search_fields = ('response_id', 'model_name', 'user', 'error', 'instructions')
	search_help_text = 'Search by response id, model, user, or error text.'
	ordering = ('-created_at',)
	readonly_fields = ('response_id',)
	fieldsets = (
		('Response', {'fields': ('response_id', 'object', 'created_at', 'status', 'error', 'incomplete_details')}),
		('Model', {'fields': ('model_name', 'previous_response_id', 'instructions', 'reasoning_effort', 'reasoning_summary')}),
		('Generation', {'fields': ('store', 'temperature', 'text_format_type', 'tool_choice', 'tools', 'top_p', 'truncation', 'parallel_tool_calls')}),
		('Usage', {'fields': ('usage_input_tokens', 'usage_output_tokens', 'usage_total_tokens')}),
		('Context', {'fields': ('user', 'metadata')}),
	)


@admin.register(MessageOutput)
class MessageOutputAdmin(admin.ModelAdmin):
	list_display = ('output_id', 'output_type', 'output_status', 'output_role', 'output_content_type')
	list_filter = ('output_type', 'output_status', 'output_role')
	search_fields = ('output_id', 'output_content_text', 'output_content_annotations')
	search_help_text = 'Search by output id or content text.'
	ordering = ('output_id',)
	readonly_fields = ('output_id',)
	fieldsets = (
		('Output', {'fields': ('output_id', 'output_type', 'output_status', 'output_role', 'output_content_type')}),
		('Content', {'fields': ('output_content_text', 'output_content_annotations')}),
	)

