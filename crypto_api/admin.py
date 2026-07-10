from django.contrib import admin
from django.utils import timezone

from .models import UserKeyMaterial


class UMKVersionFilter(admin.SimpleListFilter):
	title = 'key version'
	parameter_name = 'umk_version'

	def lookups(self, request, model_admin):
		versions = (
			UserKeyMaterial.objects.order_by('version')
			.values_list('version', flat=True)
			.distinct()
		)
		return [(str(v), f'v{v}') for v in versions]

	def queryset(self, request, queryset):
		value = self.value()
		if value:
			return queryset.filter(version=value)
		return queryset


@admin.register(UserKeyMaterial)
class UserKeyMaterialAdmin(admin.ModelAdmin):
	"""Admin for the per-user Master Key (UMK).

	The UMK is sensitive: it is provisioned once via the crypto_api endpoint and
	must not be created, edited, or rotated from the admin (that would silently
	break every artifact encrypted under the old key). So this admin is
	view/delete only — the base64 key value is masked in the list and shown
	read-only on the detail page for support/debugging.
	"""

	list_display = ('user_id', 'version', 'umk_preview', 'created_at', 'updated_at')
	list_filter = (UMKVersionFilter, 'version', 'created_at', 'updated_at')
	search_fields = ('user_id__username', 'user_id__email', 'user_id__user_id')
	search_help_text = 'Search by username, email, or user id.'
	autocomplete_fields = ('user_id',)
	ordering = ('-updated_at',)
	date_hierarchy = 'created_at'
	list_per_page = 50
	readonly_fields = ('user_id', 'umk_b64', 'version', 'created_at', 'updated_at')
	fieldsets = (
		('Owner', {'fields': ('user_id',)}),
		('Key Material', {
			'fields': ('umk_b64', 'version'),
			'description': 'Provisioned via the crypto_api /umk endpoint. Read-only here — rotating or editing it would orphan every artifact encrypted under the previous key.',
		}),
		('Lifecycle', {'fields': ('created_at', 'updated_at')}),
	)

	def has_add_permission(self, request):
		# UMK is provisioned exactly once per user via the API, never by hand.
		return False

	@admin.display(description='UMK (masked)')
	def umk_preview(self, obj):
		raw = obj.umk_b64 or ''
		if len(raw) <= 10:
			return '•' * len(raw)
		return f'{raw[:6]}…{raw[-4:]} ({len(raw)} chars)'
