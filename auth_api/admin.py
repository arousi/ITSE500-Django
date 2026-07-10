from django.contrib import admin
from django.db.models import Q
from django.utils import timezone

from .models import OAuthState, ProviderOAuthToken


class OAuthStateStatusFilter(admin.SimpleListFilter):
	title = 'state status'
	parameter_name = 'state_status'

	def lookups(self, request, model_admin):
		return [
			('active', 'Active'),
			('used', 'Used'),
			('expired', 'Expired'),
			('stale', 'Used or expired'),
		]

	def queryset(self, request, queryset):
		now = timezone.now()
		if self.value() == 'active':
			return queryset.filter(is_used=False, expires_at__gt=now)
		if self.value() == 'used':
			return queryset.filter(is_used=True)
		if self.value() == 'expired':
			return queryset.filter(expires_at__lte=now)
		if self.value() == 'stale':
			return queryset.filter(Q(is_used=True) | Q(expires_at__lte=now))
		return queryset


class OAuthTokenStatusFilter(admin.SimpleListFilter):
	title = 'token status'
	parameter_name = 'token_status'

	def lookups(self, request, model_admin):
		return [
			('active', 'Active'),
			('expired', 'Expired'),
			('revoked', 'Revoked'),
			('stale', 'Expired or revoked'),
		]

	def queryset(self, request, queryset):
		now = timezone.now()
		if self.value() == 'active':
			return queryset.filter(Q(expires_at__gt=now) | Q(expires_at__isnull=True)).exclude(
				Q(access_token__startswith='revoked:') | Q(refresh_token__startswith='revoked:')
			)
		if self.value() == 'expired':
			return queryset.filter(expires_at__lte=now)
		if self.value() == 'revoked':
			return queryset.filter(Q(access_token__startswith='revoked:') | Q(refresh_token__startswith='revoked:'))
		if self.value() == 'stale':
			return queryset.filter(Q(expires_at__lte=now) | Q(access_token__startswith='revoked:') | Q(refresh_token__startswith='revoked:'))
		return queryset
@admin.action(description='Mark selected states as used')
def mark_selected_states_used(modeladmin, request, queryset):
	queryset.update(is_used=True, code_verifier=None)


@admin.action(description='Expire selected states now')
def expire_selected_states(modeladmin, request, queryset):
	queryset.update(is_used=True, expires_at=timezone.now(), code_verifier=None)


@admin.action(description='Revoke selected provider tokens')
def revoke_selected_tokens(modeladmin, request, queryset):
	queryset.update(
		access_token=f"revoked:{timezone.now().isoformat()}",
		refresh_token=None,
		expires_at=timezone.now(),
	)


@admin.register(OAuthState)
class OAuthStateAdmin(admin.ModelAdmin):
	list_display = ('oauth_state_id', 'provider', 'state', 'user_id', 'created_at', 'expires_at', 'is_used')
	list_filter = ('provider', 'is_used', OAuthStateStatusFilter, 'created_at')
	search_fields = ('state', 'oauth_state_id', 'user_id__username', 'user_id__email')
	search_help_text = 'Search by state, id, username, or email.'
	readonly_fields = ('oauth_state_id', 'created_at', 'code_verifier', 'result_payload')
	ordering = ('-created_at',)
	date_hierarchy = 'created_at'
	list_select_related = ('user_id',)
	autocomplete_fields = ('user_id',)
	save_on_top = True
	actions = (mark_selected_states_used, expire_selected_states)
	fieldsets = (
		('State', {'fields': ('oauth_state_id', 'user_id', 'provider', 'state', 'code_challenge', 'code_verifier')}),
		('Redirects', {'fields': ('redirect_uri', 'mobile_redirect', 'scope')}),
		('Result', {'fields': ('result_payload', 'result_retrieved')}),
		('Lifecycle', {'fields': ('created_at', 'expires_at', 'is_used')}),
	)

	def get_readonly_fields(self, request, obj=None):
		if obj:
			return tuple(self.readonly_fields) + ('user_id', 'provider', 'state', 'code_challenge', 'redirect_uri', 'mobile_redirect', 'scope', 'expires_at')
		return tuple(self.readonly_fields)


@admin.register(ProviderOAuthToken)
class ProviderOAuthTokenAdmin(admin.ModelAdmin):
	list_display = ('provider_oauth_token_id', 'user_id', 'provider', 'provider_account_id', 'expires_at', 'created_at', 'updated_at')
	list_filter = ('provider', OAuthTokenStatusFilter, 'created_at', 'expires_at')
	search_fields = ('provider_oauth_token_id', 'user_id__username', 'user_id__email', 'provider_account_id')
	search_help_text = 'Search by token id, username, email, or provider account id.'
	readonly_fields = ('provider_oauth_token_id', 'created_at', 'updated_at')
	ordering = ('-created_at',)
	date_hierarchy = 'created_at'
	list_select_related = ('user_id',)
	autocomplete_fields = ('user_id',)
	save_on_top = True
	actions = (revoke_selected_tokens,)
	fieldsets = (
		('Token', {'fields': ('provider_oauth_token_id', 'user_id', 'provider', 'provider_account_id')}),
		('Encrypted Values', {'fields': ('access_token', 'refresh_token', 'token_type', 'scope')}),
		('Lifecycle', {'fields': ('expires_at', 'created_at', 'updated_at')}),
	)

	def get_readonly_fields(self, request, obj=None):
		if obj:
			return tuple(self.readonly_fields) + ('user_id', 'provider', 'provider_account_id')
		return tuple(self.readonly_fields)

