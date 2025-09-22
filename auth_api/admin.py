from django.contrib import admin
from .models import OAuthState, ProviderOAuthToken


@admin.register(OAuthState)
class OAuthStateAdmin(admin.ModelAdmin):
	list_display = ('oauth_state_id', 'provider', 'state', 'user_id', 'created_at', 'expires_at', 'is_used')
	list_filter = ('provider', 'is_used', 'created_at')
	search_fields = ('state', 'oauth_state_id')
	readonly_fields = ('oauth_state_id', 'created_at')
	ordering = ('-created_at',)


@admin.register(ProviderOAuthToken)
class ProviderOAuthTokenAdmin(admin.ModelAdmin):
	list_display = ('provider_oauth_token_id', 'user_id', 'provider', 'provider_account_id', 'expires_at', 'created_at')
	list_filter = ('provider',)
	search_fields = ('provider_oauth_token_id', 'user_id__username', 'user_id__email', 'provider_account_id')
	readonly_fields = ('provider_oauth_token_id', 'created_at', 'updated_at')
	ordering = ('-created_at',)

