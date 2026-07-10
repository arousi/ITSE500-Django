from django.contrib import admin
from django.db.models import Exists, OuterRef, Q
from django.urls import reverse
from django.utils import timezone
from django.utils.http import urlencode

from auth_api.models import OAuthState, ProviderOAuthToken

from .models.custom_user import Custom_User


class OAuthLinkedFilter(admin.SimpleListFilter):
	title = 'oauth linked'
	parameter_name = 'oauth_linked'

	def lookups(self, request, model_admin):
		return (
			('yes', 'Linked'),
			('no', 'Not linked'),
		)

	def queryset(self, request, queryset):
		has_state = OAuthState.objects.filter(user_id=OuterRef('pk'))
		has_token = ProviderOAuthToken.objects.filter(user_id=OuterRef('pk'))
		queryset = queryset.annotate(
			_has_oauth_state=Exists(has_state),
			_has_oauth_token=Exists(has_token),
		)
		if self.value() == 'yes':
			return queryset.filter(Q(_has_oauth_state=True) | Q(_has_oauth_token=True))
		if self.value() == 'no':
			return queryset.filter(Q(_has_oauth_state=False) & Q(_has_oauth_token=False))
		return queryset


def _build_admin_link(base_path, **query_params):
	return f"{base_path}?{urlencode(query_params)}" if query_params else base_path


class OAuthStateInline(admin.TabularInline):
	model = OAuthState
	fk_name = 'user_id'
	extra = 0
	fields = ('provider', 'state', 'created_at', 'expires_at', 'is_used', 'result_retrieved')
	readonly_fields = ('provider', 'state', 'created_at', 'expires_at', 'is_used', 'result_retrieved')
	show_change_link = True
	can_delete = False


class ProviderOAuthTokenInline(admin.TabularInline):
	model = ProviderOAuthToken
	fk_name = 'user_id'
	extra = 0
	fields = ('provider', 'provider_account_id', 'expires_at', 'created_at', 'updated_at')
	readonly_fields = ('provider', 'provider_account_id', 'expires_at', 'created_at', 'updated_at')
	show_change_link = True
	can_delete = False


def make_active(modeladmin, request, queryset):
	queryset.update(is_active=True)


def make_inactive(modeladmin, request, queryset):
	queryset.update(is_active=False)


def make_staff(modeladmin, request, queryset):
	queryset.update(is_staff=True)


def remove_staff(modeladmin, request, queryset):
	queryset.update(is_staff=False)


make_active.short_description = 'Mark selected users as active'
make_inactive.short_description = 'Mark selected users as inactive'
make_staff.short_description = 'Grant staff status to selected users'
remove_staff.short_description = 'Remove staff status from selected users'


@admin.register(Custom_User)
class CustomUserAdmin(admin.ModelAdmin):
	change_list_template = 'admin/user_mang/custom_user/change_list.html'
	list_display = (
		'user_id', 'username', 'email', 'is_staff', 'is_active', 'is_visitor',
		'email_verified', 'is_archived', 'last_login', 'date_joined'
	)
	list_display_links = ('username', 'email')
	list_filter = (
		'is_active', 'is_staff', 'is_superuser', 'is_visitor', 'email_verified',
		'is_archived', 'is_google_user', 'is_openrouter_user', 'is_microsoft_user', 'is_github_user', OAuthLinkedFilter,
	)
	search_fields = ('username', 'email', 'user_id', 'temp_id')
	readonly_fields = ('user_id', 'last_login', 'date_joined', 'last_modified')
	ordering = ('-date_joined',)
	date_hierarchy = 'date_joined'
	list_per_page = 50
	save_on_top = True
	filter_horizontal = ('groups', 'user_permissions')
	actions = (make_active, make_inactive, make_staff, remove_staff)
	inlines = (OAuthStateInline, ProviderOAuthTokenInline)
	fieldsets = (
		('Account', {'fields': ('user_id', 'username', 'email', 'phone_number', 'biometric_enabled', 'is_active', 'is_staff', 'is_superuser')}),
		('Flags', {'fields': ('is_visitor', 'email_verified', 'is_archived', 'is_google_user', 'is_openrouter_user', 'is_microsoft_user', 'is_github_user')}),
		('IDs', {'fields': ('devices_id', 'temp_id', 'related_devices')}),
		('Security', {'fields': ('last_login', 'date_joined', 'last_modified')}),
		('Groups', {'fields': ('groups', 'user_permissions')}),
	)

	def changelist_view(self, request, extra_context=None):
		now = timezone.now()
		state_changelist = reverse('admin:auth_api_oauthstate_changelist')
		token_changelist = reverse('admin:auth_api_provideroauthtoken_changelist')
		user_changelist = reverse('admin:user_mang_custom_user_changelist')

		total_users = Custom_User.objects.count()
		active_users = Custom_User.objects.filter(is_active=True).count()
		archived_users = Custom_User.objects.filter(is_archived=True).count()
		email_verified_users = Custom_User.objects.filter(email_verified=True).count()
		oauth_linked_users = Custom_User.objects.annotate(
			_has_oauth_state=Exists(OAuthState.objects.filter(user_id=OuterRef('pk'))),
			_has_oauth_token=Exists(ProviderOAuthToken.objects.filter(user_id=OuterRef('pk'))),
		).filter(Q(_has_oauth_state=True) | Q(_has_oauth_token=True)).count()
		revoked_states = OAuthState.objects.filter(Q(is_used=True) | Q(expires_at__lte=now)).count()
		revoked_tokens = ProviderOAuthToken.objects.filter(
			Q(expires_at__lte=now) | Q(access_token__startswith='revoked:') | Q(refresh_token__startswith='revoked:')
		).count()

		auth_health = {
			'cards': [
				{'label': 'Active users', 'count': active_users, 'url': _build_admin_link(user_changelist, is_active__exact='1')},
				{'label': 'Archived users', 'count': archived_users, 'url': _build_admin_link(user_changelist, is_archived__exact='1')},
				{'label': 'Email-verified users', 'count': email_verified_users, 'url': _build_admin_link(user_changelist, email_verified__exact='1')},
				{'label': 'OAuth-linked users', 'count': oauth_linked_users, 'url': _build_admin_link(user_changelist, oauth_linked='yes')},
				{'label': 'Revoked / stale OAuth states', 'count': revoked_states, 'url': state_changelist},
				{'label': 'Revoked / expired OAuth tokens', 'count': revoked_tokens, 'url': token_changelist},
			],
			'stats': {
				'total_users': total_users,
				'active_users': active_users,
				'archived_users': archived_users,
				'email_verified_users': email_verified_users,
				'oauth_linked_users': oauth_linked_users,
				'revoked_states': revoked_states,
				'revoked_tokens': revoked_tokens,
			},
		}
		extra_context = extra_context or {}
		extra_context['auth_health'] = auth_health
		return super().changelist_view(request, extra_context=extra_context)

