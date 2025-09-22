from django.contrib import admin
from .models.custom_user import Custom_User


@admin.register(Custom_User)
class CustomUserAdmin(admin.ModelAdmin):
	list_display = (
		'user_id', 'username', 'email', 'is_staff', 'is_active', 'is_visitor',
		'email_verified', 'is_archived', 'last_login', 'date_joined'
	)
	list_filter = (
		'is_active', 'is_staff', 'is_superuser', 'is_visitor', 'email_verified',
		'is_archived', 'is_google_user', 'is_openrouter_user', 'is_microsoft_user', 'is_github_user'
	)
	search_fields = ('username', 'email', 'user_id', 'temp_id')
	readonly_fields = ('user_id', 'last_login', 'date_joined', 'last_modified')
	ordering = ('-date_joined',)
	fieldsets = (
		('Account', {'fields': ('user_id', 'username', 'email', 'phone_number', 'biometric_enabled', 'is_active', 'is_staff', 'is_superuser')}),
		('Flags', {'fields': ('is_visitor', 'email_verified', 'is_archived', 'is_google_user', 'is_openrouter_user', 'is_microsoft_user', 'is_github_user')}),
		('IDs', {'fields': ('devices_id', 'temp_id', 'related_devices')}),
		('Security', {'fields': ('last_login', 'date_joined', 'last_modified')}),
		('Groups', {'fields': ('groups', 'user_permissions')}),
	)

