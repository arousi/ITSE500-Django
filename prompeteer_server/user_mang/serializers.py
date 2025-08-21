from rest_framework import serializers
from rest_framework.fields import UUIDField
from .models.custom_user import Custom_User

class CustomeUserSerializer(serializers.ModelSerializer):
    """
    Serializer for Custom_User model, for user data management endpoints.
    """
    user_id = UUIDField(read_only=True)  # Explicitly define user_id as UUIDField

    class Meta:
        model = Custom_User
        fields = [
            'user_id',
            'username',
            'first_name',
            'last_name',
            'email',
            'phone_number',
            'biometric_enabled',
            'last_modified',
            'email_verified',  # Updated field name
            'is_archived',
            'is_active',
            'is_google_user',
            'is_openrouter_user',
            'date_joined',
        ]
        read_only_fields = ['user_id', 'last_modified', 'date_joined']
