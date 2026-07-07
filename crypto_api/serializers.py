from rest_framework import serializers
from .models import UserKeyMaterial

class UserKeyMaterialSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserKeyMaterial
        fields = ['user','umk_b64','version','created_at','updated_at']
        read_only_fields = ['version','created_at','updated_at']


# ------------------------- Documentation Serializers -------------------------

class UMKNotProvisionedResponseSerializer(serializers.Serializer):
    """GET response shape when the caller has no UMK provisioned yet."""
    exists = serializers.BooleanField(default=False)


class UMKGetResponseSerializer(serializers.Serializer):
    """GET response shape when the caller's UMK exists (UserKeyMaterial fields + exists=True)."""
    user = serializers.IntegerField(help_text='Owning user id')
    umk_b64 = serializers.CharField()
    version = serializers.IntegerField()
    created_at = serializers.DateTimeField()
    updated_at = serializers.DateTimeField()
    exists = serializers.BooleanField(default=True)


class UMKProvisionRequestSerializer(serializers.Serializer):
    """POST request body: optionally client-supplied 32-byte key, base64-encoded."""
    umk_b64 = serializers.CharField(
        required=False, allow_blank=True,
        help_text='Optional client-provided 32-byte key, base64-encoded. If omitted, the server generates one.',
    )


class UMKProvisionResponseSerializer(serializers.Serializer):
    """201 response after provisioning: the created UserKeyMaterial record."""
    user = serializers.IntegerField(help_text='Owning user id')
    umk_b64 = serializers.CharField()
    version = serializers.IntegerField()
    created_at = serializers.DateTimeField()
    updated_at = serializers.DateTimeField()


class UMKErrorResponseSerializer(serializers.Serializer):
    error = serializers.CharField()
