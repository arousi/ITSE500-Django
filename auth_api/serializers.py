from rest_framework import serializers
from django.conf import settings
import hashlib
from user_mang.models.custom_user import Custom_User


class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(write_only=True)
    user_password = serializers.CharField(write_only=True, required=False, allow_blank=True, min_length=6)

    class Meta:
        model = Custom_User
        fields = ['username', 'email', 'user_password']

    def validate(self, attrs):
        if not attrs.get('username'):
            raise serializers.ValidationError({'username': 'This field is required.'})
        if not attrs.get('email'):
            raise serializers.ValidationError({'email': 'This field is required.'})
        if '@' not in attrs.get('email', ''):
            raise serializers.ValidationError({'email': 'Enter a valid email address.'})
        if Custom_User.objects.filter(email=attrs['email']).exists():
            raise serializers.ValidationError({'email': 'A user with this email already exists.'})
        pwd = attrs.get('user_password', '')
        if pwd and len(pwd) < 6:
            raise serializers.ValidationError({'user_password': 'Password must be at least 6 characters.'})
        return attrs

    def create(self, validated_data):
        BACKEND_SALT = getattr(settings, 'BACKEND_PASSWORD_SALT', 'fallback_dev_salt')
        pwd = validated_data.get('user_password', '')
        backend_hash = hashlib.sha256((pwd + BACKEND_SALT).encode('utf-8')).hexdigest() if pwd else ''
        user = Custom_User(
            username=validated_data['username'],
            email=validated_data['email'],
            user_password=backend_hash if pwd else None,
        )
        user.full_clean()
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
    identifier = serializers.CharField(required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    username = serializers.CharField(required=False, allow_blank=True)
    user_password = serializers.CharField(required=False, allow_blank=True)

    def validate(self, attrs):
        identifier = attrs.get('identifier') or attrs.get('email') or attrs.get('username')
        pwd = attrs.get('user_password', '')
        if not identifier:
            raise serializers.ValidationError({'detail': 'Identifier required'})
        user = None
        if '@' in str(identifier):
            user = Custom_User.objects.filter(email=identifier).first()
        if not user:
            user = Custom_User.objects.filter(username=identifier).first()
        if not user:
            raise serializers.ValidationError({'detail': 'Invalid credentials'})
        if pwd == '':
            attrs['user'] = user
            return attrs
        BACKEND_SALT = getattr(settings, 'BACKEND_PASSWORD_SALT', 'fallback_dev_salt')
        salted = (pwd + BACKEND_SALT).encode('utf-8')
        backend_hash = hashlib.sha256(salted).hexdigest()
        if user.user_password != backend_hash:
            raise serializers.ValidationError({'detail': 'Invalid credentials'})
        attrs['user'] = user
        return attrs

class OAuthCallbackSerializer(serializers.Serializer):
    state = serializers.CharField()
    code = serializers.CharField(required=False, allow_blank=True)
    error = serializers.CharField(required=False, allow_blank=True)

class OAuthAuthorizeRequestSerializer(serializers.Serializer):
    # Default minimal scope; provider-specific views may override (e.g., add email profile)
    scope = serializers.CharField(required=False, allow_blank=True, default='openid')
    redirect_uri = serializers.CharField(required=False, allow_blank=True)

class SendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

# ------------------------- Documentation Serializers -------------------------

class MessageDoc(serializers.Serializer):
    message_id = serializers.CharField()
    timestamp = serializers.DateTimeField()
    has_image = serializers.BooleanField(required=False)
    has_document = serializers.BooleanField(required=False)


class ConversationDoc(serializers.Serializer):
    conversation_id = serializers.CharField()
    title = serializers.CharField(required=False, allow_null=True)
    updated_at = serializers.DateTimeField(required=False)
    messages = MessageDoc(many=True)


class RegisterResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
    user_id = serializers.CharField()
    access_token = serializers.CharField()
    refresh_token = serializers.CharField()
    email = serializers.EmailField()
    onboarding = serializers.BooleanField()
    conversations = ConversationDoc(many=True)
    temp_id = serializers.CharField(required=False, allow_null=True)
    device_id = serializers.CharField(required=False, allow_null=True)
    related_devices = serializers.ListField(child=serializers.CharField(), required=False)


class AttachmentDoc(serializers.Serializer):
    attachment_id = serializers.CharField(required=False)
    message_id = serializers.CharField(required=False)
    url = serializers.CharField(required=False)


class LoginResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
    user_id = serializers.CharField()
    access_token = serializers.CharField()
    refresh_token = serializers.CharField()
    email_verified = serializers.BooleanField()
    conversations = ConversationDoc(many=True)
    attachments = AttachmentDoc(many=True)


class LogoutResponseSerializer(serializers.Serializer):
    detail = serializers.CharField()


class HealthCheckResponseSerializer(serializers.Serializer):
    status = serializers.CharField()
    message = serializers.CharField()


class OAuthAuthorizeResponseSerializer(serializers.Serializer):
    authorize_url = serializers.CharField()
    state = serializers.CharField()
    state_id = serializers.CharField()
    expires_at = serializers.CharField()
    bridge = serializers.BooleanField()


class OAuthCallbackResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
    user_id = serializers.CharField()
    username = serializers.CharField(required=False, allow_null=True)
    access_token = serializers.CharField()
    refresh_token = serializers.CharField()
    provider_scope = serializers.CharField(required=False, allow_null=True)
    provider_expires_at = serializers.CharField(required=False, allow_null=True)
    provider_access_token = serializers.CharField(required=False, allow_null=True)
    provider_refresh_token = serializers.CharField(required=False, allow_null=True)
    provider_token_type = serializers.CharField(required=False, allow_null=True)
    id_token = serializers.CharField(required=False, allow_null=True)
    email = serializers.EmailField(required=False, allow_null=True)
    email_verified = serializers.BooleanField(required=False)
    is_google_user = serializers.BooleanField(required=False)
    is_openrouter_user = serializers.BooleanField(required=False)
    is_github_user = serializers.BooleanField(required=False)
    is_ms_user = serializers.BooleanField(required=False)


class EmailPinVerifyRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()
    pin = serializers.CharField(max_length=5)


class EmailPinVerifyResponseSerializer(serializers.Serializer):
    message = serializers.CharField()


class SetPasswordAfterEmailVerifyRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(min_length=6)


class SetPasswordAfterEmailVerifyResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
