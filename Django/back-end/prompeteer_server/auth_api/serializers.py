from rest_framework import serializers
from django.conf import settings
import hashlib
from user_mang.models.custom_user import Custom_User

class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(write_only=True)
    user_password = serializers.CharField(write_only=True, allow_blank=False, min_length=6)

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
        pwd = attrs.get('user_password')
        if not pwd:
            raise serializers.ValidationError({'user_password': 'This field is required.'})
        if len(pwd) < 6:
            raise serializers.ValidationError({'user_password': 'Password must be at least 6 characters.'})
        return attrs

    def create(self, validated_data):
        # Hash password with backend salt similar to login expectation
        BACKEND_SALT = getattr(settings, 'BACKEND_PASSWORD_SALT', 'fallback_dev_salt')
        salted = (validated_data['user_password'] + BACKEND_SALT).encode('utf-8')
        backend_hash = hashlib.sha256(salted).hexdigest()
        user = Custom_User(
            username=validated_data['username'],
            email=validated_data['email'],
            user_password=backend_hash,
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
