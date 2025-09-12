# Compatibility alias module used by legacy tests importing auth_api.serializer
# Re-export the new serializers to keep import paths working
from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    OAuthCallbackSerializer,
    OAuthAuthorizeRequestSerializer,
    SendOTPSerializer,
    VerifyOTPSerializer,
)
