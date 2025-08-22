from django.urls import path
from .views import (
    LoginView,
    RegisterView,
    EmailPinVerifyView,
    SetPasswordAfterEmailVerifyView,
    LogoutView,
    HealthCheckView,
    LoginWithOTPView,

    OpenRouterAuthorizeView,
    OpenRouterCallbackView,
    SendLoginOTPView,
    VerifyLoginOTPView,

    GoogleAuthorizeView,
    GoogleCallbackView,
    OAuthResultView,
)
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path("login/", LoginView.as_view(), name="Login"),
    path("reg/", RegisterView.as_view(), name="Register"),
    path("verify-email-pin/", EmailPinVerifyView.as_view(), name="verify-email-pin"),
    path("set-password-after-email-verify/", SetPasswordAfterEmailVerifyView.as_view(), name="set-password-after-email-verify"),
    path("logout/", LogoutView.as_view(), name="Logout"),
    path('health/', HealthCheckView.as_view(), name='health-check'),
    
    path("otp-login/", LoginWithOTPView.as_view(), name="otp-login"),
    
    # Google OAuth (unified)
    path("google/authorize/", GoogleAuthorizeView.as_view(), name="google-authorize"), #* Start OAuth flow
    path("google/callback/", GoogleCallbackView.as_view(), name="google-callback"), #* Finish OAuth flow

    # OpenRouter OAuth (unified)
    path("openrouter/authorize/", OpenRouterAuthorizeView.as_view(), name="openrouter-authorize"),
    path("openrouter/callback/", OpenRouterCallbackView.as_view(), name="openrouter-callback"),

    # Bridge result endpoint (for mobile/SPA)
    path("oauth/result/<str:state_value>/", OAuthResultView.as_view(), name="oauth-result"),

    
    # JWT token refresh (SimpleJWT standard endpoint)
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    

]
"""path("visitor-login/", VisitorLoginView.as_view(), name="visitor-login"),"""