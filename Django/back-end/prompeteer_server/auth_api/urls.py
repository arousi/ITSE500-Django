from django.urls import path
from .views import (
    LoginView,
    RegisterView,
    EmailPinVerifyView,
    SetPasswordAfterEmailVerifyView,
    LogoutView,
    HealthCheckView,
    LoginWithOTPView,
    GoogleOAuthView,
    OpenRouterOAuthView,
    OpenRouterAuthorizeView,
    OpenRouterCallbackView,
    SendLoginOTPView,
    VerifyLoginOTPView,
    OpenRouterAuthorizeSSRView,
    OpenRouterCallbackSSRView,
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
    
    
    path("google-oauth/", GoogleOAuthView.as_view(), name="google-oauth"),
    path("google/authorize/", GoogleAuthorizeView.as_view(), name="google-authorize"),
    path("google/callback/", GoogleCallbackView.as_view(), name="google-callback"),
    # Legacy SSR paths now point to unified endpoints (mode=redirect triggers provider redirect)
    path("google/authorize/ssr/", GoogleAuthorizeView.as_view(), name="google-authorize-ssr"),
    path("google/callback/ssr/", GoogleCallbackView.as_view(), name="google-callback-ssr"),
    
    
    path("openrouter-oauth/", OpenRouterOAuthView.as_view(), name="openrouter-oauth"),
    path("openrouter/authorize/", OpenRouterAuthorizeView.as_view(), name="openrouter-authorize"),
    path("openrouter/callback/", OpenRouterCallbackView.as_view(), name="openrouter-callback"),
    path("openrouter/authorize/ssr/", OpenRouterAuthorizeSSRView.as_view(), name="openrouter-authorize-ssr"),
    path("openrouter/callback/ssr/", OpenRouterCallbackSSRView.as_view(), name="openrouter-callback-ssr"),
    path("oauth/result/<str:state_value>/", OAuthResultView.as_view(), name="oauth-result"),
    path("otp/send/", SendLoginOTPView.as_view(), name="send-login-otp"),
    path("otp/verify/", VerifyLoginOTPView.as_view(), name="verify-login-otp"),
    
    
    # JWT token refresh (SimpleJWT standard endpoint)
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    

]
"""path("visitor-login/", VisitorLoginView.as_view(), name="visitor-login"),"""