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
    
    GitHubAuthorizeView,
    GitHubCallbackView,
    
    MicrosoftAuthorizeView,
    MicrosoftCallbackView
)
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    # Canonical names
    path("login/", LoginView.as_view(), name="login"),
    path("register/", RegisterView.as_view(), name="register"),
    path("verify-email-pin/", EmailPinVerifyView.as_view(), name="email-pin-verify"),
    path("set-password-after-email-verify/", SetPasswordAfterEmailVerifyView.as_view(), name="set-password"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path('health/', HealthCheckView.as_view(), name='health-check'),
    
    path("otp-login/", LoginWithOTPView.as_view(), name="otp-login"),
    
    # Google OAuth (unified)
    path("google/authorize/", GoogleAuthorizeView.as_view(), name="google-authorize"), #* Start OAuth flow
    path("google/callback/", GoogleCallbackView.as_view(), name="google-callback"), #* Finish OAuth flow
    path("google/callback", GoogleCallbackView.as_view()),  # alias without trailing slash

    # OpenRouter OAuth (unified)
    path("openrouter/authorize/", OpenRouterAuthorizeView.as_view(), name="openrouter-authorize"),
    path("openrouter/callback/", OpenRouterCallbackView.as_view(), name="openrouter-callback"),
    path("openrouter/callback", OpenRouterCallbackView.as_view()),  # alias without trailing slash

    path('github/authorize/', GitHubAuthorizeView.as_view(), name='github-authorize'),
    path('github/callback/', GitHubCallbackView.as_view(), name='github-callback'),
    path('github/callback', GitHubCallbackView.as_view()),
    
    path('microsoft/authorize/', MicrosoftAuthorizeView.as_view(), name='ms-authorize'),
    path('microsoft/callback/', MicrosoftCallbackView.as_view(), name='ms-callback'),
    path('microsoft/callback', MicrosoftCallbackView.as_view()),
    
    path("google/authorize/ssr/", GoogleAuthorizeView.as_view(), name="google-authorize-ssr"),
    path("openrouter/authorize/ssr/", OpenRouterAuthorizeView.as_view(), name="openrouter-authorize-ssr"),
    path("github/authorize/ssr/", GitHubAuthorizeView.as_view(), name="github-authorize-ssr"),
    path("microsoft/authorize/ssr/", MicrosoftAuthorizeView.as_view(), name="ms-authorize-ssr"),
    
    # Bridge result endpoint (for mobile/SPA)
    path("oauth/result/<str:state_value>/", OAuthResultView.as_view(), name="oauth-result"),

    
    # JWT token refresh (SimpleJWT standard endpoint)
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    

]
"""path("visitor-login/", VisitorLoginView.as_view(), name="visitor-login"),"""

# Backward-compatibility alias routes (names used in older tests/clients)
urlpatterns += [
    path("google/oauth/", GoogleAuthorizeView.as_view(), name="google-oauth"),
    path("openrouter/oauth/", OpenRouterAuthorizeView.as_view(), name="openrouter-oauth"),
]