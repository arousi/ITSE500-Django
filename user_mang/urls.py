from django.urls import path
from .views import UnifiedSyncView

urlpatterns = [
    # User endpoints (self-management)
    path('me/', UnifiedSyncView.as_view(), name='user-detail'),
    # Admin endpoints (manage any user)
]
