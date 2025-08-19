from django.urls import path
from .views import UserDetailView, AdminUserDetailView

urlpatterns = [
    # User endpoints (self-management)
    path('me/', UserDetailView.as_view(), name='user-detail'),
    # Admin endpoints (manage any user)
    path('admin/user/<uuid:user_id>/', AdminUserDetailView.as_view(), name='admin-user-detail'),
]
