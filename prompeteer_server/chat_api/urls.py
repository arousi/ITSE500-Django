from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import SyncConversationsView, AssociateDeviceView, SyncOrRegisterVisitorView, AttachmentViewSet

router = DefaultRouter()
router.register(r'attachments', AttachmentViewSet, basename='attachment')


urlpatterns = [
    path('', include(router.urls)),
    path('sync-conversations/<str:anon_id>/', SyncConversationsView.as_view(), name='sync-conversations'),
    path('associate-device/', AssociateDeviceView.as_view(), name='associate-device'),
    path('sync-or-register/', SyncOrRegisterVisitorView.as_view(), name='sync-or-register'),
]