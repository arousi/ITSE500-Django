from django.urls import path
from . import views

urlpatterns = [
    path('conversations/', views.ConversationListCreateView.as_view(), name='conversation-list-create'),
    path('conversations/<uuid:conversation_id>/', views.ConversationDetailView.as_view(), name='conversation-detail'),
    path('conversations/<uuid:conversation_id>/messages/', views.MessageListCreateView.as_view(), name='message-list-create'),
    path(
        'conversations/<uuid:conversation_id>/messages/<uuid:message_id>/attachments/',
        views.AttachmentListCreateView.as_view(),
        name='message-attachments',
    ),
]
