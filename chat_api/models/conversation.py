from django.db import models
from user_mang.models.custom_user import Custom_User
import uuid

# Import validators if needed in the Conversation model
# Currently, no validators are directly used in this model.

class Conversation(models.Model):
    conversation_id = models.UUIDField(primary_key=True, unique=True,
                                       default=uuid.uuid4, editable=False) 
    # Represents conversationID
    
    user_id = models.ForeignKey(Custom_User, on_delete=models.CASCADE,
                                
                             related_name="conversations", blank=True) 
    # Foreign key to Custom_User
    # visitor_id field removed; use user_id for both registered and guest 
    # (is_visitor=True)
    title = models.CharField(max_length=255, blank=True, null=True, 
                             default="Title") 
    # Matches app schema
    
    created_at = models.DateTimeField(auto_now_add=True)  # Matches app schema
    updated_at = models.DateTimeField(auto_now=True)  # Matches app schema
    local_only = models.BooleanField(default=False)  # Matches app schema

    
    class Meta:
        verbose_name = "Conversation"
        verbose_name_plural = "Conversations"

    def __str__(self):
        try:
            return f"Conversation {self.conversation_id} by User {self.user_id.user_id}"
        except Exception:
            return f"Conversation {self.conversation_id}"