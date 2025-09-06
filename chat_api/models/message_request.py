import uuid
from django.db import models

class MessageRequest(models.Model):
    request_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    request_model = models.CharField(max_length=255, blank=True, null=True)
    request_input = models.TextField(blank=True, null=True)
    request_system_role = models.CharField(max_length=50, blank=True, null=True)
    request_system_content = models.TextField(blank=True, null=True)
    # Added to support unified system prompt separate from role/content 
    # (multi-provider)
    request_system_prompt = models.TextField(blank=True, null=True)
    # Structured output control flags (front-end sync)
    request_user_structured_output = models.BooleanField(blank=True, null=True)
    request_structured_schema = models.TextField(blank=True, null=True)
    request_user_role = models.CharField(max_length=50, blank=True, null=True)
    request_user_content = models.TextField(blank=True, null=True) 
    #ACTUAL USER MESSAGE
    request_min_p = models.FloatField(blank=True, null=True)
    request_temperature = models.FloatField(blank=True, null=True)
    request_top_p = models.FloatField(blank=True, null=True)
    request_n = models.IntegerField(blank=True, null=True)
    request_top_k = models.IntegerField(blank=True, null=True)
    request_stream = models.BooleanField(default=False)
    request_stop = models.TextField(blank=True, null=True)
    request_max_tokens = models.IntegerField(blank=True, null=True)
    repeat_penalty = models.FloatField(blank=True, null=True)
    
    def __str__(self):
        return f"MessageRequest {self.request_id}"
