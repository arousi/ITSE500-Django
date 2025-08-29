from django.db import models

class MessageResponse(models.Model):
    # search the primary key field matter in django
    response_id = models.CharField(max_length=255, blank=True, primary_key=True)
    object = models.CharField(max_length=50, blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    status = models.CharField(max_length=50, blank=True, null=True)
    error = models.TextField(blank=True, null=True, default="null")
    incomplete_details = models.TextField(blank=True, null=True, default="null")
    max_output_tokens = models.IntegerField(blank=True, null=True, default=None)
    model_name = models.CharField(max_length=255, blank=True, null=True, default="unassigned")
    parallel_tool_calls = models.BooleanField(default=False)
    previous_response_id = models.CharField(max_length=255, blank=True, null=True, default="unassigned")
    instructions = models.TextField(blank=True, null=True)
    
    reasoning_effort = models.TextField(blank=True, null=True, default="null")
    reasoning_summary = models.TextField(blank=True, null=True, default="null")
    
    store = models.BooleanField(default=True)
    temperature = models.FloatField(blank=True, null=True, default=1.0)
    text_format_type = models.CharField(max_length=50, blank=True, null=True)
    tool_choice = models.CharField(max_length=255, blank=True, null=True)
    tools = models.TextField(blank=True, null=True)
    top_p = models.FloatField(blank=True, null=True)
    truncation = models.CharField(max_length=50, blank=True, null=True)

    usage_input_tokens = models.IntegerField(blank=True, null=True)
    #usage_input_tokens_details
    usage_output_tokens = models.IntegerField(blank=True, null=True)
    #usage_output_tokens_details
    usage_total_tokens = models.IntegerField(blank=True, null=True)
    
    user = models.CharField(max_length=255, blank=True, null=True, default="null")
    metadata = models.JSONField(blank=True, null=True)

    def __str__(self):
        return f"MessageResponse {self.response_id}"
