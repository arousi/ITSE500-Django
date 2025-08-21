from django.db import models

class MessageOutput(models.Model):
    output_type = models.CharField(max_length=50, blank=True, null=True, default="message")
    output_id = models.CharField(max_length=255, blank=True, null=True)
    #from provider response
    output_status = models.CharField(max_length=50, blank=True, null=True)
    output_role = models.CharField(max_length=50, blank=True, null=True)
    output_content_type = models.CharField(max_length=50, blank=True, null=True)
    output_content_text = models.TextField(blank=True, null=True) #REAL OUTPUT OF LLM
    output_content_annotations = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"MessageOutput {self.id}"
