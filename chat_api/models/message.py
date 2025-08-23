
import uuid
from django.db import models
from user_mang.models.custom_user import Custom_User
from chat_api.models.conversation import Conversation
from django.core.exceptions import ValidationError
import json
# Normalized related fields
from .message_request import MessageRequest
from .message_response import MessageResponse
from .message_output import MessageOutput



def validate_image_size(image):
        max_size_kb = 1024  # Maximum size in KB
        if image.size > max_size_kb * 1024:
            raise ValidationError(f"Image size should not exceed {max_size_kb} KB.")


def validate_metadata_size(metadata):
        max_size_bytes = 4096  # Maximum allowed size in bytes
        try:
            metadata_str = json.dumps(metadata)
        except (TypeError, ValueError):
            raise ValidationError("Invalid metadata format.")
        if len(metadata_str.encode("utf-8")) > max_size_bytes:
            raise ValidationError(f"Metadata size should not exceed {max_size_bytes} bytes.")

def validate_embedding_size(embedding):
        max_size_bytes = 4096  # Maximum allowed size in bytes for embedding
        try:
            embedding_str = json.dumps(embedding)
        except (TypeError, ValueError):
            raise ValidationError("Invalid embedding format.")
        if len(embedding_str.encode("utf-8")) > max_size_bytes:
            raise ValidationError(f"Embedding size should not exceed {max_size_bytes} bytes.")


def validate_document_size(document):
        max_size_bytes = 10485760  # Maximum allowed size in bytes (10 MB)
        if document.size > max_size_bytes:
            raise ValidationError(f"Document size should not exceed {max_size_bytes / 1048576} MB.")

class Message(models.Model):
    
    # created by our system.
    message_id = models.UUIDField(primary_key=True, default=uuid.uuid4,
                                  editable=False)  # Represents messageID
    # we do conv id from front end
    
    user_id = models.ForeignKey(Custom_User, on_delete=models.CASCADE,
                                related_name="messages")  # Foreign key to Custom_User
    request_id = models.OneToOneField(#we do the req id from front end
        MessageRequest,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name="message"
    )

    response_id = models.OneToOneField( # response id from provider
        MessageResponse,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name="message"
    )

    output_id = models.OneToOneField( # representing the output[] array of the
                                      # response
        MessageOutput,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name="message"
    )

    timestamp = models.DateTimeField(auto_now_add=True)  # Matches app schema

    has_image = models.BooleanField(
        default=False)  # Represents whether the message has an associated image
    
    img_Url = models.ImageField(
        upload_to="message_images/",
        blank=True,
        null=True,
        validators=[
            validate_image_size
        ]
    )  # Matches app schema

    metadata = models.JSONField(
        blank=True,
        null=True,
        validators=[
            validate_metadata_size
        ]
    )  # Matches app schema

    has_embedding = models.BooleanField( # store in response
        default=False)

    has_document = models.BooleanField(
        default=False)  # Represents whether the message has an associated document 
    doc_url = models.FileField(
        upload_to="message_docs/",
        blank=True,
        null=True,
        validators=[
            validate_document_size
        ]
    )  # Represents document content

    

    vote = models.BooleanField(default=False, blank=True, null=True)  # Matches app schema
    
    def __str__(self):
        return f"Message {self.message_id}"

    class Meta:
        verbose_name = "Message"
        verbose_name_plural = "Messages"
