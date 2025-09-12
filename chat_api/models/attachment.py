import uuid
from django.db import models
from django.conf import settings
from .message import Message

def encrypted_upload_path(instance, filename):
    # Store under encrypted/<conversation_id>/<uuid>.bin
    return f"encrypted/{instance.conversation.conversation_id}/{instance.id}.bin"

class Attachment(models.Model):
    """Represents an artifact (image, embedding, document, etc.) optionally encrypted client-side.
    The server stores only ciphertext for encrypted artifacts plus metadata necessary for clients
    to locate and decrypt (nonce/iv, algo, key reference). The raw key material (UMK) lives in
    crypto_api.UserKeyMaterial and is never exposed here.
    """
    attachment_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    message_id = models.ForeignKey(Message, on_delete=models.CASCADE, related_name="attachments")

    type = models.CharField(max_length=32)  # image | embedding | pdf | other
    mime_type = models.CharField(max_length=128, blank=True, null=True)
    file_path = models.CharField(max_length=512, help_text="Server-side storage path or external URL", blank=True, null=True)
    encrypted_blob = models.FileField(upload_to=encrypted_upload_path, blank=True, null=True, help_text="Encrypted ciphertext blob uploaded by client")
    size_bytes = models.BigIntegerField(blank=True, null=True)
    width = models.IntegerField(blank=True, null=True)
    height = models.IntegerField(blank=True, null=True)
    sha256 = models.CharField(max_length=64, blank=True, null=True)

    # Encryption metadata (phase 0 client-side AES-GCM)
    is_encrypted = models.BooleanField(default=False)
    enc_algo = models.CharField(max_length=32, blank=True, null=True)  # e.g. AES-256-GCM
    iv_base64 = models.CharField(max_length=64, blank=True, null=True)
    key_ref = models.CharField(max_length=64, blank=True, null=True)  # future: wrapping / rotation reference

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "attachment"
        indexes = [
            models.Index(fields=["message_id", "created_at"], name="attach_message_created_idx"),
            models.Index(fields=["message_id"], name="attach_message_idx"),
        ]
        ordering = ["created_at"]

    def __str__(self):
        try:
            mid = getattr(self.message_id, 'message_id', None)
        except Exception:
            mid = None
        return f"Attachment {self.attachment_id} ({self.type}) msg={mid}"
