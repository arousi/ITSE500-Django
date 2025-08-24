from django.conf import settings
from django.db import models
from django.utils import timezone


class UserKeyMaterial(models.Model):
    """Stores the (phase 0) raw User Master Key (UMK) for client-side encryption.
    Later iterations will store wrapped versions instead of plaintext base64.
    """
    user_id = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="key_material")
    umk_b64 = models.TextField(help_text="Base64 encoded 32-byte user master key")
    version = models.PositiveSmallIntegerField(default=1)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "user_key_material"
        verbose_name = "User Key Material"
        verbose_name_plural = "User Key Materials"

    def __str__(self):
        return f"UserKeyMaterial(user={self.user_id.pk}, version={self.version})"
