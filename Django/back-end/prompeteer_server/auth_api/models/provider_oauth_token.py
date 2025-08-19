

from django.db import models
from django.conf import settings
from django.utils import timezone
import uuid
import base64
import hashlib
import logging
from typing import Any, Optional, Callable

from user_mang.models.custom_user import Custom_User
from .oauth_state import OAuthState

logger = logging.getLogger('auth_api')

try:  # optional strong encryption
	from cryptography.fernet import Fernet  # type: ignore
	_CRYPTO_OK = True
except Exception:  # pragma: no cover
	Fernet = None  # type: ignore
	_CRYPTO_OK = False


def _build_fernet():
	if not _CRYPTO_OK or Fernet is None:  # type: ignore[truthy-bool]
		return None
	secret = getattr(settings, 'OAUTH_TOKEN_ENCRYPTION_KEY', None) or settings.SECRET_KEY
	key_material = hashlib.sha256(secret.encode('utf-8')).digest()
	key_b64 = base64.urlsafe_b64encode(key_material)
	try:
		F: Callable[[bytes], Any] = Fernet  # type: ignore[assignment]
		return F(key_b64)
	except Exception:
		logger.exception("[ProviderOAuthToken] Failed to init Fernet; using obfuscation fallback")
		return None

_FERNET = _build_fernet()


def _simple_obfuscate(raw: str) -> str:
	secret = settings.SECRET_KEY.encode('utf-8')
	rb = raw.encode('utf-8')
	xored = bytes(b ^ secret[i % len(secret)] for i, b in enumerate(rb))
	return 'obf:' + base64.urlsafe_b64encode(xored).decode('utf-8')


def _simple_deobfuscate(data: str) -> str:
	payload_b64 = data[4:]
	xored = base64.urlsafe_b64decode(payload_b64.encode('utf-8'))
	secret = settings.SECRET_KEY.encode('utf-8')
	raw_b = bytes(b ^ secret[i % len(secret)] for i, b in enumerate(xored))
	return raw_b.decode('utf-8')


def encrypt_token(raw: str | None) -> str | None:
	if raw is None:
		return None
	try:
		if _FERNET:
			return 'enc:' + _FERNET.encrypt(raw.encode('utf-8')).decode('utf-8')
		return _simple_obfuscate(raw)
	except Exception:
		logger.exception("[ProviderOAuthToken] Encryption failed, using obfuscation")
		return _simple_obfuscate(raw)


def decrypt_token(stored: str | None) -> str | None:
	if stored is None:
		return None
	try:
		if stored.startswith('enc:') and _FERNET:
			return _FERNET.decrypt(stored[4:].encode('utf-8')).decode('utf-8')
		if stored.startswith('obf:'):
			return _simple_deobfuscate(stored)
		return stored  # legacy plain
	except Exception:
		logger.exception("[ProviderOAuthToken] Decryption failed, returning raw value")
		return stored

class ProviderOAuthToken(models.Model):
	"""Persisted provider access/refresh tokens per user.

	NOTE: For production consider encrypting these fields at rest.
	"""

	PROVIDER_CHOICES = OAuthState.PROVIDER_CHOICES

	id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
	user = models.ForeignKey(Custom_User, on_delete=models.CASCADE, related_name="provider_tokens")
	provider = models.CharField(max_length=32, choices=PROVIDER_CHOICES, db_index=True)
	access_token = models.TextField()
	refresh_token = models.TextField(blank=True, null=True)
	token_type = models.CharField(max_length=32, blank=True, null=True)
	scope = models.CharField(max_length=512, blank=True, null=True)
	expires_at = models.DateTimeField(blank=True, null=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		unique_together = ("user", "provider")

	def expired(self):
		return self.expires_at and timezone.now() >= self.expires_at

	def set_tokens(self, access: str | None, refresh: str | None):
		if access is not None:
			self.access_token = encrypt_token(access)  # type: ignore[assignment]
		if refresh is not None:
			self.refresh_token = encrypt_token(refresh)  # type: ignore[assignment]

	def get_access_token(self) -> str | None:
		return decrypt_token(self.access_token)

	def get_refresh_token(self) -> str | None:
		return decrypt_token(self.refresh_token)

	def save(self, *args, **kwargs):  # type: ignore[override]
		def needs_enc(val: str | None) -> bool:
			return bool(val) and not (val.startswith('enc:') or val.startswith('obf:'))
		if needs_enc(getattr(self, 'access_token', None)):
			self.access_token = encrypt_token(decrypt_token(self.access_token))  # type: ignore[assignment]
		if needs_enc(getattr(self, 'refresh_token', None)):
			self.refresh_token = encrypt_token(decrypt_token(self.refresh_token))  # type: ignore[assignment]
		super().save(*args, **kwargs)

	def __str__(self):
		return f"ProviderOAuthToken(user={self.user.id}, provider={self.provider})"

