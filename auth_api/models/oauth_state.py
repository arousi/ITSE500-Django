
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.contrib.auth import get_user_model
import uuid
from user_mang.models.custom_user import Custom_User


class OAuthState(models.Model):
	"""Ephemeral server-side record for PKCE / state validation.

	We store the plain code_verifier temporarily (<=10 min) until the callback
	so the mobile / web client never has to persist it.
	After successful token exchange we null out the code_verifier field.
	"""

	PROVIDER_CHOICES = (
		("openrouter", "OpenRouter"),
		("google", "Google"),
		("github", "GitHub"),
		("microsoft", "Microsoft"),
	)
	user_id = models.ForeignKey(Custom_User, null=True, blank=True, on_delete=models.SET_NULL, related_name="oauth_states")
	oauth_state_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
	provider = models.CharField(max_length=32, choices=PROVIDER_CHOICES)
	state = models.CharField(max_length=128, unique=True, db_index=True)
	code_challenge = models.CharField(max_length=256)
	code_verifier = models.CharField(max_length=256, blank=True, null=True)
	redirect_uri = models.CharField(max_length=512, blank=True, null=True)
	# If the client initiated with a custom scheme (mobile deep link), we store it here
	mobile_redirect = models.CharField(max_length=512, blank=True, null=True)
	# Server-stored final result payload (JWT + provider token metadata) for bridge flows
	result_payload = models.TextField(blank=True, null=True)
	result_retrieved = models.BooleanField(default=False)
	scope = models.CharField(max_length=512, blank=True, null=True)
	
	created_at = models.DateTimeField(auto_now_add=True)
	expires_at = models.DateTimeField()
	is_used = models.BooleanField(default=False)

	def is_expired(self):
		return timezone.now() >= self.expires_at

	def mark_used(self):
		# Mark this state as used and drop the verifier for security
		self.is_used = True
		self.code_verifier = None
		self.save(update_fields=["is_used", "code_verifier"])

	@property
	def used(self):
		"""Backward-compatible alias for the boolean flag.
		Some existing code references `used`; keep a property so both work.
		"""
		return bool(self.is_used)

	@used.setter
	def used(self, val: bool):
		self.is_used = bool(val)

	def __str__(self):
		return f"OAuthState(provider={self.provider}, state={self.state}, used={self.is_used})"

