from django.db import models
from django.contrib.auth.models import AbstractUser, UserManager
from django.core.exceptions import ValidationError
import uuid
import hashlib
from django.conf import settings

class CustomUserManager(UserManager):
    def _create_user(self, username, email, password, **extra_fields):
        if not username:
            raise ValueError('The given username must be set')
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        if password:
            backend_salt = getattr(settings, 'BACKEND_PASSWORD_SALT', 'fallback_dev_salt')
            salted = (password + backend_salt).encode('utf-8')
            user.user_password = hashlib.sha256(salted).hexdigest()
        user.save(using=self._db)
        return user

    def create_user(self, username, email=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(username, email, password, **extra_fields)

    def create_superuser(self, username, email=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        return self._create_user(username, email, password, **extra_fields)

class Custom_User(AbstractUser):
    user_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)  # Represents userID as the primary key
    is_visitor = models.BooleanField(default=False, help_text="Is this user a guest/visitor?")
    id = None
    phone_number = models.CharField(max_length=15, blank=True, null=True)  # Represents PhoneNumber
    biometric_enabled = models.BooleanField(default=False, blank=True)  # Represents biometric_enabled
    last_modified = models.DateTimeField(auto_now=True)  # Represents last_modified
    user_password = models.CharField(max_length=128, blank=True, null=True)  # Custom password field
    # Make email required but remove default to avoid unique collisions; keep unique constraint
    email = models.EmailField(max_length=254, unique=True)  # Single email field for user
    password = None  # Remove AbstractUser's password field from ORM
    device_id = models.CharField(max_length=128, blank=True, null=True)  # Device identifier from frontend (legacy single device)
    # Temporary local identifier sent by clients before receiving a server UUID
    temp_id = models.CharField(max_length=64, blank=True, null=True, unique=True)
    # List of associated device IDs for this user/visitor
    try:
        related_devices = models.JSONField(default=list, blank=True)
    except Exception:
        # Fallback for older Django versions lacking JSONField on SQLite
        related_devices = models.TextField(blank=True, null=True, help_text="JSON-encoded list of device IDs")
    def set_password(self, raw_password):
        # Set the user_password field instead of password
        self.user_password = raw_password
        self._password = raw_password

    def check_password(self, raw_password):
        # Check the user_password field instead of password
        return self.user_password == raw_password

    @property
    def is_password_usable(self):
        return bool(self.user_password)

    # Email verification fields
    email_pin = models.PositiveSmallIntegerField(blank=True, null=True, help_text="5-digit email verification PIN")
    email_pin_created = models.DateTimeField(blank=True, null=True, help_text="When the PIN was generated")
    email_verified = models.BooleanField(default=False, help_text="Has the user verified their email?")
    is_archived = models.BooleanField(default=False, help_text="Is the user account archived?")
    profile_email_verified = models.BooleanField(default=False)
    profile_email_pin = models.CharField(max_length=10, blank=True, null=True)
    profile_email_pin_created = models.DateTimeField(blank=True, null=True)
    # OTP (One-Time Password) login fields
    login_otp = models.CharField(max_length=10, blank=True, null=True, help_text="Transient OTP for passwordless login")
    login_otp_created = models.DateTimeField(blank=True, null=True)
    login_otp_sent_count = models.PositiveIntegerField(default=0, help_text="Number of OTPs sent in current rate window")
    login_otp_last_sent = models.DateTimeField(blank=True, null=True)
    # Provider flags
    is_google_user = models.BooleanField(default=False, help_text="Account created / linked via Google OAuth")
    is_openrouter_user = models.BooleanField(default=False, help_text="Account created / linked via OpenRouter OAuth")
    totp_secret = models.CharField(max_length=32, blank=True, null=True, help_text="TOTP secret for two-factor authentication app")
    
    def clean(self):
        super().clean()
        if not self.username:
            raise ValidationError({'username': 'This field is required.'})
        if not self.email:
            raise ValidationError({'email': 'This field is required.'})
        # Allow blank user_password during registration (before email is verified)
        if self.email_verified:  # Updated field name
            if not self.user_password:
                raise ValidationError({'user_password': 'This field is required after email verification.'})
            if len(self.user_password) < 6:
                raise ValidationError({'user_password': 'Password must be at least 6 characters long.'})
        elif self.user_password and len(self.user_password) < 6:
            raise ValidationError({'user_password': 'Password must be at least 6 characters long.'})
        if '@' not in self.email:
            raise ValidationError({'email': 'Enter a valid email address.'})

    # No normalized_email property needed; use self.email everywhere

    #* Attributes inherited from AbstractUser Class:
    # username: A string field for the user's username.
    # first_name: A string field for the user's first name.
    # last_name: A string field for the user's last name.
    # is_staff: A boolean field indicating if the user is a staff member.
    # is_active: A boolean field indicating if the user is active.
    # is_superuser: A boolean field indicating if the user is a superuser.
    # date_joined: A datetime field for when the user joined.
    # last_login: A datetime field for the user's last login.

    groups = models.ManyToManyField(
        'auth.Group',
        related_name='custom_user_groups',  # Custom related name
        blank=True
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='custom_user_permissions',  # Custom related name
        blank=True
    )
    objects = CustomUserManager()
    
    def __str__(self):
        return f"User(id={self.user_id}, username={self.username}, email={self.email}, phone={self.phone_number})"

