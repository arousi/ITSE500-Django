"""Unit tests for auth_api serializers and Custom_User password hashing.

These are pure-logic / single-model unit tests (per testing-discipline tier
table) -- no view dispatch, no HTTP layer.
"""
import hashlib

import pyotp
import pytest
from django.conf import settings

from auth_api.serializers import LoginSerializer, RegisterSerializer
from user_mang.models.custom_user import Custom_User


@pytest.mark.django_db
class TestRegisterSerializer:
    def test_valid_data_creates_user_with_hashed_password(self):
        ser = RegisterSerializer(data={"username": "u1", "email": "u1@example.com", "user_password": "mypassword"})
        assert ser.is_valid(), ser.errors
        user = ser.save()
        assert user.user_password is not None
        assert user.user_password != "mypassword"
        salt = getattr(settings, "BACKEND_PASSWORD_SALT", "fallback_dev_salt")
        expected = hashlib.sha256(("mypassword" + salt).encode()).hexdigest()
        assert user.user_password == expected

    def test_duplicate_email_rejected(self):
        Custom_User.objects.create(username="existing", email="dup@example.com")
        ser = RegisterSerializer(data={"username": "new", "email": "dup@example.com", "user_password": "abcdef"})
        assert not ser.is_valid()
        assert "email" in ser.errors

    def test_short_password_rejected(self):
        ser = RegisterSerializer(data={"username": "u2", "email": "u2@example.com", "user_password": "abc"})
        assert not ser.is_valid()
        assert "user_password" in ser.errors

    def test_missing_username_rejected(self):
        ser = RegisterSerializer(data={"username": "", "email": "u3@example.com", "user_password": "abcdef"})
        assert not ser.is_valid()
        assert "username" in ser.errors


@pytest.mark.django_db
class TestLoginSerializer:
    def test_valid_credentials_resolve_user(self):
        user = Custom_User.objects.create(username="loginu", email="loginu@example.com")
        salt = getattr(settings, "BACKEND_PASSWORD_SALT", "fallback_dev_salt")
        user.user_password = hashlib.sha256(("pw123456" + salt).encode()).hexdigest()
        user.save()

        ser = LoginSerializer(data={"identifier": "loginu@example.com", "user_password": "pw123456"})
        assert ser.is_valid(), ser.errors
        assert ser.validated_data["user"].pk == user.pk

    def test_wrong_password_invalid(self):
        user = Custom_User.objects.create(username="loginu2", email="loginu2@example.com")
        salt = getattr(settings, "BACKEND_PASSWORD_SALT", "fallback_dev_salt")
        user.user_password = hashlib.sha256(("pw123456" + salt).encode()).hexdigest()
        user.save()

        ser = LoginSerializer(data={"identifier": "loginu2@example.com", "user_password": "wrongpw"})
        assert not ser.is_valid()

    def test_unknown_identifier_invalid(self):
        ser = LoginSerializer(data={"identifier": "nobody@example.com", "user_password": "pw123456"})
        assert not ser.is_valid()

    def test_missing_identifier_invalid(self):
        ser = LoginSerializer(data={"user_password": "pw123456"})
        assert not ser.is_valid()


@pytest.mark.django_db
class TestCustomUserPasswordHashing:
    def test_set_password_and_check_password_roundtrip(self):
        user = Custom_User(username="pwuser", email="pwuser@example.com")
        user.set_password("correct horse battery staple")
        user.save()
        assert user.check_password("correct horse battery staple") is True
        assert user.check_password("wrong password") is False

    def test_set_password_none_clears_password(self):
        user = Custom_User(username="pwuser2", email="pwuser2@example.com")
        user.set_password(None)
        assert user.user_password is None
        assert user.check_password("anything") is False


class TestPyotpTOTP:
    """Unit coverage for the pyotp-based TOTP helper logic used for 2FA.

    Exercises pyotp directly (the same library auth_api imports) to lock in
    the expected generate/verify contract independent of the (currently
    unwired -- see auth_api.views EnableTOTPView/VerifyTOTPView) view layer.
    """

    def test_generated_code_verifies_against_same_secret(self):
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        code = totp.now()
        assert totp.verify(code) is True

    def test_code_does_not_verify_against_different_secret(self):
        secret_a = pyotp.random_base32()
        secret_b = pyotp.random_base32()
        code = pyotp.TOTP(secret_a).now()
        assert pyotp.TOTP(secret_b).verify(code) is False

    def test_provisioning_uri_contains_issuer_and_account(self):
        secret = pyotp.random_base32()
        uri = pyotp.TOTP(secret).provisioning_uri(name="user@example.com", issuer_name="Prompeteer")
        assert "user%40example.com" in uri or "user@example.com" in uri
        assert "Prompeteer" in uri
