"""crypto_api / UserUMKView tests: user master key (UMK) provisioning.

Covers the state machine of a user's key material:
    (no key) -- POST --> (provisioned) -- POST(rotate=false) --> 409 (no double-provision)
    (no key) -- GET  --> {"exists": false}
    (provisioned) -- GET --> umk metadata

FIXED: UserUMKView.post() previously called
`UserKeyMaterial.objects.create(user=request.user, ...)` and
UserKeyMaterialSerializer.Meta.fields listed "user", but the model's actual
field is `user_id` (a OneToOneField). Both raised immediately:
  - the serializer could never be instantiated (ImproperlyConfigured), and
  - the create() call raised TypeError("unexpected keyword argument 'user'").
Both the view and the serializer now reference `user_id`.
"""
import base64

import pytest
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

from crypto_api.models import UserKeyMaterial

UMK_URL = "/api/v1/crypto_api/umk/"


def _auth(api_client, user):
    refresh = RefreshToken.for_user(user)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")


@pytest.mark.django_db
class TestUserUMKView:
    def test_get_requires_authentication(self, api_client):
        resp = api_client.get(UMK_URL)
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_get_no_key_material_returns_exists_false(self, api_client, make_user):
        user = make_user(username="umkuser1", email="umk1@example.com")
        _auth(api_client, user)
        resp = api_client.get(UMK_URL)
        assert resp.status_code == status.HTTP_200_OK
        assert resp.data == {"exists": False}

    def test_post_provisions_key_material_when_absent(self, api_client, make_user):
        user = make_user(username="umkuser2", email="umk2@example.com")
        _auth(api_client, user)
        resp = api_client.post(UMK_URL, {}, format="json")
        assert resp.status_code == status.HTTP_201_CREATED
        assert UserKeyMaterial.objects.filter(user_id=user).exists()
        # Persisted key must decode to exactly 32 bytes (a valid AES-256 key length)
        ukm = UserKeyMaterial.objects.get(user_id=user)
        assert len(base64.b64decode(ukm.umk_b64)) == 32

    def test_post_accepts_client_provided_key(self, api_client, make_user):
        user = make_user(username="umkuser3", email="umk3@example.com")
        _auth(api_client, user)
        raw_key = base64.b64encode(b"0" * 32).decode()
        resp = api_client.post(UMK_URL, {"umk_b64": raw_key}, format="json")
        assert resp.status_code == status.HTTP_201_CREATED
        ukm = UserKeyMaterial.objects.get(user_id=user)
        assert ukm.umk_b64 == raw_key

    def test_post_rejects_invalid_key_length(self, api_client, make_user):
        user = make_user(username="umkuser4", email="umk4@example.com")
        _auth(api_client, user)
        bad_key = base64.b64encode(b"short").decode()
        resp = api_client.post(UMK_URL, {"umk_b64": bad_key}, format="json")
        assert resp.status_code == status.HTTP_400_BAD_REQUEST
        assert not UserKeyMaterial.objects.filter(user_id=user).exists()

    def test_post_rejects_invalid_base64(self, api_client, make_user):
        user = make_user(username="umkuser5", email="umk5@example.com")
        _auth(api_client, user)
        resp = api_client.post(UMK_URL, {"umk_b64": "not-valid-base64!!"}, format="json")
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    def test_post_already_provisioned_returns_409(self, api_client, make_user):
        user = make_user(username="umkuser6", email="umk6@example.com")
        UserKeyMaterial.objects.create(user_id=user, umk_b64=base64.b64encode(b"1" * 32).decode())
        _auth(api_client, user)
        resp = api_client.post(UMK_URL, {}, format="json")
        assert resp.status_code == status.HTTP_409_CONFLICT

    def test_post_rotate_not_implemented(self, api_client, make_user):
        user = make_user(username="umkuser7", email="umk7@example.com")
        UserKeyMaterial.objects.create(user_id=user, umk_b64=base64.b64encode(b"1" * 32).decode())
        _auth(api_client, user)
        resp = api_client.post(f"{UMK_URL}?rotate=true", {}, format="json")
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    def test_get_after_provisioning_returns_metadata(self, api_client, make_user):
        user = make_user(username="umkuser8", email="umk8@example.com")
        # Provision directly against the model (bypassing the broken POST view -- see
        # bug notes above) so this test exercises the GET contract in isolation.
        UserKeyMaterial.objects.create(user_id=user, umk_b64=base64.b64encode(b"3" * 32).decode())
        _auth(api_client, user)
        resp = api_client.get(UMK_URL)
        assert resp.status_code == status.HTTP_200_OK
        assert resp.data["exists"] is True
        assert "umk_b64" in resp.data

    def test_get_only_returns_own_key_material(self, api_client, make_user):
        """A user must never see another user's UMK metadata."""
        user_a = make_user(username="umkusera", email="umka@example.com")
        user_b = make_user(username="umkuserb", email="umkb@example.com")
        UserKeyMaterial.objects.create(user_id=user_b, umk_b64=base64.b64encode(b"2" * 32).decode())

        _auth(api_client, user_a)
        resp = api_client.get(UMK_URL)
        assert resp.status_code == status.HTTP_200_OK
        assert resp.data == {"exists": False}
