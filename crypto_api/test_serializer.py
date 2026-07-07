"""Regression test for UserKeyMaterialSerializer field/model mismatch.

Bug: `Meta.fields` referenced `user`, but the UserKeyMaterial model's field is
named `user_id` (a OneToOneField). Serializing a UserKeyMaterial instance
raised (DRF cannot build a field for a `user` attribute the model doesn't have),
which would 500 on GET /crypto_api/... in production.
"""
from django.test import TestCase

from user_mang.models.custom_user import Custom_User
from crypto_api.models import UserKeyMaterial
from crypto_api.serializers import UserKeyMaterialSerializer


class UserKeyMaterialSerializerFieldMismatchTest(TestCase):
    def setUp(self):
        self.user = Custom_User.objects.create(
            username="alice", email="alice@example.com", is_active=True, email_verified=True,
        )
        self.ukm = UserKeyMaterial.objects.create(user_id=self.user, umk_b64="abc123==")

    def test_serializing_user_key_material_does_not_raise(self):
        data = UserKeyMaterialSerializer(self.ukm).data
        self.assertEqual(str(data["user_id"]), str(self.user.pk))
        self.assertEqual(data["umk_b64"], "abc123==")
