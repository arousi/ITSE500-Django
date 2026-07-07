from rest_framework import serializers
from .models import UserKeyMaterial

class UserKeyMaterialSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserKeyMaterial
        fields = ['user_id','umk_b64','version','created_at','updated_at']
        read_only_fields = ['user_id','version','created_at','updated_at']
