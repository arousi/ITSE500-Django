from rest_framework import serializers
from .models import Conversation, Message, MessageRequest, MessageResponse, MessageOutput, Attachment


class MessageRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = MessageRequest
        fields = '__all__'


class MessageResponseSerializer(serializers.ModelSerializer):
    class Meta:
        model = MessageResponse
        fields = '__all__'


class MessageOutputSerializer(serializers.ModelSerializer):
    class Meta:
        model = MessageOutput
        fields = '__all__'


class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = [
            'message_id','user_id','conversation_id','request_id','response_id','output_id','timestamp',
            'has_image','img_Url','metadata','has_embedding','has_document','doc_url','vote'
        ]


class ConversationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Conversation
        fields = ['conversation_id','user_id','title','created_at','updated_at','local_only']


class AttachmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attachment
        fields = [
            'id','user','conversation','message','type','mime_type','file_path','encrypted_blob',
            'size_bytes','width','height','sha256',
            'is_encrypted','enc_algo','iv_base64','key_ref','created_at'
        ]
        read_only_fields = ['id','created_at','user','file_path','sha256','size_bytes','width','height']

    def create(self, validated_data):
        request = self.context.get('request')
        if request and request.user and not validated_data.get('user'):
            validated_data['user'] = request.user
        instance = super().create(validated_data)
        # Auto-populate file_path from stored file if missing
        if instance.encrypted_blob and not instance.file_path:
            instance.file_path = instance.encrypted_blob.name
            if not instance.size_bytes:
                try:
                    instance.size_bytes = instance.encrypted_blob.size
                except Exception:
                    pass
            instance.save(update_fields=['file_path','size_bytes'])
        return instance
