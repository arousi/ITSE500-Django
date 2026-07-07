"""chat_api serializers.

Reuse the already-tested Conversation/Message serializers from `user_mang.serializers`
(there is no circular import: user_mang.serializers imports chat_api MODELS, not views).

`MessageWriteSerializer` is a thin subclass used only for POST on the
conversation-scoped message-create endpoint: the parent conversation is resolved
from the URL by the view, so `conversation_id` (and `user_id`) must not be
required from the request body.
"""
from user_mang.serializers import ConversationSerializer, MessageSerializer

__all__ = ["ConversationSerializer", "MessageSerializer", "MessageWriteSerializer"]


class MessageWriteSerializer(MessageSerializer):
    """Write-side Message serializer for the nested conversation messages endpoint.

    The conversation is supplied by the view (from the URL), not the client, so
    `conversation_id` is not required in the request body.
    """

    class Meta(MessageSerializer.Meta):
        pass

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["conversation_id"].required = False
