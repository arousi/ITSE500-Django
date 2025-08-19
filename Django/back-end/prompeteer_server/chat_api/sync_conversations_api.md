# SyncConversationsView API Documentation

## Endpoint

`/api/sync-conversations/`  
(Method: `POST` or `GET`)

### URL Parameters

- For unregistered users: `?anon_id=<anon_id>`
- For registered users: `?user_id=<user_id>`

---

## POST: Sync Conversations and Messages

### Request Body

```json
{
  "conversations": [
    {
      "id": "conversation-uuid",
      "title": "Conversation Title",
      "created_at": "2025-07-27T12:34:56Z",
      "updated_at": "2025-07-27T12:34:56Z",
      "local_only": false,
      // ...other Conversation fields...
      "messages": [
        {
          "message_id": "message-uuid",
          "timestamp": "2025-07-27T12:35:00Z",
          "vote": true,
          "img": null,
          "metadata": {},
          "embedding": {},
          "doc": null,
          // ...other Message fields...
          "request": {
            // MessageRequest fields
            "id": 1,
            "request_model": "gpt-4",
            "request_messages_role": "user"
            // ...other request fields...
          },
          "response": {
            // MessageResponse fields
            "id": 1,
            "response_id": "resp_123",
            "model": "gpt-4"
            // ...other response fields...
          },
          "output": {
            // MessageOutput fields
            "id": 1,
            "output_type": "text",
            "output_content_text": "Hello!"
            // ...other output fields...
          }
        }
      ]
    }
  ]
}
```

- All fields for `Conversation`, `Message`, `MessageRequest`, `MessageResponse`, and `MessageOutput` should match your backend schema.
- The `messages` array is optional for each conversation.
- The `request`, `response`, and `output` objects are optional for each message.

---

### Response

On success (`200 OK`):

```json
{
  "message": "X conversations created, Y updated. Z messages created, W updated.",
  "created": X,
  "updated": Y,
  "messages_created": Z,
  "messages_updated": W
}
```

On error (e.g., missing visitor):

```json
{
  "error": "Visitor not found"
}

```

On error (e.g., invalid format):

```json
{
  "error": "Invalid conversations format"
}
```

---

## GET: Fetch Conversation IDs

### Response

```json
{
  "conversations": [
    "conversation-uuid-1",
    "conversation-uuid-2"
    // ...
  ]
}
```

---

## Notes

- The endpoint supports both registered (`user_id`) and unregistered (`anon_id`) users.
- All nested objects (`request`, `response`, `output`) are created/updated in their respective normalized tables.
- All fields must match the backend schema for successful validation.
