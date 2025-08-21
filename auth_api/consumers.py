import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer

logger = logging.getLogger(__name__)

class UserNotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        """Assign user to a WebSocket group based on their user_id"""
        user_id = self.scope["url_route"]["kwargs"]["user_id"]
        self.group_name = f"user_{user_id}"
        
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        """Remove user from the WebSocket group on disconnect"""
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def send_relogin_message(self, event):
        """Send a re-login message to the user"""
        await self.send(text_data=json.dumps({"message": "re-login"}))

    async def send_otp_notification(self, event):
        """Send OTP-related notifications to the user"""
        otp_status = event.get("otp_status", "unknown")
        await self.send(text_data=json.dumps({"message": f"OTP status: {otp_status}"}))
        logger.info(f"OTP notification sent: {otp_status}")

    async def send_oauth_notification(self, event):
        """Send OAuth-related notifications to the user"""
        oauth_status = event.get("oauth_status", "unknown")
        await self.send(text_data=json.dumps({"message": f"OAuth status: {oauth_status}"}))
        logger.info(f"OAuth notification sent: {oauth_status}")

    async def handle_error(self, event):
        """Handle errors and notify the user"""
        error_message = event.get("error_message", "An error occurred")
        await self.send(text_data=json.dumps({"error": error_message}))
        logger.error(f"Error notification sent: {error_message}")
