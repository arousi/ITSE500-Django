import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from .models import Custom_User
from .serializers import CustomeUserSerializer

# Get a logger specific to the user_mang app
logger = logging.getLogger('user_mang')

class UserDetailView(APIView):
    """
    Retrieve, update, or archive the authenticated user's data.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        """
        Return authenticated user's data, or confirm state if last_modified matches.
        If the user is inactive, block access.
        """
        logger.info(f"Authorization header: {request.headers.get('Authorization')}")
        logger.info(f"Request headers: {request.headers}")
        user = request.user
        if not user.is_active:
            logger.warning(f"User {user.pk} attempted access with inactive account.")
            return Response({"error": "Account is locked or inactive."}, status=status.HTTP_403_FORBIDDEN)
        last_modified_param = request.query_params.get('last_modified')
        logger.info(f"UserDetailView GET called for user_id={user.pk}")
        if last_modified_param:
            # Compare ISO format
            user_last_modified = user.last_modified.isoformat() if user.last_modified else None
            if user_last_modified == last_modified_param:
                logger.info(f"User {user.pk} data is up-to-date.")
                return Response({"status": "up-to-date", "last_modified": user_last_modified}, status=status.HTTP_200_OK)
        serializer = CustomeUserSerializer(user)
        logger.info(f"User {user.pk} data returned.")
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        """
        Update authenticated user's data only if the data is not up-to-date.
        If the user is inactive, block update.
        If last_modified param is provided and matches, return up-to-date status.
        """
        logger.info(f"Authorization header: {request.headers.get('Authorization')}")
        logger.info(f"Request headers: {request.headers}")
        user = request.user
        if not user.is_active:
            logger.warning(f"User {user.pk} attempted update with inactive account.")
            return Response({"error": "Account is locked or inactive."}, status=status.HTTP_403_FORBIDDEN)
        last_modified_param = request.data.get('last_modified') or request.query_params.get('last_modified')
        user_last_modified = user.last_modified.isoformat() if user.last_modified else None
        if last_modified_param and user_last_modified == last_modified_param:
            logger.info(f"User {user.pk} attempted update but data is up-to-date.")
            return Response({"status": "up-to-date", "last_modified": user_last_modified}, status=status.HTTP_200_OK)
        logger.info(f"UserDetailView PUT called for user_id={user.pk}")
        serializer = CustomeUserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            logger.info(f"User {user.pk} updated successfully.")
            return Response(serializer.data, status=status.HTTP_200_OK)
        logger.warning(f"User {user.pk} update failed: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        """Archive or delete authenticated user.

        Side effects:
        - Purge stored provider OAuth tokens.
        - On archive: deactivate & clear provider linkage flags.
        """
        from auth_api.models import ProviderOAuthToken  # lazy import
        user = request.user
        delete_param = request.query_params.get('delete', 'false').lower()
        # Capture optional reason (from JSON body or query param)
        reason = None
        try:
            reason = request.data.get('reason') if hasattr(request, 'data') else None
        except Exception:
            reason = None
        if not reason:
            reason = request.query_params.get('reason')
        ProviderOAuthToken.objects.filter(user=user).delete()
        if delete_param == 'true':
            uid = user.pk
            if reason:
                logger.info(f"User {uid} deletion reason: {reason[:500]}")
            user.delete()
            logger.info(f"User {uid} deleted and tokens purged.")
            return Response({"message": "User deleted successfully"}, status=status.HTTP_200_OK)
        user.is_archived = True
        user.is_active = False
        changed = ['is_archived', 'is_active']
        if getattr(user, 'is_google_user', False):
            user.is_google_user = False
            changed.append('is_google_user')
        if getattr(user, 'is_openrouter_user', False):
            user.is_openrouter_user = False
            changed.append('is_openrouter_user')
        user.save(update_fields=changed)
        if reason:
            logger.info(f"User {user.pk} archive reason: {reason[:500]}")
        logger.info(f"User {user.pk} archived; tokens purged & provider flags cleared.")
        return Response({"message": "User archived successfully"}, status=status.HTTP_200_OK)

class AdminUserDetailView(APIView):
    """
    Admin: Retrieve, update, or archive any user's data by user_id.
    """
    permission_classes = [permissions.IsAdminUser]

    def get(self, request, user_id):
        """Return user data for given user_id."""
        try:
            user = Custom_User.objects.get(pk=user_id)
            logger.info(f"AdminUserDetailView GET for user_id={user_id}")
            serializer = CustomeUserSerializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Custom_User.DoesNotExist:
            logger.warning(f"AdminUserDetailView GET failed: user_id={user_id} not found")
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    def put(self, request, user_id):
        """Update user data for given user_id."""
        try:
            user = Custom_User.objects.get(pk=user_id)
            logger.info(f"AdminUserDetailView PUT for user_id={user_id}")
            serializer = CustomeUserSerializer(user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                logger.info(f"User {user_id} updated by admin.")
                return Response(serializer.data, status=status.HTTP_200_OK)
            logger.warning(f"AdminUserDetailView PUT failed for user_id={user_id}: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Custom_User.DoesNotExist:
            logger.warning(f"AdminUserDetailView PUT failed: user_id={user_id} not found")
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, user_id):
        """Archive user account for given user_id."""
        try:
            user = Custom_User.objects.get(pk=user_id)
            user.is_active = False
            user.save()
            logger.info(f"User {user_id} archived by admin.")
            return Response({"message": "User archived successfully"}, status=status.HTTP_200_OK)
        except Custom_User.DoesNotExist:
            logger.warning(f"AdminUserDetailView DELETE failed: user_id={user_id} not found")
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
