import base64
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
# from django.utils.crypto import get_random_string
from .models import UserKeyMaterial
from .serializers import UserKeyMaterialSerializer

class UserUMKView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        """Return the caller's UMK metadata + base64 (phase 0)."""
        try:
            ukm = request.user.key_material
        except UserKeyMaterial.DoesNotExist:
            return Response({"exists": False}, status=status.HTTP_200_OK)
        else:
            ser = UserKeyMaterialSerializer(ukm)
            data = dict(ser.data)
            data['exists'] = True
            return Response(data, status=status.HTTP_200_OK)

    def post(self, request):
        """Provision UMK once. Reject if already exists unless rotate=true (not yet supported)."""
        rotate = request.query_params.get('rotate') == 'true'
        if hasattr(request.user, 'key_material') and not rotate:
            return Response({'error': 'UMK already provisioned'}, status=status.HTTP_409_CONFLICT)
        if rotate:
            return Response({'error': 'Rotation not implemented'}, status=status.HTTP_400_BAD_REQUEST)
        # Accept optional client-provided umk_b64 else generate securely server-side and return.
        umk_b64 = request.data.get('umk_b64')
        if umk_b64:
            try:
                raw = base64.b64decode(umk_b64)
                if len(raw) != 32:
                    return Response({'error': 'Provided key must decode to 32 bytes'}, status=status.HTTP_400_BAD_REQUEST)
            except Exception:
                return Response({'error': 'Invalid base64 for umk_b64'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            # Server generate 32 random bytes and base64 encode
            import os
            raw = os.urandom(32)
            umk_b64 = base64.b64encode(raw).decode('utf-8')
        ukm = UserKeyMaterial.objects.create(user=request.user, umk_b64=umk_b64)
        return Response(UserKeyMaterialSerializer(ukm).data, status=status.HTTP_201_CREATED)
