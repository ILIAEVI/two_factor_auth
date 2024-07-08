from io import BytesIO
import pyotp
import qrcode
from django.contrib.auth import authenticate, login
from rest_framework import status, viewsets, permissions
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken

from authentication.serializers import UserSerializer, VerifyOtpSerializer
from authentication.models import User
from django.http import FileResponse
from authentication.permissions import NotAuthenticated, TwoFactorEnablePermission, TwoFactorRequired


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all().order_by('id')
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAdminUser]

    @action(
        detail=False,
        methods=["POST"],
        url_path="login",
        serializer_class=UserSerializer,
        permission_classes=[NotAuthenticated],
    )
    def login(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        user = authenticate(request, email=email, password=password)

        if user:
            if not user.is_2fa_enabled:
                refresh = RefreshToken.for_user(user)
                access_token = AccessToken.for_user(user)
                return Response({
                    'refresh': str(refresh),
                    'access': str(access_token),
                    'detail': 'Please Enable 2FA'
                }, status.HTTP_200_OK)
            else:
                return Response({'detail': 'Please Verify Otp'}, status.HTTP_401_UNAUTHORIZED) # change status

        else:
            return Response({
                "error": "Invalid email or password."
            }, status=status.HTTP_401_UNAUTHORIZED)

    @action(
        detail=False,
        methods=["POST"],
        url_path="verify_otp",
        serializer_class=VerifyOtpSerializer,
        permission_classes=[NotAuthenticated, TwoFactorRequired],
    )
    def verify_otp(self, request):
        serializer = VerifyOtpSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]
        entered_otp = serializer.validated_data["otp"]
        try:
            user = authenticate(request, email=email, password=password)

            totp = pyotp.TOTP(user.otp_secret)
            if totp.verify(entered_otp):
                refresh = RefreshToken.for_user(user)
                access_token = AccessToken.for_user(user)
                return Response({
                    'refresh': str(refresh),
                    'access': str(access_token)
                }, status.HTTP_200_OK)
            else:
                return Response({'detail': 'Invalid OTP'}, status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({'detail': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)

    @action(
        detail=False,
        methods=["POST"],
        url_path="enable_2fa",
        permission_classes=[TwoFactorEnablePermission],
    )
    def enable_2fa(self, request):
        user = request.user
        if user.is_2fa_enabled:
            return Response({"error": "2FA is already enabled"}, status=status.HTTP_400_BAD_REQUEST)

        user.otp_secret = pyotp.random_base32()
        user.is_2fa_enabled = True
        user.save()

        totp = pyotp.TOTP(user.otp_secret)
        provisioning_uri = totp.provisioning_uri(user.email, issuer_name="Secured App")
        return Response({'provisioning_uri': provisioning_uri}, status=status.HTTP_200_OK)

    @action(
        detail=False,
        methods=["GET"],
        url_path="get_qr_code",
        permission_classes=[permissions.IsAuthenticated],
    )
    def get_qr_code(self, request):
        user = request.user
        if user.is_2fa_enabled:
            totp = pyotp.TOTP(user.otp_secret)
            provisioning_uri = totp.provisioning_uri(user.email, issuer_name="Secured App")
            return Response({'provisioning_uri': provisioning_uri}, status=status.HTTP_200_OK)
        else:
            return Response({'error': '2fa is not enabled'}, status=status.HTTP_400_BAD_REQUEST)




