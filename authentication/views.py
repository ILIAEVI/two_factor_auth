import secrets
import pyotp
from django.contrib.auth import authenticate
from rest_framework import status, viewsets, permissions
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from authentication.serializers import UserSerializer, VerifyOtpSerializer, VerifyTwoFactorSerializer
from authentication.models import User, SetupToken, BackupCode
from authentication.permissions import NotAuthenticated, TwoFactorRequired, SetupTokenRequired
from django.utils.crypto import get_random_string


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
                setup_token = secrets.token_urlsafe(32)
                SetupToken.objects.create(user=user, token=setup_token)
                return Response({
                    'setup-token': setup_token,
                    'detail': 'Please Enable 2FA'
                }, status.HTTP_200_OK)
            else:
                return Response({'detail': 'Please Verify Otp'}, status.HTTP_401_UNAUTHORIZED)

        else:
            return Response({
                "error": "Invalid email or password."
            }, status=status.HTTP_400_BAD_REQUEST)

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
            elif BackupCode.objects.filter(user=user, code=entered_otp).exists():
                backup_code = BackupCode.objects.get(user=user, code=entered_otp)
                if backup_code and backup_code.is_active:
                    backup_code.active = False
                    backup_code.save()
                    refresh = RefreshToken.for_user(user)
                    access_token = AccessToken.for_user(user)
                    return Response({
                        'refresh': str(refresh),
                        'access': str(access_token),
                        'detail': 'Logged in successfully with backup code'
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({'detail': 'Backup code is not active'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'detail': 'Invalid OTP'}, status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'detail': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)

    @action(
        detail=False,
        methods=["POST"],
        url_path="enable_2fa",
        permission_classes=[SetupTokenRequired],
    )
    def enable_2fa(self, request):
        setup_token = request.headers.get('setup-token')

        try:
            token_object = SetupToken.objects.get(token=setup_token)
        except SetupToken.DoesNotExist:
            return Response({'detail': 'Setup token does not exist'}, status=status.HTTP_404_NOT_FOUND)

        if token_object.is_valid():
            user = token_object.user
            if user.is_2fa_enabled:
                return Response({"error": "2FA is already enabled"}, status=status.HTTP_400_BAD_REQUEST)

            user.otp_secret = pyotp.random_base32()
            user.save()

            totp = pyotp.TOTP(user.otp_secret)
            provisioning_uri = totp.provisioning_uri(user.email, issuer_name="Secured App")
            return Response({
                'provisioning_uri': provisioning_uri,
                'detail': 'Please verify OTP to complete 2FA setup',
                'setup-token': setup_token,
            }, status=status.HTTP_200_OK)
        else:
            token_object.delete()
            return Response({'detail': 'Setup token is expired, try again'}, status=status.HTTP_400_BAD_REQUEST)

    @action(
        detail=False,
        methods=["POST"],
        url_path="verify_enabled_2fa",
        permission_classes=[SetupTokenRequired],
        serializer_class=VerifyTwoFactorSerializer,
    )
    def verify_enabled_2fa(self, request):
        setup_token = request.headers.get('setup-token')

        try:
            token_object = SetupToken.objects.get(token=setup_token)
        except SetupToken.DoesNotExist:
            return Response({'detail': 'Setup Token does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        user = token_object.user
        if token_object.is_valid():
            serializer = VerifyTwoFactorSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            entered_otp = serializer.validated_data["otp"]

            totp = pyotp.TOTP(user.otp_secret)
            if totp.verify(entered_otp):
                user.is_2fa_enabled = True
                user.save()
                refresh = RefreshToken.for_user(user)
                access_token = AccessToken.for_user(user)
                return Response({
                    'detail': '2FA enabled successfully',
                    'refresh': str(refresh),
                    'access': str(access_token)
                }, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid OTP. Please try again.'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            token_object.delete()
            return Response({'detail': 'Setup token is expired, try again'}, status=status.HTTP_400_BAD_REQUEST)

    @action(
        detail=False,
        methods=["GET"],
        url_path="backup_2fa_code",
        permission_classes=[SetupTokenRequired],
    )
    def backup_2fa_code(self, request):
        setup_token = request.headers.get('setup-token')

        try:
            token_object = SetupToken.objects.get(token=setup_token)
        except SetupToken.DoesNotExist:
            return Response({'detail': 'Invalid setup token'}, status=status.HTTP_400_BAD_REQUEST)

        user = token_object.user
        if token_object.is_valid():
            backup_codes = []
            for _ in range(6):
                code = get_random_string(length=6, allowed_chars='0123456789')
                BackupCode.objects.create(user=user, code=code)
                backup_codes.append(code)

            return Response({'backup_codes': backup_codes}, status=status.HTTP_200_OK)
        else:
            token_object.delete()
            return Response({'detail': 'setup token is expired'}, status=status.HTTP_400_BAD_REQUEST)

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
