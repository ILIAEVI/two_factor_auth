from rest_framework import permissions
from rest_framework.exceptions import PermissionDenied

from authentication.models import User, SetupToken


class NotAuthenticated(permissions.BasePermission):
    def has_permission(self, request, view):

        return not request.user or not request.user.is_authenticated


class SetupTokenRequired(permissions.BasePermission):

    def has_permission(self, request, view):
        setup_token = request.headers.get('setup-token')
        if not setup_token:
            return False

        try:
            token_object = SetupToken.objects.get(token=setup_token)
            if token_object.token == setup_token and token_object.is_valid():
                return True
        except SetupToken.DoesNotExist:
            return False

        return False


class TwoFactorRequired(permissions.BasePermission):
    def has_permission(self, request, view):
        email = request.data['email']

        if email:
            try:
                user = User.objects.get(email=email)
                if not user.is_2fa_enabled:
                    raise PermissionDenied("Please enable 2FA before verifying OTP.")
            except User.DoesNotExist:
                return False
        return True
