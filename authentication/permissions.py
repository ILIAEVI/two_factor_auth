from rest_framework import permissions
from rest_framework.exceptions import PermissionDenied

from authentication.models import User


class NotAuthenticated(permissions.BasePermission):
    def has_permission(self, request, view):

        return not request.user or not request.user.is_authenticated


class TwoFactorEnablePermission(permissions.BasePermission):

    def has_permission(self, request, view):
        user = request.user
        if view.action == 'enable_2fa':
            return True

        if not user.is_authenticated and not user.is_2fa_enabled:
            return False

        return True


class TwoFactorIsDisabled(permissions.BasePermission):
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
