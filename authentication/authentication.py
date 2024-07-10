from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed


class CustomJWTAuthentication(JWTAuthentication):

    def authenticate(self, request):
        result = super().authenticate(request)
        if result is None:
            return None

        user, token = result
        if user is not None:
            if not user.is_2fa_enabled:
                raise AuthenticationFailed('2FA is not enabled')
        return user, token
