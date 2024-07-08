from authentication.models import User
from rest_framework import serializers
import pyotp


class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('email', 'password')


class VerifyOtpSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True)
    otp = serializers.CharField(max_length=6)

    class Meta:
        model = User
        fields = ('email', 'password', 'otp')


class VerifyTwoFactorSerializer(serializers.ModelSerializer):
    otp = serializers.CharField(max_length=6)

    class Meta:
        model = User
        fields = ['otp']
