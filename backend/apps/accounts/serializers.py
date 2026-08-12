"""Serializers de autenticação e usuários (RF001, RF002, RF003)."""

from __future__ import annotations

from typing import Any

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    """Representação pública de um usuário (sem dados sensíveis)."""

    class Meta:
        model = User
        fields = ("id", "email", "role", "is_active")
        read_only_fields = fields


class LoginSerializer(TokenObtainPairSerializer):
    """Login por email/senha que devolve os tokens e o usuário (api.md)."""

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        data = super().validate(attrs)
        data["user"] = UserSerializer(self.user).data
        return data


class RegisterSerializer(serializers.ModelSerializer):
    """Cadastro de usuário (restrito a admin — RF002).

    A senha é validada pela política de senha forte e nunca é retornada.
    """

    password = serializers.CharField(write_only=True, style={"input_type": "password"})

    class Meta:
        model = User
        fields = ("id", "email", "password", "role")
        read_only_fields = ("id",)

    def validate_password(self, value: str) -> str:
        validate_password(value)
        return value

    def create(self, validated_data: dict[str, Any]) -> Any:
        password = validated_data.pop("password")
        return User.objects.create_user(password=password, **validated_data)


class LogoutSerializer(serializers.Serializer):
    """Recebe o refresh token a ser invalidado (blacklist)."""

    refresh = serializers.CharField()
