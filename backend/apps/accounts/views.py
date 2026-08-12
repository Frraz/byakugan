"""Views de autenticação e gestão de usuários (RF001–RF003).

Views finas: apenas orquestram request/response. Regras de senha/RBAC ficam
nos serializers e nas permission classes.
"""

from __future__ import annotations

from rest_framework import status
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from apps.core.audit import client_ip, record_audit
from apps.core.permissions import IsAdmin

from .serializers import LoginSerializer, LogoutSerializer, RegisterSerializer, UserSerializer


class LoginView(TokenObtainPairView):
    """Emite access/refresh e registra a autenticação (RN011)."""

    serializer_class = LoginSerializer

    def post(self, request: Request, *args, **kwargs) -> Response:
        response = super().post(request, *args, **kwargs)
        if response.status_code == status.HTTP_200_OK:
            record_audit(
                "auth.login",
                user_email=request.data.get("email"),
                severity="info",
                source=client_ip(request),
            )
        return response


class LogoutView(APIView):
    """Invalida o refresh token (blacklist) e audita o logout."""

    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            RefreshToken(serializer.validated_data["refresh"]).blacklist()
        except TokenError:
            return Response(
                {"detail": "Refresh token inválido ou já expirado."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        record_audit(
            "auth.logout",
            user=request.user,
            severity="info",
            source=client_ip(request),
        )
        return Response(status=status.HTTP_205_RESET_CONTENT)


class RegisterView(CreateAPIView):
    """Cria usuários — restrito a administradores (RF002 / RN006)."""

    serializer_class = RegisterSerializer
    permission_classes = [IsAdmin]

    def perform_create(self, serializer: RegisterSerializer) -> None:
        user = serializer.save()
        record_audit(
            "user.create",
            user=self.request.user,
            severity="warning",
            source=client_ip(self.request),
            created_user_id=str(user.id),
            role=user.role,
        )


class MeView(APIView):
    """Retorna o usuário autenticado."""

    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        return Response(UserSerializer(request.user).data)
