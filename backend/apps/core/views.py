"""Views transversais do Byakugan."""

from datetime import UTC, datetime

from rest_framework import mixins, viewsets
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import AuditLog
from .permissions import IsAdmin
from .serializers import AuditLogSerializer

API_VERSION = "0.1.0"


class HealthView(APIView):
    """Health check público da API (RF/RNF de observabilidade).

    Usado por load balancers, healthchecks do Docker e pelo frontend para
    confirmar a comunicação ponta a ponta.
    """

    permission_classes = [AllowAny]

    def get(self, request: Request) -> Response:
        """Retorna o status atual da API."""
        return Response(
            {
                "status": "ok",
                "service": "byakugan-api",
                "version": API_VERSION,
                "time": datetime.now(tz=UTC).isoformat(),
            }
        )


class AuditLogViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """Consulta somente-leitura da trilha de auditoria (RN011).

    Restrita a administradores; registros são imutáveis (não há create/update/
    delete pela API).
    """

    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializer
    permission_classes = [IsAdmin]
    filterset_fields = ["action", "severity"]
    search_fields = ["action", "source"]
    ordering_fields = ["timestamp", "severity"]
