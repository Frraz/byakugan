"""Views de inventário: consulta de ativos e serviços (RF007, RF011)."""

from __future__ import annotations

from rest_framework import mixins, viewsets
from rest_framework.decorators import action
from rest_framework.request import Request
from rest_framework.response import Response

from apps.core.permissions import ReadOnlyOrAnalyst

from .models import Asset
from .serializers import (
    AssetDetailSerializer,
    AssetSerializer,
    DnsRecordSerializer,
    ServiceSerializer,
    TechnologySerializer,
)


class AssetViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """Consulta de ativos descobertos (somente leitura).

    O inventário é populado pelos scans; não há criação manual de ativos via API.
    """

    queryset = Asset.objects.all()
    permission_classes = [ReadOnlyOrAnalyst]
    filterset_fields = ["status"]
    search_fields = ["ip", "hostname", "domain"]
    ordering_fields = ["created_at", "hostname"]

    def get_serializer_class(self):
        if self.action == "retrieve":
            return AssetDetailSerializer
        return AssetSerializer

    @action(detail=True, methods=["get"])
    def services(self, request: Request, pk: str | None = None) -> Response:
        """Lista os serviços expostos pelo ativo."""
        asset = self.get_object()
        serializer = ServiceSerializer(asset.services.all(), many=True)
        return Response(serializer.data)

    @action(detail=True, methods=["get"])
    def technologies(self, request: Request, pk: str | None = None) -> Response:
        """Lista as tecnologias identificadas no ativo (technology profile)."""
        asset = self.get_object()
        serializer = TechnologySerializer(asset.technologies.all(), many=True)
        return Response(serializer.data)

    @action(detail=True, methods=["get"], url_path="dns-records")
    def dns_records(self, request: Request, pk: str | None = None) -> Response:
        """Lista os registros DNS não-A/AAAA descobertos para o ativo (Fase 3)."""
        asset = self.get_object()
        serializer = DnsRecordSerializer(asset.dns_records.all(), many=True)
        return Response(serializer.data)
