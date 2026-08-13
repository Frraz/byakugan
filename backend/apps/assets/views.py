"""Views de inventário: consulta de ativos e serviços (RF007, RF011)."""

from __future__ import annotations

from django.db.models import Count
from rest_framework import mixins, viewsets
from rest_framework.decorators import action
from rest_framework.request import Request
from rest_framework.response import Response

from apps.core.audit import client_ip, record_audit
from apps.core.permissions import ReadOnlyOrAnalyst

from .models import Asset
from .serializers import (
    AssetDetailSerializer,
    AssetSerializer,
    DnsRecordSerializer,
    ServiceSerializer,
    TechnologySerializer,
)
from .services import delete_asset


class AssetViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):
    """Consulta de ativos descobertos; exclusão restrita a admin (RN006/RN020).

    O inventário é populado pelos scans; não há criação/edição manual de
    ativos via API — só leitura e exclusão (em cascata, RN020).
    """

    queryset = Asset.objects.all()
    permission_classes = [ReadOnlyOrAnalyst]
    filterset_fields = ["status"]
    search_fields = ["ip", "hostname", "domain"]
    ordering_fields = ["created_at", "hostname"]

    def get_queryset(self):
        # annotate() com agregação descarta o Meta.ordering — reaplicar.
        return Asset.objects.annotate(findings_total=Count("findings")).order_by("-created_at")

    def get_serializer_class(self):
        if self.action == "retrieve":
            return AssetDetailSerializer
        return AssetSerializer

    def perform_destroy(self, instance: Asset) -> None:
        asset_id, label = str(instance.id), str(instance)
        deleted = delete_asset(instance)  # RN020 — cascata (findings)
        record_audit(
            "asset.delete",
            user=self.request.user,
            severity="warning",
            source=client_ip(self.request),
            asset_id=asset_id,
            label=label,
            findings_deleted=deleted["findings"],
        )

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
