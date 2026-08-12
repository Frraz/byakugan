"""Views do motor de scans: Target e Scan (RF004–RF008).

Views finas: a lógica de negócio vive em ``services`` e ``tasks``.
"""

from __future__ import annotations

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.request import Request
from rest_framework.response import Response

from apps.core.audit import client_ip, record_audit
from apps.core.permissions import IsAnalystOrAdmin, ReadOnlyOrAnalyst

from .models import Finding, Scan, Target, Vulnerability
from .serializers import (
    FindingSerializer,
    ScanCreateSerializer,
    ScanSerializer,
    TargetSerializer,
    VulnerabilitySerializer,
)
from .services import InvalidTransition, TargetOutOfScope, cancel_scan, create_scan
from .tasks import run_scan
from .validators import InvalidTarget


class TargetViewSet(viewsets.ModelViewSet):
    """CRUD de alvos autorizados. Escrita: analyst/admin; exclusão: admin (RN006)."""

    queryset = Target.objects.all()
    serializer_class = TargetSerializer
    permission_classes = [ReadOnlyOrAnalyst]
    filterset_fields = ["is_active", "kind"]
    search_fields = ["name", "value"]
    ordering_fields = ["created_at", "name"]

    def perform_create(self, serializer: TargetSerializer) -> None:
        target = serializer.save()
        record_audit(
            "target.create",
            user=self.request.user,
            severity="info",
            source=client_ip(self.request),
            target_id=str(target.id),
            value=target.value,
        )

    def perform_destroy(self, instance: Target) -> None:
        record_audit(
            "target.delete",
            user=self.request.user,
            severity="warning",
            source=client_ip(self.request),
            target_id=str(instance.id),
            value=instance.value,
        )
        super().perform_destroy(instance)


class ScanViewSet(viewsets.ModelViewSet):
    """Criação/consulta de scans. Sem update; exclusão restrita a admin (RN003/RN006)."""

    queryset = Scan.objects.all()
    http_method_names = ["get", "post", "delete", "head", "options"]
    filterset_fields = ["status", "scan_type"]
    ordering_fields = ["created_at", "status"]

    def get_serializer_class(self):
        if self.action == "create":
            return ScanCreateSerializer
        return ScanSerializer

    def get_permissions(self):
        if self.action in {"create", "cancel"}:
            return [IsAnalystOrAdmin()]
        return [ReadOnlyOrAnalyst()]

    def create(self, request: Request, *args, **kwargs) -> Response:
        serializer = ScanCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        try:
            scan = create_scan(
                created_by=request.user,
                scan_type=data["scan_type"],
                target=data.get("target"),
                authorized_by=data.get("authorized_by"),
                authorization_scope=data.get("authorization_scope"),
                target_ref=data.get("target_ref"),
            )
        except InvalidTarget as exc:
            raise ValidationError({"target": str(exc)}) from exc
        except TargetOutOfScope as exc:
            record_audit(
                "scan.out_of_scope",
                user=request.user,
                severity="warning",
                source=client_ip(request),
                target=data.get("target"),
            )
            raise PermissionDenied(str(exc)) from exc

        record_audit(
            "scan.create",
            user=request.user,
            severity="info",
            source=client_ip(request),
            scan_id=str(scan.id),
            target=scan.target,
            scan_type=scan.scan_type,
        )
        run_scan.delay(str(scan.id))
        return Response(ScanSerializer(scan).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"])
    def cancel(self, request: Request, pk: str | None = None) -> Response:
        """Cancela um scan pendente/em execução (RN010)."""
        scan = self.get_object()
        try:
            cancel_scan(scan)
        except InvalidTransition as exc:
            raise ValidationError(str(exc)) from exc
        record_audit(
            "scan.cancel",
            user=request.user,
            severity="warning",
            source=client_ip(request),
            scan_id=str(scan.id),
        )
        return Response(ScanSerializer(scan).data)

    @action(detail=True, methods=["get"])
    def findings(self, request: Request, pk: str | None = None) -> Response:
        """Lista os findings produzidos pelo scan."""
        scan = self.get_object()
        serializer = FindingSerializer(scan.findings.all(), many=True)
        return Response(serializer.data)

    @action(detail=True, methods=["get"])
    def services(self, request: Request, pk: str | None = None) -> Response:
        """Lista os serviços descobertos pelo scan (via ativos relacionados)."""
        from apps.assets.serializers import ServiceSerializer

        scan = self.get_object()
        asset_ids = scan.findings.values_list("asset_id", flat=True)
        from apps.assets.models import Service

        services = Service.objects.filter(asset_id__in=asset_ids)
        return Response(ServiceSerializer(services, many=True).data)


class VulnerabilityViewSet(viewsets.ReadOnlyModelViewSet):
    """Catálogo de vulnerabilidades conhecidas — somente leitura (RF008)."""

    queryset = Vulnerability.objects.all()
    serializer_class = VulnerabilitySerializer
    permission_classes = [ReadOnlyOrAnalyst]
    filterset_fields = ["severity"]
    search_fields = ["cve", "title"]
    ordering_fields = ["created_at", "cvss_score", "severity"]


class FindingViewSet(viewsets.ReadOnlyModelViewSet):
    """Findings do ambiente — somente leitura (RF008)."""

    queryset = Finding.objects.all()
    serializer_class = FindingSerializer
    permission_classes = [ReadOnlyOrAnalyst]
    filterset_fields = ["severity", "asset", "scan"]
    ordering_fields = ["created_at", "severity", "cvss"]
