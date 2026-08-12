"""Views do motor de scans: Target e Scan (RF004–RF008).

Views finas: a lógica de negócio vive em ``services`` e ``tasks``.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict

from django.db.models import Count, Q
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.core.audit import client_ip, record_audit
from apps.core.permissions import IsAnalystOrAdmin, ReadOnlyOrAnalyst

from .correlation import compute_asset_risk, compute_heatmap, compute_risk
from .models import Finding, Scan, Severity, Target, Vulnerability
from .serializers import (
    FindingSerializer,
    ScanCreateSerializer,
    ScanSerializer,
    TargetSerializer,
    VulnerabilitySerializer,
)
from .services import (
    InvalidTransition,
    TargetOutOfScope,
    cancel_scan,
    create_scan,
    delete_scan,
)
from .tasks import run_scan
from .validators import InvalidTarget

DEFAULT_TOP_ASSETS_LIMIT = 10


class TargetViewSet(viewsets.ModelViewSet):
    """CRUD de alvos autorizados. Escrita: analyst/admin; exclusão: admin (RN006)."""

    queryset = Target.objects.all()
    serializer_class = TargetSerializer
    permission_classes = [ReadOnlyOrAnalyst]
    filterset_fields = ["is_active", "kind"]
    search_fields = ["name", "value"]
    ordering_fields = ["created_at", "name"]

    def get_queryset(self):
        # annotate() com agregação descarta o Meta.ordering — reaplicar.
        return Target.objects.annotate(scans_count=Count("scans")).order_by("-created_at")

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

    def perform_update(self, serializer: TargetSerializer) -> None:
        target = serializer.save()
        record_audit(
            "target.update",
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
    search_fields = ["target"]
    ordering_fields = ["created_at", "status"]

    def get_queryset(self):
        severity_annotations = {
            f"sev_{severity}": Count("findings", filter=Q(findings__severity=severity))
            for severity in Severity.values
        }
        # annotate() com agregação descarta o Meta.ordering — reaplicar.
        return (
            Scan.objects.select_related("target_ref")
            .annotate(findings_total=Count("findings"), **severity_annotations)
            .order_by("-created_at")
        )

    def get_serializer_class(self):
        if self.action == "create":
            return ScanCreateSerializer
        return ScanSerializer

    def get_permissions(self):
        if self.action in {"create", "cancel"}:
            return [IsAnalystOrAdmin()]
        return [ReadOnlyOrAnalyst()]

    def perform_destroy(self, instance: Scan) -> None:
        scan_id, target = str(instance.id), instance.target
        deleted = delete_scan(instance)  # RN014 — 409 se pending/running
        record_audit(
            "scan.delete",
            user=self.request.user,
            severity="warning",
            source=client_ip(self.request),
            scan_id=scan_id,
            target=target,
            findings_deleted=deleted["findings"],
            reports_deleted=deleted["reports"],
        )

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
        findings = scan.findings.select_related("scan", "asset", "vulnerability")
        serializer = FindingSerializer(findings, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=["get"])
    def services(self, request: Request, pk: str | None = None) -> Response:
        """Lista os serviços dos ativos cobertos pelo scan.

        O modelo não liga ``Scan`` diretamente a ``Asset``/``Service`` — o único
        vínculo scan→asset é via ``Finding``. Para scans de ``discovery``/
        ``fingerprint`` (que não geram findings), resolvemos os ativos pelo
        **alvo** do scan (``ip``/``hostname``/``domain``), unindo com os ativos
        que têm findings deste scan (scans de ``vulnerability``).
        """
        from apps.assets.models import Asset, Service
        from apps.assets.serializers import ServiceSerializer

        scan = self.get_object()

        # Casar o alvo por hostname/domínio sempre; por IP só se for um IP válido
        # (o campo é ``inet`` no Postgres — string não-IP levantaria DataError).
        target_q = Q(hostname=scan.target) | Q(domain=scan.target)
        try:
            ipaddress.ip_address(scan.target)
            target_q |= Q(ip=scan.target)
        except ValueError:
            pass

        asset_ids = set(scan.findings.values_list("asset_id", flat=True))
        asset_ids |= set(Asset.objects.filter(target_q).values_list("id", flat=True))

        services = Service.objects.filter(asset_id__in=asset_ids).select_related("asset")
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

    queryset = Finding.objects.select_related("scan", "asset", "vulnerability")
    serializer_class = FindingSerializer
    permission_classes = [ReadOnlyOrAnalyst]
    filterset_fields = ["severity", "asset", "scan", "category"]
    search_fields = ["title", "category", "vulnerability__cve"]
    ordering_fields = ["created_at", "severity", "cvss"]


class RiskOverviewView(APIView):
    """Correlation Engine: risk score, priorização e heatmap (Fase 4).

    Computado sob demanda a partir dos ``Finding`` persistidos — não há
    modelo de "risco" próprio, então a resposta nunca fica desatualizada.
    Ver docs/scanning-engine.md (seção Correlation Engine).
    """

    permission_classes = [ReadOnlyOrAnalyst]

    def get(self, request: Request) -> Response:
        from apps.assets.models import Asset

        try:
            limit = int(request.query_params.get("limit", DEFAULT_TOP_ASSETS_LIMIT))
        except ValueError:
            limit = DEFAULT_TOP_ASSETS_LIMIT

        rows = list(
            Finding.objects.values(
                "asset_id",
                "asset__ip",
                "asset__hostname",
                "asset__domain",
                "severity",
                "cvss",
                "category",
            )
        )

        return Response(
            {
                "summary": {"assets": Asset.objects.count(), **asdict(compute_risk(rows))},
                "top_assets": compute_asset_risk(rows)[:limit],
                "heatmap": compute_heatmap(rows),
            }
        )
