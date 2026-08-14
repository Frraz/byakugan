"""Views do motor de scans: Target e Scan (RF004–RF008).

Views finas: a lógica de negócio vive em ``services`` e ``tasks``.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict

from django.conf import settings
from django.db.models import Count, OuterRef, Q, Subquery
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.core.audit import client_ip, record_audit
from apps.core.exceptions import ExploitationDisabled
from apps.core.permissions import IsAnalystOrAdmin, ReadOnlyOrAnalyst

from .correlation import compute_asset_risk, compute_heatmap, compute_risk
from .models import (
    Evidence,
    ExploitationPlaybook,
    Finding,
    FindingTriage,
    Scan,
    Severity,
    Target,
    Vulnerability,
)
from .serializers import (
    EvidenceSerializer,
    ExploitationPlaybookSerializer,
    FindingSerializer,
    FindingTriageInputSerializer,
    FindingTriageSerializer,
    ScanCreateSerializer,
    ScanSerializer,
    TargetSerializer,
    VulnerabilitySerializer,
)
from .services import (
    AuthorizationExpired,
    InvalidTransition,
    TargetOutOfScope,
    cancel_scan,
    create_scan,
    delete_scan,
    triage_finding,
)
from .tasks import exploit_scan, run_scan
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
        if self.action in {"create", "cancel", "exploit"}:
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
                options=data.get("options"),
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
        except AuthorizationExpired as exc:
            record_audit(
                "scan.authorization_expired",
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
        result = run_scan.delay(str(scan.id))
        task_id = getattr(result, "id", None)
        if task_id:
            Scan.objects.filter(id=scan.id).update(celery_task_id=task_id)
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

    @action(detail=True, methods=["post"])
    def exploit(self, request: Request, pk: str | None = None) -> Response:
        """Dispara a fase de exploração (prova de impacto) sobre os findings do scan.

        Ação deliberada de analyst/admin — é o opt-in explícito (dispensa
        ``options["exploit"]``/aggressive). Ainda gated pelo kill-switch
        ``BYAKUGAN_EXPLOITATION_ENABLED`` e pela revalidação de escopo por
        finding (feita no runner). Enfileira ``scans.exploit_scan`` (assíncrono)
        e nunca reescreve findings — só cria ``Evidence`` imutável (RN003).
        """
        scan = self.get_object()
        if not getattr(settings, "BYAKUGAN_EXPLOITATION_ENABLED", False):
            record_audit(
                "exploit.blocked",
                user=request.user,
                severity="warning",
                source=client_ip(request),
                scan_id=str(scan.id),
                reason="kill-switch",
            )
            raise ExploitationDisabled()
        if scan.status != Scan.Status.COMPLETED:
            raise ValidationError("A exploração só pode ser disparada sobre um scan concluído.")

        record_audit(
            "exploit.request",
            user=request.user,
            severity="warning",
            source=client_ip(request),
            scan_id=str(scan.id),
            target=scan.target,
        )
        result = exploit_scan.delay(str(scan.id))
        return Response(
            {"detail": "Exploração enfileirada.", "task_id": getattr(result, "id", None)},
            status=status.HTTP_202_ACCEPTED,
        )

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
    """Findings do ambiente — somente leitura, exceto a ação de triagem (Fase 5)."""

    queryset = Finding.objects.select_related("scan", "asset", "vulnerability")
    serializer_class = FindingSerializer
    permission_classes = [ReadOnlyOrAnalyst]
    filterset_fields = ["severity", "asset", "scan", "category"]
    search_fields = ["title", "category", "vulnerability__cve"]
    ordering_fields = ["created_at", "severity", "cvss"]

    def get_queryset(self):
        # Subquery em vez de join direto: dedup_key não é uma FK (é um hash
        # comparado por valor), então não dá pra usar select_related/
        # prefetch_related — a annotation evita N+1 (uma query por Finding)
        # ao listar, com fallback por instância em FindingSerializer.get_triage_status.
        triage_status = FindingTriage.objects.filter(dedup_key=OuterRef("dedup_key")).values(
            "status"
        )[:1]
        return (
            Finding.objects.select_related("scan", "asset", "vulnerability")
            .annotate(triage_status=Subquery(triage_status))
            .order_by("-created_at")
        )

    def get_permissions(self):
        if self.action == "triage":
            return [IsAnalystOrAdmin()]
        return [ReadOnlyOrAnalyst()]

    @action(detail=True, methods=["post"])
    def triage(self, request: Request, pk: str | None = None) -> Response:
        """Classifica o achado lógico (por dedup_key) — aberto/corrigido/falso-positivo/risco aceito.

        Afeta todos os ``Finding`` (passados e futuros) que compartilham o
        mesmo ``dedup_key`` — não altera o ``Finding`` em si (RN003, imutável).
        """
        finding = self.get_object()
        serializer = FindingTriageInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        triage = triage_finding(
            dedup_key=finding.dedup_key,
            asset=finding.asset,
            status=serializer.validated_data["status"],
            note=serializer.validated_data.get("note", ""),
            updated_by=request.user,
        )
        record_audit(
            "finding.triage",
            user=request.user,
            severity="info",
            source=client_ip(request),
            finding_id=str(finding.id),
            dedup_key=finding.dedup_key,
            status=triage.status,
        )
        return Response(FindingTriageSerializer(triage).data)


class EvidenceViewSet(viewsets.ReadOnlyModelViewSet):
    """Evidências de exploração (aba Evidências) — somente leitura (RN003).

    ``Evidence`` é imutável: representa o que o motor de exploração de fato
    executou e provou. Criada pelo runner (fase inline ou ``POST
    /scans/{id}/exploit/``), nunca pela API diretamente.
    """

    queryset = Evidence.objects.select_related("finding", "asset", "scan")
    serializer_class = EvidenceSerializer
    permission_classes = [ReadOnlyOrAnalyst]
    filterset_fields = ["status", "impact_level", "scan", "asset", "finding", "playbook_key"]
    search_fields = ["playbook_key", "proof"]
    ordering_fields = ["created_at", "impact_level", "status"]

    def get_queryset(self):
        return Evidence.objects.select_related("finding", "asset", "scan").order_by("-created_at")


class ExploitationPlaybookViewSet(viewsets.ModelViewSet):
    """Playbooks curados de exploração (aba Evidências).

    Leitura: qualquer autenticado; escrita: analyst/admin; exclusão: admin
    (RN006). Como a Knowledge Base, é conteúdo de referência **vivo** —
    editável, não histórico imutável.
    """

    queryset = ExploitationPlaybook.objects.all()
    serializer_class = ExploitationPlaybookSerializer
    permission_classes = [ReadOnlyOrAnalyst]
    lookup_field = "key"
    # As keys têm ponto (ex.: ``injection.sqli-error``); o regex de lookup padrão
    # do DRF (``[^/.]+``) exclui ``.`` e daria 404. Permite tudo menos ``/``.
    lookup_value_regex = "[^/]+"
    filterset_fields = ["category", "max_impact"]
    search_fields = ["title", "vuln_class", "key", "summary"]
    ordering_fields = ["created_at", "title", "category"]

    def perform_create(self, serializer: ExploitationPlaybookSerializer) -> None:
        playbook = serializer.save()
        record_audit(
            "playbook.create",
            user=self.request.user,
            severity="info",
            source=client_ip(self.request),
            playbook_key=playbook.key,
        )

    def perform_update(self, serializer: ExploitationPlaybookSerializer) -> None:
        playbook = serializer.save()
        record_audit(
            "playbook.update",
            user=self.request.user,
            severity="info",
            source=client_ip(self.request),
            playbook_key=playbook.key,
        )

    def perform_destroy(self, instance: ExploitationPlaybook) -> None:
        record_audit(
            "playbook.delete",
            user=self.request.user,
            severity="warning",
            source=client_ip(self.request),
            playbook_key=instance.key,
        )
        super().perform_destroy(instance)


class RiskOverviewView(APIView):
    """Correlation Engine: risk score, priorização e heatmap (Fase 4).

    Computado sob demanda a partir dos ``Finding`` persistidos — não há
    modelo de "risco" próprio, então a resposta nunca fica desatualizada.
    Ver docs/scanning-engine.md (seção Correlation Engine).

    Fase 5: achados triados como corrigido/falso-positivo/risco aceito
    (``FindingTriage``) são excluídos do risk_score/heatmap — sem isso, o
    score aditivo infla a cada reexecução do mesmo scan sobre o mesmo alvo.
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
                "dedup_key",
            )
        )
        excluded_dedup_keys = set(
            FindingTriage.objects.filter(status__in=FindingTriage.RESOLVED_STATUSES).values_list(
                "dedup_key", flat=True
            )
        )

        return Response(
            {
                "summary": {
                    "assets": Asset.objects.count(),
                    **asdict(compute_risk(rows, excluded_dedup_keys=excluded_dedup_keys)),
                },
                "top_assets": compute_asset_risk(rows, excluded_dedup_keys=excluded_dedup_keys)[
                    :limit
                ],
                "heatmap": compute_heatmap(rows, excluded_dedup_keys=excluded_dedup_keys),
            }
        )
