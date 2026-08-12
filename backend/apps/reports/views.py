"""Views de relatórios: geração, consulta e download (RF009, RF010).

Views finas: a lógica de geração vive em ``services``/``rendering``.
"""

from __future__ import annotations

from django.http import FileResponse
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.request import Request
from rest_framework.response import Response

from apps.core.audit import client_ip, record_audit
from apps.core.permissions import IsAdmin, IsAnalystOrAdmin, ReadOnlyOrAnalyst

from .models import Report
from .rendering import CONTENT_TYPE_BY_FORMAT
from .serializers import ReportCreateSerializer, ReportSerializer
from .services import generate_report, report_file_path


class ReportViewSet(viewsets.ModelViewSet):
    """Geração, consulta e exclusão de relatórios. Sem update (RN003)."""

    queryset = Report.objects.all()
    http_method_names = ["get", "post", "delete", "head", "options"]
    filterset_fields = ["scan", "report_type", "format"]
    ordering_fields = ["created_at"]

    def get_serializer_class(self):
        if self.action == "create":
            return ReportCreateSerializer
        return ReportSerializer

    def get_permissions(self):
        if self.action == "create":
            return [IsAnalystOrAdmin()]
        if self.action == "destroy":
            return [IsAdmin()]
        return [ReadOnlyOrAnalyst()]

    def create(self, request: Request, *args, **kwargs) -> Response:
        serializer = ReportCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        report = generate_report(
            scan=data["scan"],
            report_type=data["report_type"],
            format=data["format"],
            created_by=request.user,
        )
        record_audit(
            "report.create",
            user=request.user,
            severity="info",
            source=client_ip(request),
            report_id=str(report.id),
            scan_id=str(report.scan_id),
            report_type=report.report_type,
            format=report.format,
        )
        return Response(ReportSerializer(report).data, status=status.HTTP_201_CREATED)

    def perform_destroy(self, instance: Report) -> None:
        record_audit(
            "report.delete",
            user=self.request.user,
            severity="warning",
            source=client_ip(self.request),
            report_id=str(instance.id),
        )
        path = report_file_path(instance)
        path.unlink(missing_ok=True)
        super().perform_destroy(instance)

    @action(detail=True, methods=["get"])
    def download(self, request: Request, pk: str | None = None) -> FileResponse:
        """Baixa o artefato do relatório. Exportação sempre auditada (RN011)."""
        report = self.get_object()
        record_audit(
            "report.download",
            user=request.user,
            severity="info",
            source=client_ip(request),
            report_id=str(report.id),
        )
        path = report_file_path(report)
        return FileResponse(
            path.open("rb"),
            as_attachment=True,
            filename=path.name,
            content_type=CONTENT_TYPE_BY_FORMAT[report.format],
        )
