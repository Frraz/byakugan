"""Testes do serviço de geração de relatórios (RN003/RN005/RN012)."""

from __future__ import annotations

import pytest

from apps.accounts.tests.factories import UserFactory
from apps.reports.models import Report
from apps.reports.services import ScanNotCompleted, generate_report, report_file_path
from apps.reports.tests.factories import make_completed_scan_with_findings
from apps.scans.models import Scan
from apps.scans.tests.factories import ScanFactory

pytestmark = pytest.mark.django_db


def test_generate_report_writes_file_and_persists_record():
    scan = make_completed_scan_with_findings()
    user = UserFactory(role="analyst")

    report = generate_report(
        scan=scan,
        report_type=Report.ReportType.TECHNICAL,
        format=Report.Format.JSON,
        created_by=user,
    )

    assert report.scan_id == scan.id
    assert report.created_by_id == user.id
    path = report_file_path(report)
    assert path.exists()
    assert path.read_bytes()


def test_generate_report_rejects_non_completed_scan():
    scan = ScanFactory(status=Scan.Status.RUNNING)
    user = UserFactory(role="analyst")

    with pytest.raises(ScanNotCompleted):
        generate_report(
            scan=scan,
            report_type=Report.ReportType.TECHNICAL,
            format=Report.Format.JSON,
            created_by=user,
        )

    assert not Report.objects.exists()
