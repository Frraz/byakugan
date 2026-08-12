"""Testes de invariantes do modelo (RN008 e novos campos do motor ofensivo)."""

from __future__ import annotations

import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction

from apps.assets.models import Asset
from apps.scans.models import Finding, FindingTriage
from apps.scans.tests.factories import ScanFactory

pytestmark = pytest.mark.django_db


def _base_finding_kwargs(asset, scan):
    return {
        "scan": scan,
        "asset": asset,
        "category": "software",
        "title": "Finding de teste",
        "severity": "medium",
        "description": "d",
        "evidence": "e",
        "recommendation": "r",
    }


def test_finding_save_succeeds_with_all_rn008_fields():
    asset = Asset.objects.create(ip="192.168.0.10")
    scan = ScanFactory()
    finding = Finding(**_base_finding_kwargs(asset, scan))
    finding.save()  # não deve levantar
    assert finding.pk is not None


@pytest.mark.parametrize("missing_field", ["description", "evidence", "recommendation"])
def test_finding_save_rejects_missing_rn008_field(missing_field):
    asset = Asset.objects.create(ip="192.168.0.10")
    scan = ScanFactory()
    kwargs = _base_finding_kwargs(asset, scan)
    kwargs[missing_field] = ""
    finding = Finding(**kwargs)
    with pytest.raises(ValidationError):
        finding.save()


def test_finding_save_rejects_whitespace_only_field():
    asset = Asset.objects.create(ip="192.168.0.10")
    scan = ScanFactory()
    kwargs = _base_finding_kwargs(asset, scan)
    kwargs["evidence"] = "   "
    finding = Finding(**kwargs)
    with pytest.raises(ValidationError):
        finding.save()


def test_finding_save_rejects_category_outside_enum():
    asset = Asset.objects.create(ip="192.168.0.10")
    scan = ScanFactory()
    kwargs = _base_finding_kwargs(asset, scan)
    kwargs["category"] = "not-a-real-category"
    finding = Finding(**kwargs)
    with pytest.raises(ValidationError):
        finding.save()


def test_scan_defaults_for_offensive_engine_fields():
    scan = ScanFactory()
    assert scan.options == {}
    assert scan.progress == 0
    assert scan.phase == ""
    assert scan.celery_task_id == ""


def test_finding_dedup_key_is_not_unique_across_rows():
    """Múltiplas execuções de scan compartilham o mesmo dedup_key de propósito (RN003)."""
    asset = Asset.objects.create(ip="192.168.0.10")
    scan1, scan2 = ScanFactory(), ScanFactory()
    Finding.objects.create(**_base_finding_kwargs(asset, scan1), dedup_key="shared-key")
    Finding.objects.create(**_base_finding_kwargs(asset, scan2), dedup_key="shared-key")
    assert Finding.objects.filter(dedup_key="shared-key").count() == 2


# --- FindingTriage (Fase 5) ----------------------------------------------


def test_finding_triage_default_status_is_open():
    asset = Asset.objects.create(ip="192.168.0.10")
    triage = FindingTriage.objects.create(dedup_key="a" * 64, asset=asset)
    assert triage.status == FindingTriage.Status.OPEN
    assert triage.status not in FindingTriage.RESOLVED_STATUSES


def test_finding_triage_resolved_statuses_contents():
    assert set(FindingTriage.RESOLVED_STATUSES) == {
        FindingTriage.Status.FIXED,
        FindingTriage.Status.FALSE_POSITIVE,
        FindingTriage.Status.ACCEPTED_RISK,
    }
    assert FindingTriage.Status.OPEN not in FindingTriage.RESOLVED_STATUSES


def test_finding_triage_dedup_key_is_unique():
    asset = Asset.objects.create(ip="192.168.0.10")
    FindingTriage.objects.create(dedup_key="dup-key", asset=asset)
    with pytest.raises(IntegrityError), transaction.atomic():
        FindingTriage.objects.create(dedup_key="dup-key", asset=asset)


def test_finding_triage_updated_by_set_null_on_user_delete(analyst_user):
    asset = Asset.objects.create(ip="192.168.0.10")
    triage = FindingTriage.objects.create(dedup_key="b" * 64, asset=asset, updated_by=analyst_user)
    analyst_user.delete()
    triage.refresh_from_db()
    assert triage.updated_by is None
