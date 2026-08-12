"""Testes das regras de negócio de scan (RN002, RN007, RN010)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from apps.assets.models import Asset
from apps.core.exceptions import Conflict
from apps.scans.models import FindingTriage, Scan
from apps.scans.services import (
    AuthorizationExpired,
    InvalidTransition,
    TargetOutOfScope,
    cancel_scan,
    create_scan,
    transition,
    triage_finding,
    update_progress,
)
from apps.scans.tests.factories import ScanFactory, TargetFactory
from apps.scans.validators import InvalidTarget

pytestmark = pytest.mark.django_db


def test_create_scan_happy_path(analyst_user):
    scan = create_scan(
        created_by=analyst_user,
        scan_type="discovery",
        target="empresa.com",
        authorized_by="CISO",
        authorization_scope="empresa.com",
    )
    assert scan.status == Scan.Status.PENDING
    assert scan.target == "empresa.com"


def test_rn001_create_scan_rejects_invalid_target(analyst_user):
    with pytest.raises(InvalidTarget):
        create_scan(
            created_by=analyst_user,
            scan_type="discovery",
            target="not a target",
            authorized_by="CISO",
            authorization_scope="not a target",
        )


def test_rn007_create_scan_blocks_out_of_scope(analyst_user):
    with pytest.raises(TargetOutOfScope):
        create_scan(
            created_by=analyst_user,
            scan_type="discovery",
            target="evil.com",
            authorized_by="CISO",
            authorization_scope="empresa.com",
        )


def test_rn002_prevents_duplicate_concurrent_scan(analyst_user):
    create_scan(
        created_by=analyst_user,
        scan_type="discovery",
        target="empresa.com",
        authorized_by="CISO",
        authorization_scope="empresa.com",
    )
    with pytest.raises(Conflict):
        create_scan(
            created_by=analyst_user,
            scan_type="discovery",
            target="empresa.com",
            authorized_by="CISO",
            authorization_scope="empresa.com",
        )


def test_rn010_valid_transition():
    scan = ScanFactory()
    transition(scan, Scan.Status.RUNNING)
    assert scan.status == Scan.Status.RUNNING
    assert scan.started_at is not None


def test_rn010_invalid_transition_is_rejected():
    scan = ScanFactory(status=Scan.Status.COMPLETED)
    with pytest.raises(InvalidTransition):
        transition(scan, Scan.Status.RUNNING)


def test_cancel_scan():
    scan = ScanFactory()
    cancel_scan(scan)
    assert scan.status == Scan.Status.CANCELLED
    assert scan.finished_at is not None


def test_cancel_scan_without_task_id_does_not_attempt_revoke():
    """Scan cancelado antes do worker setar celery_task_id — sem task para revogar."""
    scan = ScanFactory()
    assert scan.celery_task_id == ""
    cancel_scan(scan)  # não deve levantar mesmo sem task id
    assert scan.status == Scan.Status.CANCELLED


def test_cancel_scan_attempts_revoke_when_task_id_present(monkeypatch):
    revoked = {}

    class _FakeControl:
        def revoke(self, task_id, terminate=False):
            revoked["task_id"] = task_id
            revoked["terminate"] = terminate

    class _FakeCeleryApp:
        control = _FakeControl()

    import config.celery as celery_config

    monkeypatch.setattr(celery_config, "app", _FakeCeleryApp())

    scan = ScanFactory(celery_task_id="abc-123")
    cancel_scan(scan)

    assert revoked == {"task_id": "abc-123", "terminate": False}


# --- Fundação do motor ofensivo: options normalizadas + expiração de autorização


def test_create_scan_normalizes_options(analyst_user):
    scan = create_scan(
        created_by=analyst_user,
        scan_type="discovery",
        target="empresa.com",
        authorized_by="CISO",
        authorization_scope="empresa.com",
        options={"intensity": "aggressive"},
    )
    assert scan.options["intensity"] == "aggressive"
    assert scan.options["port_set"] == "top1000"


def test_create_scan_defaults_options_when_omitted(analyst_user):
    scan = create_scan(
        created_by=analyst_user,
        scan_type="discovery",
        target="empresa.com",
        authorized_by="CISO",
        authorization_scope="empresa.com",
    )
    assert scan.options["intensity"] == "normal"


def test_create_scan_rejects_expired_target_authorization(analyst_user):
    target = TargetFactory(
        created_by=analyst_user,
        authorization_expires_at=timezone.now() - timedelta(days=1),
    )
    with pytest.raises(AuthorizationExpired):
        create_scan(created_by=analyst_user, scan_type="discovery", target_ref=target)


def test_create_scan_allows_non_expired_target_authorization(analyst_user):
    target = TargetFactory(
        created_by=analyst_user,
        authorization_expires_at=timezone.now() + timedelta(days=1),
    )
    scan = create_scan(created_by=analyst_user, scan_type="discovery", target_ref=target)
    assert scan.status == Scan.Status.PENDING


def test_create_scan_allows_target_without_expiration(analyst_user):
    target = TargetFactory(created_by=analyst_user, authorization_expires_at=None)
    scan = create_scan(created_by=analyst_user, scan_type="discovery", target_ref=target)
    assert scan.status == Scan.Status.PENDING


def test_update_progress_computes_percentage():
    scan = ScanFactory()
    update_progress(scan, completed=2, total=4, phase="dns @ empresa.com")
    assert scan.progress == 50
    assert scan.phase == "dns @ empresa.com"


def test_update_progress_caps_at_100():
    scan = ScanFactory()
    update_progress(scan, completed=10, total=4, phase="x")
    assert scan.progress == 100


def test_update_progress_handles_zero_total():
    scan = ScanFactory()
    update_progress(scan, completed=0, total=0, phase="")
    assert scan.progress == 0


# --- triage_finding (Fase 5) ---------------------------------------------


def test_triage_finding_creates_new_triage(analyst_user):
    asset = Asset.objects.create(ip="192.168.0.10")

    triage = triage_finding(
        dedup_key="a" * 64,
        asset=asset,
        status=FindingTriage.Status.FALSE_POSITIVE,
        note="Confirmado falso positivo em revisão manual.",
        updated_by=analyst_user,
    )

    assert triage.status == FindingTriage.Status.FALSE_POSITIVE
    assert triage.asset_id == asset.id
    assert triage.updated_by_id == analyst_user.id
    assert FindingTriage.objects.count() == 1


def test_triage_finding_is_idempotent_per_dedup_key(analyst_user):
    asset = Asset.objects.create(ip="192.168.0.10")
    dedup_key = "b" * 64

    triage_finding(dedup_key=dedup_key, asset=asset, status=FindingTriage.Status.OPEN)
    triage_finding(
        dedup_key=dedup_key,
        asset=asset,
        status=FindingTriage.Status.ACCEPTED_RISK,
        note="Risco aceito pelo gestor.",
        updated_by=analyst_user,
    )

    assert FindingTriage.objects.count() == 1
    triage = FindingTriage.objects.get(dedup_key=dedup_key)
    assert triage.status == FindingTriage.Status.ACCEPTED_RISK
    assert triage.note == "Risco aceito pelo gestor."
    assert triage.updated_by_id == analyst_user.id


def test_triage_finding_defaults_to_no_note_and_no_updater():
    asset = Asset.objects.create(ip="192.168.0.10")

    triage = triage_finding(dedup_key="c" * 64, asset=asset, status=FindingTriage.Status.FIXED)

    assert triage.note == ""
    assert triage.updated_by is None
