"""Testes das regras de negócio de scan (RN002, RN007, RN010)."""

from __future__ import annotations

import pytest

from apps.core.exceptions import Conflict
from apps.scans.models import Scan
from apps.scans.services import (
    InvalidTransition,
    TargetOutOfScope,
    cancel_scan,
    create_scan,
    transition,
)
from apps.scans.tests.factories import ScanFactory
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
