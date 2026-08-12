"""Testes da orquestração de scan (run_scan)."""

from __future__ import annotations

import pytest
from django.db import OperationalError

import apps.scans.tasks as tasks_mod
from apps.assets.models import Asset
from apps.core.models import AuditLog
from apps.scans.adapters import RawResult, ScannerAdapter
from apps.scans.models import Finding, Scan
from apps.scans.tests.factories import ScanFactory

pytestmark = pytest.mark.django_db


class _FakeAdapter(ScannerAdapter):
    name = "fake"
    scan_type = "discovery"

    def run(self, target, context):
        return [
            RawResult(
                kind="service",
                data={"ip": "192.168.0.10", "port": 80, "protocol": "tcp", "service_name": "http"},
            ),
        ]


def _adapters_for(*adapters):
    """Monkeypatch helper: get_adapters_for(scan_type, options=None) → adapters fixos."""
    return lambda scan_type, options=None: list(adapters)


def test_killswitch_blocks_scan(settings):
    settings.BYAKUGAN_SCANNING_ENABLED = False
    scan = ScanFactory()
    result = tasks_mod.run_scan(str(scan.id))
    scan.refresh_from_db()
    assert scan.status == Scan.Status.FAILED
    assert result["reason"] == "scanning_disabled"
    assert AuditLog.objects.filter(action="scan.blocked").exists()


def test_run_scan_completes_and_persists(settings, monkeypatch):
    settings.BYAKUGAN_SCANNING_ENABLED = True
    monkeypatch.setattr(tasks_mod, "get_adapters_for", _adapters_for(_FakeAdapter()))
    scan = ScanFactory()

    result = tasks_mod.run_scan(str(scan.id))

    scan.refresh_from_db()
    assert scan.status == Scan.Status.COMPLETED
    assert result["services"] == 1
    assert Asset.objects.filter(ip="192.168.0.10").exists()
    assert AuditLog.objects.filter(action="scan.completed").exists()


def test_run_scan_counts_dns_records(settings, monkeypatch):
    """Fase 3: kind="dns_record" (MX/NS/TXT) flui pelo resumo do scan."""
    settings.BYAKUGAN_SCANNING_ENABLED = True

    class _FakeDnsRecordAdapter(ScannerAdapter):
        name = "fake-dns-record"
        scan_type = "discovery"

        def run(self, target, context):
            return [
                RawResult(
                    kind="dns_record",
                    data={"domain": target, "record_type": "MX", "value": "10 mail.example.com."},
                )
            ]

    monkeypatch.setattr(tasks_mod, "get_adapters_for", _adapters_for(_FakeDnsRecordAdapter()))
    scan = ScanFactory()

    result = tasks_mod.run_scan(str(scan.id))

    scan.refresh_from_db()
    assert scan.status == Scan.Status.COMPLETED
    assert result["dns_records"] == 1


def test_run_scan_reaches_full_progress(settings, monkeypatch):
    settings.BYAKUGAN_SCANNING_ENABLED = True
    monkeypatch.setattr(tasks_mod, "get_adapters_for", _adapters_for(_FakeAdapter()))
    scan = ScanFactory()

    tasks_mod.run_scan(str(scan.id))

    scan.refresh_from_db()
    assert scan.progress == 100
    assert scan.phase  # foi preenchida durante a execução


def test_run_scan_sets_celery_task_id(settings, monkeypatch):
    settings.BYAKUGAN_SCANNING_ENABLED = True
    monkeypatch.setattr(tasks_mod, "get_adapters_for", _adapters_for(_FakeAdapter()))
    scan = ScanFactory()

    tasks_mod.run_scan(str(scan.id))

    scan.refresh_from_db()
    # Chamada direta (fora do worker) ainda popula algum id de request do Celery.
    assert scan.celery_task_id is not None


class _FakeDiscoveryAdapter(ScannerAdapter):
    name = "fake-discovery"
    scan_type = "discovery"

    def run(self, target, context):
        return [
            RawResult(
                kind="service",
                data={"ip": "192.168.0.20", "port": 80, "protocol": "tcp", "service_name": "http"},
            )
        ]


class _FakeVulnerabilityAdapter(ScannerAdapter):
    """Só produz resultado se o asset da fase de discovery já estiver persistido."""

    name = "fake-vuln"
    scan_type = "vulnerability"

    def run(self, target, context):
        asset = Asset.objects.filter(ip="192.168.0.20").first()
        if asset is None:
            return []
        return [
            RawResult(
                kind="vulnerability",
                data={
                    "asset_id": str(asset.id),
                    "cve": "CVE-2024-0001",
                    "title": "CVE-2024-0001 em http",
                    "severity": "high",
                    "cvss_score": 7.5,
                    "cvss_vector": None,
                    "description": "Descrição.",
                    "references": [],
                    "category": "software",
                    "evidence": "evidência",
                    "recommendation": "recomendação",
                    "product": "http",
                    "product_version": "1.0",
                },
            )
        ]


def test_run_scan_persists_profile_before_vulnerability_phase(settings, monkeypatch):
    """RN da Fase 3: o CveLookupAdapter só vê o profile já persistido nesta execução."""
    settings.BYAKUGAN_SCANNING_ENABLED = True
    monkeypatch.setattr(
        tasks_mod,
        "get_adapters_for",
        _adapters_for(_FakeDiscoveryAdapter(), _FakeVulnerabilityAdapter()),
    )
    scan = ScanFactory(scan_type=Scan.ScanType.FULL)

    result = tasks_mod.run_scan(str(scan.id))

    scan.refresh_from_db()
    assert scan.status == Scan.Status.COMPLETED
    assert result["findings"] == 1
    assert Finding.objects.filter(scan=scan).exists()


class _FakeProfilePhaseVulnerabilityAdapter(ScannerAdapter):
    """Simula TlsAdapter (Fase 2): scan_type="fingerprint" mas emite
    kind="vulnerability" também — sem asset_id, já que roda antes de
    qualquer Asset existir para o host."""

    name = "fake-tls-like"
    scan_type = "fingerprint"

    def run(self, target, context):
        return [
            RawResult(
                kind="vulnerability",
                data={
                    "ip": "192.168.0.99",
                    "hostname": target,
                    "title": "Certificado TLS autoassinado",
                    "severity": "medium",
                    "category": "certificate",
                    "description": "O certificado é autoassinado.",
                    "evidence": "issuer == subject.",
                    "recommendation": "Usar um certificado emitido por CA confiável.",
                },
            )
        ]


def test_run_scan_persists_vulnerability_findings_from_profile_phase_adapters(
    settings, monkeypatch
):
    """Um adapter de fase profile (ex.: TlsAdapter) que também emite
    kind="vulnerability" deve ter seus findings persistidos — mesmo sem
    nenhum adapter de scan_type="vulnerability" no scan."""
    settings.BYAKUGAN_SCANNING_ENABLED = True
    monkeypatch.setattr(
        tasks_mod, "get_adapters_for", _adapters_for(_FakeProfilePhaseVulnerabilityAdapter())
    )
    scan = ScanFactory(scan_type=Scan.ScanType.FINGERPRINT)

    result = tasks_mod.run_scan(str(scan.id))

    scan.refresh_from_db()
    assert scan.status == Scan.Status.COMPLETED
    assert result["findings"] == 1
    finding = Finding.objects.get(scan=scan)
    assert finding.category == "certificate"
    assert finding.asset.ip == "192.168.0.99"


# --- Fundação do motor ofensivo: pré-cancel, cancelamento cooperativo,
# correção do bug cancelled→completed, retry transiente ------------------


def test_run_scan_skips_when_already_cancelled_before_pickup(settings, monkeypatch):
    """Bug corrigido: scan cancelado enquanto PENDING não deve levantar InvalidTransition."""
    settings.BYAKUGAN_SCANNING_ENABLED = True
    monkeypatch.setattr(tasks_mod, "get_adapters_for", _adapters_for(_FakeAdapter()))
    scan = ScanFactory(status=Scan.Status.CANCELLED)

    result = tasks_mod.run_scan(str(scan.id))  # não deve levantar

    assert result["reason"] == "already_terminal"
    scan.refresh_from_db()
    assert scan.status == Scan.Status.CANCELLED  # permanece cancelado, não vira running


def test_run_scan_skips_when_already_completed():
    """Reentrega duplicada (acks_late) de um scan já finalizado não reprocessa."""
    scan = ScanFactory(status=Scan.Status.COMPLETED)
    result = tasks_mod.run_scan(str(scan.id))
    assert result["reason"] == "already_terminal"


def test_run_scan_stops_cooperatively_when_cancelled_mid_run(settings, monkeypatch):
    """Cancelamento cooperativo interrompe ANTES do próximo adapter rodar.

    Simula uma requisição externa (`cancel_scan`) cancelando o scan entre dois
    adapters: o primeiro flipa o status no banco (como faria a API de cancel)
    e chama ``check_cancelled()``; o segundo nunca deveria rodar.
    """
    settings.BYAKUGAN_SCANNING_ENABLED = True
    calls: list[str] = []

    class _CancelsThenChecks(ScannerAdapter):
        name = "cancels-then-checks"
        scan_type = "discovery"

        def run(self, target, context):
            calls.append(self.name)
            Scan.objects.filter(id=context.scan_id).update(status=Scan.Status.CANCELLED)
            context.check_cancelled()
            return []  # nunca alcançado

    class _ShouldNeverRun(ScannerAdapter):
        name = "should-never-run"
        scan_type = "discovery"

        def run(self, target, context):
            calls.append(self.name)
            return []

    monkeypatch.setattr(
        tasks_mod, "get_adapters_for", _adapters_for(_CancelsThenChecks(), _ShouldNeverRun())
    )
    scan = ScanFactory()

    result = tasks_mod.run_scan(str(scan.id))

    assert result["status"] == Scan.Status.CANCELLED
    assert calls == ["cancels-then-checks"]  # o segundo adapter nunca rodou
    scan.refresh_from_db()
    assert scan.status == Scan.Status.CANCELLED
    assert AuditLog.objects.filter(action="scan.cancelled").exists()


def test_run_scan_does_not_overwrite_cancelled_with_completed(settings, monkeypatch):
    """Bug corrigido: cancelamento persistido no banco durante a execução não
    deve ser sobrescrito por COMPLETED ao final (objeto em memória fica stale)."""
    settings.BYAKUGAN_SCANNING_ENABLED = True

    class _CancelDuringRun(ScannerAdapter):
        name = "fake-cancel-during-run"
        scan_type = "discovery"

        def run(self, target, context):
            # Simula outra requisição cancelando o scan nesse exato momento —
            # sem passar por should_abort/ScanCancelled (ex.: cancelamento
            # ocorreu entre a última checagem cooperativa e o fim do loop).
            Scan.objects.filter(id=context.scan_id).update(status=Scan.Status.CANCELLED)
            return []

    monkeypatch.setattr(tasks_mod, "get_adapters_for", _adapters_for(_CancelDuringRun()))
    scan = ScanFactory()

    result = tasks_mod.run_scan(str(scan.id))

    assert result["status"] == Scan.Status.CANCELLED
    scan.refresh_from_db()
    assert scan.status == Scan.Status.CANCELLED  # não foi sobrescrito para completed


def test_run_scan_retries_on_transient_operational_error(settings, monkeypatch):
    settings.BYAKUGAN_SCANNING_ENABLED = True

    class _FlakyAdapter(ScannerAdapter):
        name = "flaky"
        scan_type = "discovery"

        def run(self, target, context):
            raise OperationalError("conexão perdida")

    monkeypatch.setattr(tasks_mod, "get_adapters_for", _adapters_for(_FlakyAdapter()))
    scan = ScanFactory()

    # Chamada direta (fora do dispatch do worker): self.retry() reergue a
    # exceção original em vez de celery.exceptions.Retry (comportamento do
    # Celery para tasks chamadas diretamente — ver `request.called_directly`).
    with pytest.raises(OperationalError):
        tasks_mod.run_scan(str(scan.id))

    scan.refresh_from_db()
    # Não foi marcado como failed — o retry ainda está em curso.
    assert scan.status == Scan.Status.RUNNING


def test_run_scan_resumes_without_retransitioning_when_already_running(settings, monkeypatch):
    """Uma reexecução (retry) encontra o scan já RUNNING — não deve tentar
    transicionar de novo (o que levantaria InvalidTransition), só retomar."""
    settings.BYAKUGAN_SCANNING_ENABLED = True
    monkeypatch.setattr(tasks_mod, "get_adapters_for", _adapters_for(_FakeAdapter()))
    scan = ScanFactory(status=Scan.Status.RUNNING)

    result = tasks_mod.run_scan(str(scan.id))  # não deve levantar InvalidTransition

    scan.refresh_from_db()
    assert scan.status == Scan.Status.COMPLETED
    assert result["services"] == 1


def test_scan_context_receives_should_abort_callback(settings, monkeypatch):
    captured = {}

    class _CapturingAdapter(ScannerAdapter):
        name = "capturing"
        scan_type = "discovery"

        def run(self, target, context):
            captured["should_abort"] = context.should_abort
            return []

    settings.BYAKUGAN_SCANNING_ENABLED = True
    monkeypatch.setattr(tasks_mod, "get_adapters_for", _adapters_for(_CapturingAdapter()))
    scan = ScanFactory()

    tasks_mod.run_scan(str(scan.id))

    assert callable(captured["should_abort"])
    assert captured["should_abort"]() is False


def test_run_scan_expands_cidr_target_into_multiple_hosts(settings, monkeypatch):
    """Bug corrigido: alvo CIDR agora é expandido em hosts individuais."""
    settings.BYAKUGAN_SCANNING_ENABLED = True
    seen_targets: list[str] = []

    class _RecordingAdapter(ScannerAdapter):
        name = "recording"
        scan_type = "discovery"

        def run(self, target, context):
            seen_targets.append(target)
            return []

    monkeypatch.setattr(tasks_mod, "get_adapters_for", _adapters_for(_RecordingAdapter()))
    scan = ScanFactory(
        target="192.168.50.0/30",
        authorization_scope="192.168.50.0/24",
    )

    tasks_mod.run_scan(str(scan.id))

    assert sorted(seen_targets) == ["192.168.50.1", "192.168.50.2"]
