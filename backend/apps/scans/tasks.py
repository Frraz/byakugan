"""Orquestração assíncrona de scans (Celery).

O ``run_scan`` conduz a máquina de estados (RN010), expande o alvo em hosts
individuais (CIDR/lista — ``targets.expand_target``), executa os adapters do
tipo de scan **por host**, normaliza e persiste os resultados, reporta
progresso e audita o desfecho. A execução real de varredura é gated pelo
kill-switch ``BYAKUGAN_SCANNING_ENABLED``.
"""

from __future__ import annotations

import logging
import time

from celery import shared_task
from django.conf import settings
from django.db import OperationalError

from apps.core.audit import record_audit

from .adapters import ScanCancelled, ScanContext, get_adapters_for
from .exploit.runner import run_exploitation_for_scan
from .models import Scan
from .parsers import FindingsSummary, PersistenceSummary, persist_findings, persist_results
from .services import transition, update_progress
from .targets import expand_target

logger = logging.getLogger("byakugan.scans")

#: Intervalo mínimo (segundos) entre checagens de cancelamento no banco —
#: evita uma query por probe individual em adapters de alta cardinalidade.
CANCEL_CHECK_INTERVAL = 1.0


def _make_should_abort(scan_id: str, *, min_interval: float = CANCEL_CHECK_INTERVAL):
    """Cria o callback de cancelamento cooperativo passado a ``ScanContext``.

    Consulta o status do scan no banco, mas no máximo a cada ``min_interval``
    segundos (e nunca mais depois de confirmado o cancelamento) — os adapters
    chamam ``context.check_cancelled()`` com frequência alta (por porta/host),
    então uma query síncrona por chamada seria custosa demais.
    """
    state = {"last_checked": 0.0, "cancelled": False}

    def should_abort() -> bool:
        if state["cancelled"]:
            return True
        now = time.monotonic()
        if now - state["last_checked"] < min_interval:
            return False
        state["last_checked"] = now
        state["cancelled"] = Scan.objects.filter(id=scan_id, status=Scan.Status.CANCELLED).exists()
        return state["cancelled"]

    return should_abort


@shared_task(
    bind=True,
    name="scans.run_scan",
    time_limit=settings.SCAN_TASK_TIME_LIMIT,
    soft_time_limit=settings.SCAN_TASK_SOFT_TIME_LIMIT,
    max_retries=2,
    acks_late=True,
)
def run_scan(self, scan_id: str) -> dict:
    """Executa um scan de ponta a ponta.

    Returns:
        Resumo com contagens de ativos/serviços/findings descobertos e o
        status final.
    """
    scan = Scan.objects.get(id=scan_id)

    if scan.status in {Scan.Status.COMPLETED, Scan.Status.FAILED, Scan.Status.CANCELLED}:
        # Terminal antes do worker sequer começar — cancelado enquanto ainda
        # PENDING, ou reentrega duplicada (acks_late) de um scan já concluído.
        # Não há transição válida para RUNNING a partir de um estado terminal
        # (RN010), então apenas registramos e saímos sem levantar InvalidTransition.
        record_audit(
            "scan.skipped",
            severity="info",
            scan_id=str(scan.id),
            target=scan.target,
            status=scan.status,
        )
        return {"status": scan.status, "reason": "already_terminal"}

    scan.celery_task_id = self.request.id or ""
    scan.save(update_fields=["celery_task_id", "updated_at"])

    if scan.status == Scan.Status.PENDING:
        if not settings.BYAKUGAN_SCANNING_ENABLED:
            transition(
                scan,
                Scan.Status.FAILED,
                reason="Varredura desabilitada (BYAKUGAN_SCANNING_ENABLED=False).",
            )
            record_audit(
                "scan.blocked",
                severity="warning",
                scan_id=str(scan.id),
                target=scan.target,
                reason="kill-switch",
            )
            return {"status": scan.status, "reason": "scanning_disabled"}

        transition(scan, Scan.Status.RUNNING)
        record_audit("scan.start", severity="info", scan_id=str(scan.id), target=scan.target)
    # else: status já é RUNNING — esta é uma reexecução via self.retry() após
    # falha transiente (OperationalError); não retransiciona, só retoma.

    should_abort = _make_should_abort(str(scan.id))
    summary = PersistenceSummary()
    findings_summary = FindingsSummary()
    exploit_summary = None

    try:
        hosts = expand_target(
            scan.target, {**scan.options, "authorization_scope": scan.authorization_scope}
        )
        adapters = get_adapters_for(scan.scan_type, scan.options)
        profile_adapters = [a for a in adapters if a.scan_type != "vulnerability"]
        vulnerability_adapters = [a for a in adapters if a.scan_type == "vulnerability"]

        total_steps = max(len(hosts) * len(adapters), 1)
        completed_steps = 0

        for host in hosts:
            context = ScanContext(
                scan_id=str(scan.id),
                authorized_by=scan.authorized_by,
                authorization_scope=scan.authorization_scope,
                options=scan.options,
                should_abort=should_abort,
            )

            # Pipeline em duas fases POR HOST: discovery/fingerprint persistem
            # primeiro, para que o CveLookupAdapter (fase "vulnerability") leia
            # o technology profile já atualizado do ativo — mesmo dentro de um
            # único scan "full".
            profile_results = []
            for adapter in profile_adapters:
                profile_results.extend(adapter.run(host, context))
                completed_steps += 1
                update_progress(
                    scan,
                    completed=completed_steps,
                    total=total_steps,
                    phase=f"{adapter.name} @ {host}",
                )
            host_summary = persist_results(profile_results)
            summary.assets += host_summary.assets
            summary.services += host_summary.services
            summary.technologies += host_summary.technologies
            summary.dns_records += host_summary.dns_records
            # Alguns adapters de fase "profile" também emitem kind="vulnerability"
            # (ex.: TlsAdapter — protocolo/cipher/certificado fraco). persist_findings
            # ignora silenciosamente qualquer outro kind, então é seguro chamar
            # aqui mesmo quando nenhum resultado de vulnerabilidade existir.
            host_profile_findings = persist_findings(scan, profile_results)
            findings_summary.findings += host_profile_findings.findings
            findings_summary.vulnerabilities += host_profile_findings.vulnerabilities

            vulnerability_results = []
            for adapter in vulnerability_adapters:
                vulnerability_results.extend(adapter.run(host, context))
                completed_steps += 1
                update_progress(
                    scan,
                    completed=completed_steps,
                    total=total_steps,
                    phase=f"{adapter.name} @ {host}",
                )
            host_findings = persist_findings(scan, vulnerability_results)
            findings_summary.findings += host_findings.findings
            findings_summary.vulnerabilities += host_findings.vulnerabilities

        # Fase de exploração (prova de impacto) — roda DEPOIS de todos os hosts,
        # sobre os Findings já persistidos. É gated (kill-switch dedicado +
        # opt-in ``options["exploit"]`` + intensity aggressive + revalidação de
        # escopo por finding); se não passar no gate, retorna sem tocar em nada.
        def _set_phase(phase: str) -> None:
            scan.phase = phase
            scan.save(update_fields=["phase", "updated_at"])

        exploit_summary = run_exploitation_for_scan(
            scan, should_abort=should_abort, update_phase=_set_phase
        )

    except ScanCancelled:
        record_audit("scan.cancelled", severity="warning", scan_id=str(scan.id), target=scan.target)
        return {"status": Scan.Status.CANCELLED, "reason": "cancelled_by_user"}
    except OperationalError as exc:
        # Falha transiente de infraestrutura (ex.: soneca de conexão com o
        # banco) — vale a pena tentar de novo, diferente de uma falha de
        # lógica de scan (capturada abaixo). A reexecução refaz todos os
        # hosts do zero: achados de rede/tecnologia são idempotentes
        # (get_or_create/update_or_create), mas um Finding de um host que já
        # havia persistido antes da falha pode duplicar — aceitável, dado que
        # é um cenário raro (erro transiente de banco) e a camada de
        # dedup/triagem (Fase 5 do motor ofensivo) absorve duplicatas.
        logger.warning("scan_retry", extra={"scan_id": str(scan.id), "error": str(exc)})
        raise self.retry(exc=exc, countdown=min(60 * (self.request.retries + 1), 300)) from exc
    except Exception as exc:  # noqa: BLE001 — falha de scan não deve derrubar o worker
        logger.exception("scan_failed", extra={"scan_id": str(scan.id)})
        transition(scan, Scan.Status.FAILED, reason=str(exc))
        record_audit(
            "scan.failed",
            severity="critical",
            scan_id=str(scan.id),
            target=scan.target,
            error=str(exc),
        )
        return {"status": scan.status, "error": str(exc)}

    # Antes de concluir, confirma a verdade do banco: se o scan foi cancelado
    # entre a última checagem cooperativa e aqui, o objeto em memória ainda
    # diz "running" — sem este refresh, o COMPLETED abaixo sobrescreveria
    # silenciosamente um cancelamento já persistido.
    scan.refresh_from_db(fields=["status"])
    if scan.status == Scan.Status.CANCELLED:
        record_audit("scan.cancelled", severity="warning", scan_id=str(scan.id), target=scan.target)
        return {"status": scan.status, "reason": "cancelled_by_user"}

    transition(scan, Scan.Status.COMPLETED)
    exploited = exploit_summary.proven if exploit_summary else 0
    record_audit(
        "scan.completed",
        severity="info",
        scan_id=str(scan.id),
        target=scan.target,
        assets=summary.assets,
        services=summary.services,
        technologies=summary.technologies,
        dns_records=summary.dns_records,
        findings=findings_summary.findings,
        exploits_proven=exploited,
    )
    return {
        "status": scan.status,
        "assets": summary.assets,
        "services": summary.services,
        "technologies": summary.technologies,
        "dns_records": summary.dns_records,
        "findings": findings_summary.findings,
        "exploits_proven": exploited,
    }


@shared_task(
    bind=True,
    name="scans.exploit_scan",
    time_limit=settings.SCAN_TASK_TIME_LIMIT,
    soft_time_limit=settings.SCAN_TASK_SOFT_TIME_LIMIT,
    max_retries=0,
    acks_late=True,
)
def exploit_scan(self, scan_id: str) -> dict:
    """Roda a fase de exploração manualmente sobre um scan já concluído.

    Gatilho de ``POST /scans/{id}/exploit/`` (analyst/admin). ``manual=True``
    dispensa o opt-in por scan/aggressive — a ação já é o opt-in explícito —,
    mas o kill-switch ``BYAKUGAN_EXPLOITATION_ENABLED`` e a revalidação de
    escopo por finding continuam sendo aplicados (piso inegociável). Nunca
    reescreve findings; só cria novos registros ``Evidence`` (imutáveis, RN003).
    """
    scan = Scan.objects.get(id=scan_id)
    should_abort = _make_should_abort(str(scan.id))

    def _set_phase(phase: str) -> None:
        scan.phase = phase
        scan.save(update_fields=["phase", "updated_at"])

    try:
        exploit_summary = run_exploitation_for_scan(
            scan, manual=True, should_abort=should_abort, update_phase=_set_phase
        )
    except Exception as exc:  # noqa: BLE001 — falha de exploração não derruba o worker
        logger.exception("exploit_failed", extra={"scan_id": str(scan.id)})
        record_audit(
            "exploit.failed",
            severity="critical",
            scan_id=str(scan.id),
            target=scan.target,
            error=str(exc),
        )
        return {"status": "error", "error": str(exc)}

    record_audit(
        "exploit.run",
        severity="warning",
        scan_id=str(scan.id),
        target=scan.target,
        proven=exploit_summary.proven,
        attempted=exploit_summary.attempted,
        blocked=exploit_summary.blocked,
        skipped_reason=exploit_summary.skipped_reason,
    )
    return {
        "status": "ok" if exploit_summary.ran else "skipped",
        "skipped_reason": exploit_summary.skipped_reason,
        "attempted": exploit_summary.attempted,
        "proven": exploit_summary.proven,
        "failed": exploit_summary.failed,
        "blocked": exploit_summary.blocked,
    }
