"""Normalização de resultados brutos dos adapters em entidades de domínio.

Converte ``RawResult`` (adapters) em ``Asset``/``Service`` do inventário. Os
ativos representam o inventário corrente e são atualizados a cada descoberta;
os resultados históricos do scan (findings/reports) é que são imutáveis (RN003).
"""

from __future__ import annotations

from dataclasses import dataclass

from apps.assets.models import Asset, Service, Technology

from .adapters import RawResult
from .models import Finding, Scan, Vulnerability


@dataclass
class PersistenceSummary:
    """Contagem do que foi persistido a partir de um scan."""

    assets: int = 0
    services: int = 0
    technologies: int = 0


def _get_or_create_asset(*, ip: str | None, hostname: str | None, domain: str | None) -> Asset:
    """Localiza ou cria um ativo pela chave natural (IP → hostname → domínio)."""
    lookup: dict[str, str] = {}
    if ip:
        lookup = {"ip": ip}
    elif hostname:
        lookup = {"hostname": hostname}
    elif domain:
        lookup = {"domain": domain}

    defaults = {"hostname": hostname, "domain": domain}
    if ip:
        defaults["ip"] = ip
    asset, _ = Asset.objects.get_or_create(**lookup, defaults=defaults)

    # Complementa campos vazios sem sobrescrever dados já conhecidos.
    updated_fields = []
    for attr, value in (("hostname", hostname), ("domain", domain), ("ip", ip)):
        if value and not getattr(asset, attr):
            setattr(asset, attr, value)
            updated_fields.append(attr)
    if updated_fields:
        asset.save(update_fields=[*updated_fields, "updated_at"])
    return asset


def persist_results(raw_results: list[RawResult]) -> PersistenceSummary:
    """Persiste os resultados brutos como ativos e serviços do inventário.

    Idempotente: reexecuções não duplicam ativos/serviços (dedup por chave
    natural). Retorna um resumo com as contagens criadas.
    """
    summary = PersistenceSummary()
    seen_assets: set[str] = set()

    for result in raw_results:
        data = result.data
        if result.kind in {"host", "service"}:
            ip = data.get("ip")
            hostname = data.get("hostname") or data.get("host")
            domain = data.get("domain")
            asset = _get_or_create_asset(ip=ip, hostname=hostname, domain=domain)
            if str(asset.id) not in seen_assets:
                seen_assets.add(str(asset.id))
                summary.assets += 1

            if result.kind == "service":
                _, created = Service.objects.get_or_create(
                    asset=asset,
                    port=data["port"],
                    protocol=data.get("protocol", "tcp"),
                    defaults={
                        "service_name": data.get("service_name", "unknown"),
                        "product": data.get("product"),
                        "version": data.get("version"),
                    },
                )
                if created:
                    summary.services += 1

        elif result.kind == "technology":
            ip = data.get("ip")
            hostname = data.get("hostname") or data.get("host")
            domain = data.get("domain")
            asset = _get_or_create_asset(ip=ip, hostname=hostname, domain=domain)
            if str(asset.id) not in seen_assets:
                seen_assets.add(str(asset.id))
                summary.assets += 1
            if _persist_technology(asset, data):
                summary.technologies += 1

    return summary


def _persist_technology(asset: Asset, data: dict) -> bool:
    """Persiste uma tecnologia e enriquece o ativo/serviço. True se criada nova.

    Reexecuções atualizam a evidência/versão em vez de duplicar (dedup por
    ``asset`` + ``category`` + ``name``). Quando a categoria é ``os``, preenche
    ``Asset.os`` se ainda vazio; quando é ``web-server``, complementa o
    ``Service`` da porta correspondente com produto/versão.
    """
    category = data["category"]
    name = data["name"]
    version = data.get("version")

    _, created = Technology.objects.update_or_create(
        asset=asset,
        category=category,
        name=name,
        defaults={
            "version": version,
            "source": data.get("source", "unknown"),
            "evidence": data.get("evidence", ""),
            "confidence": data.get("confidence", Technology.Confidence.MEDIUM),
        },
    )

    if category == Technology.Category.OS and not asset.os:
        asset.os = f"{name} {version}".strip() if version else name
        asset.save(update_fields=["os", "updated_at"])

    port = data.get("port")
    if category == Technology.Category.WEB_SERVER and port is not None:
        service = asset.services.filter(port=port).first()
        if service and not service.product:
            service.product = name
            service.version = version
            service.save(update_fields=["product", "version", "updated_at"])

    return created


@dataclass
class FindingsSummary:
    """Contagem de findings persistidos e novas entradas no catálogo de CVEs."""

    findings: int = 0
    vulnerabilities: int = 0


def persist_findings(scan: Scan, raw_results: list[RawResult]) -> FindingsSummary:
    """Persiste findings de vulnerabilidade a partir dos resultados do adapter.

    Diferente de ``persist_results`` (inventário corrente, deduplicado), cada
    ``Finding`` aqui é uma ocorrência **imutável** amarrada a este ``scan``
    (RN003/RN005) — reexecuções criam novos registros, nunca sobrescrevem os
    anteriores. O catálogo ``Vulnerability`` (por CVE) é reaproveitado entre
    scans via ``get_or_create``.
    """
    summary = FindingsSummary()

    for result in raw_results:
        if result.kind != "vulnerability":
            continue
        data = result.data

        asset = Asset.objects.get(id=data["asset_id"])
        vulnerability, created = Vulnerability.objects.get_or_create(
            cve=data["cve"],
            defaults={
                "title": data["title"],
                "severity": data["severity"],
                "cvss_score": data.get("cvss_score"),
                "cvss_vector": data.get("cvss_vector"),
                "description": data.get("description", ""),
                "references": data.get("references", []),
            },
        )
        if created:
            summary.vulnerabilities += 1

        Finding.objects.create(
            scan=scan,
            asset=asset,
            vulnerability=vulnerability,
            category=data.get("category", "software"),
            title=data["title"],
            severity=data["severity"],
            cvss=data.get("cvss_score"),
            description=data.get("description", ""),
            evidence=data["evidence"],
            recommendation=data["recommendation"],
        )
        summary.findings += 1

    return summary
