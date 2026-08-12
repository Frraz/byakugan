"""Normalização de resultados brutos dos adapters em entidades de domínio.

Converte ``RawResult`` (adapters) em ``Asset``/``Service`` do inventário. Os
ativos representam o inventário corrente e são atualizados a cada descoberta;
os resultados históricos do scan (findings/reports) é que são imutáveis (RN003).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from apps.assets.models import Asset, DnsRecord, Service, Technology

from .adapters import RawResult
from .models import Finding, Scan, Vulnerability


def compute_dedup_key(*, asset_id: str, category: str, title: str) -> str:
    """Hash estável (asset + categoria + título normalizado) de um "achado lógico".

    Usado para reconhecer o "mesmo" finding reaparecendo em execuções de
    scan diferentes sobre o mesmo alvo, sem violar a imutabilidade de
    ``Finding`` (RN003) — é o que ``FindingTriage`` (Fase 5) usa como chave
    pra guardar a decisão de triagem (aberto/corrigido/falso-positivo/risco
    aceito) e ``correlation.compute_risk`` usa pra excluir achados já
    triados da soma do risk_score.

    O título é normalizado (minúsculo, espaços colapsados) para tolerar
    pequenas variações de formatação sem tolerar mudanças de conteúdo — um
    título com CVE/versão embutidos (ex.: "CVE-2024-9999 em nginx 1.24.0")
    naturalmente gera uma chave nova quando a versão muda, o que é o
    comportamento correto (é uma vulnerabilidade diferente).
    """
    normalized_title = " ".join(title.strip().lower().split())
    raw = f"{asset_id}:{category}:{normalized_title}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class PersistenceSummary:
    """Contagem do que foi persistido a partir de um scan."""

    assets: int = 0
    services: int = 0
    technologies: int = 0
    dns_records: int = 0


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
                service, created = Service.objects.get_or_create(
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
                elif data.get("product") and not service.product:
                    # Banner grab tardio (ex.: reexecução) identificou produto/versão
                    # para um serviço já conhecido — enriquece sem duplicar.
                    service.product = data["product"]
                    service.version = data.get("version")
                    service.save(update_fields=["product", "version", "updated_at"])

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

        elif result.kind == "dns_record":
            domain = data["domain"]
            asset = _get_or_create_asset(ip=None, hostname=None, domain=domain)
            if str(asset.id) not in seen_assets:
                seen_assets.add(str(asset.id))
                summary.assets += 1
            _, created = DnsRecord.objects.get_or_create(
                asset=asset,
                record_type=data["record_type"],
                value=data["value"],
                defaults={"domain": domain},
            )
            if created:
                summary.dns_records += 1

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

    Nem todo finding tem um CVE associado — adapters de TLS/certificado, web,
    DNS etc. detectam exposição/má-configuração sem uma entrada na NVD. Nesse
    caso ``vulnerability`` fica ``None`` e não há entrada de catálogo a
    criar/reaproveitar; a validade do finding (descrição/evidência/
    recomendação não-vazias) é garantida por ``Finding.save()`` — RN008.

    Resolução do ativo: adapters que já leem o profile persistido (ex.:
    ``CveLookupAdapter``, que roda na fase de vulnerability, depois do
    ``persist_results`` da fase de profile) informam ``asset_id`` direto.
    Adapters de fase "profile" que também emitem ``kind="vulnerability"``
    (ex.: ``TlsAdapter``) rodam **antes** de qualquer ativo existir — para
    esses, resolvemos/criamos o ativo pela chave natural (mesmo helper de
    ``persist_results``), a partir de ``ip``/``hostname``/``host``/``domain``.
    """
    summary = FindingsSummary()

    for result in raw_results:
        if result.kind != "vulnerability":
            continue
        data = result.data

        if data.get("asset_id"):
            asset = Asset.objects.get(id=data["asset_id"])
        else:
            asset = _get_or_create_asset(
                ip=data.get("ip"),
                hostname=data.get("hostname") or data.get("host"),
                domain=data.get("domain"),
            )

        vulnerability = None
        cve = data.get("cve")
        if cve:
            vulnerability, created = Vulnerability.objects.get_or_create(
                cve=cve,
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

        category = data.get("category", "software")
        Finding.objects.create(
            scan=scan,
            asset=asset,
            vulnerability=vulnerability,
            category=category,
            title=data["title"],
            severity=data["severity"],
            cvss=data.get("cvss_score"),
            description=data.get("description", ""),
            evidence=data.get("evidence", ""),
            recommendation=data.get("recommendation", ""),
            dedup_key=compute_dedup_key(
                asset_id=str(asset.id), category=category, title=data["title"]
            ),
        )
        summary.findings += 1

    return summary
