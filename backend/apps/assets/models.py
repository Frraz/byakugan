"""Modelos de inventário: Asset e Service (ver docs/database.md)."""

from django.db import models

from apps.core.models import BaseModel


class Asset(BaseModel):
    """Ativo descoberto no ambiente (host/serviço)."""

    class Status(models.TextChoices):
        ACTIVE = "active", "Ativo"
        INACTIVE = "inactive", "Inativo"

    ip = models.GenericIPAddressField(null=True, blank=True)
    hostname = models.CharField(max_length=255, null=True, blank=True)
    domain = models.CharField(max_length=255, null=True, blank=True)
    os = models.CharField(max_length=255, null=True, blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.ACTIVE)

    def __str__(self) -> str:
        return self.hostname or self.ip or self.domain or str(self.id)


class Service(BaseModel):
    """Serviço exposto em um ativo (porta/protocolo)."""

    class Protocol(models.TextChoices):
        TCP = "tcp", "TCP"
        UDP = "udp", "UDP"

    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="services")
    port = models.PositiveIntegerField()
    protocol = models.CharField(max_length=3, choices=Protocol.choices, default=Protocol.TCP)
    service_name = models.CharField(max_length=100)
    product = models.CharField(max_length=255, null=True, blank=True)
    version = models.CharField(max_length=100, null=True, blank=True)

    class Meta(BaseModel.Meta):
        unique_together = ("asset", "port", "protocol")

    def __str__(self) -> str:
        return f"{self.asset} :{self.port}/{self.protocol} ({self.service_name})"


class Technology(BaseModel):
    """Tecnologia identificada num ativo pelo fingerprinting (Fase 2).

    Compõe o *technology profile* do ambiente: sistema operacional, servidor
    web, framework, linguagem, tecnologia de frontend, CMS, banco ou TLS.
    Cada entrada guarda a evidência que a sustentou (RN008 — nada sem contexto).
    """

    class Category(models.TextChoices):
        OS = "os", "Sistema operacional"
        WEB_SERVER = "web-server", "Servidor web"
        FRAMEWORK = "framework", "Framework"
        LANGUAGE = "language", "Linguagem"
        FRONTEND = "frontend", "Frontend"
        CMS = "cms", "CMS"
        DATABASE = "database", "Banco de dados"
        TLS = "tls", "TLS"
        OTHER = "other", "Outro"

    class Confidence(models.TextChoices):
        HIGH = "high", "Alta"
        MEDIUM = "medium", "Média"
        LOW = "low", "Baixa"

    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="technologies")
    category = models.CharField(max_length=20, choices=Category.choices)
    name = models.CharField(max_length=100)
    version = models.CharField(max_length=100, null=True, blank=True)
    #: Origem da detecção (ex.: "http-header", "html", "tls").
    source = models.CharField(max_length=50)
    evidence = models.TextField(blank=True, default="")
    confidence = models.CharField(
        max_length=10, choices=Confidence.choices, default=Confidence.MEDIUM
    )

    class Meta(BaseModel.Meta):
        unique_together = ("asset", "category", "name")

    def __str__(self) -> str:
        label = f"{self.name} {self.version}".strip()
        return f"{label} [{self.category}]"


class DnsRecord(BaseModel):
    """Registro DNS não-A/AAAA descoberto de um domínio (Fase 3 — DNS).

    Registros A/AAAA já viram o próprio ``Asset`` (``kind="host"`` em
    ``DnsAdapter``/``SubdomainAdapter``); os demais tipos (MX/NS/TXT/...) não
    representam um host novo, mas são evidência relevante do ambiente — ex.:
    SPF/DMARC em TXT, ou registros vazados por um AXFR mal configurado
    (``ZoneTransferAdapter``). Antes desta fase eram descartados no parser.
    """

    class RecordType(models.TextChoices):
        MX = "MX", "MX"
        NS = "NS", "NS"
        TXT = "TXT", "TXT"
        SOA = "SOA", "SOA"
        SRV = "SRV", "SRV"
        CNAME = "CNAME", "CNAME"
        CAA = "CAA", "CAA"
        PTR = "PTR", "PTR"

    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="dns_records")
    domain = models.CharField(max_length=255)
    record_type = models.CharField(max_length=10, choices=RecordType.choices)
    value = models.TextField()

    class Meta(BaseModel.Meta):
        unique_together = ("asset", "record_type", "value")

    def __str__(self) -> str:
        return f"{self.domain} {self.record_type} {self.value[:50]}"
