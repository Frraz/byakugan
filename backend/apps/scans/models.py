"""Modelos do motor de análise: Scan, Vulnerability e Finding.

Ver docs/database.md e docs/scanning-engine.md. Resultados são imutáveis (RN003).
"""

from decimal import Decimal

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from apps.assets.models import Asset
from apps.core.models import BaseModel


class Severity(models.TextChoices):
    """Severidade compartilhada por vulnerabilidades e findings."""

    CRITICAL = "critical", "Crítica"
    HIGH = "high", "Alta"
    MEDIUM = "medium", "Média"
    LOW = "low", "Baixa"
    INFO = "info", "Informativa"


class FindingCategory(models.TextChoices):
    """Categorias de finding produzidas pelos adapters (motor ofensivo).

    ``Finding.category`` continua ``CharField`` livre (compatibilidade com
    linhas antigas), mas as escolhas aqui guiam a UI (heatmap, legendas) e a
    correlação por categoria (``docs/scanning-engine.md``).
    """

    SOFTWARE = "software", "Software (CVE)"
    SERVICE = "service", "Serviço de rede"
    NETWORK = "network", "Rede"
    CREDENTIAL = "credential", "Credencial"
    TLS = "tls", "TLS"
    CERTIFICATE = "certificate", "Certificado"
    DNS = "dns", "DNS"
    EMAIL_SECURITY = "email-security", "Segurança de e-mail"
    SUBDOMAIN = "subdomain", "Subdomínio"
    WEB_HEADERS = "web-headers", "Headers HTTP"
    COOKIE = "cookie", "Cookie"
    CORS = "cors", "CORS"
    EXPOSURE = "exposure", "Exposição"
    HTTP_METHOD = "http-method", "Método HTTP"
    INJECTION = "injection", "Injeção"


class Target(BaseModel):
    """Alvo cadastrado com autorização reutilizável (RF004, RN007).

    Centraliza o registro de autorização para que vários scans referenciem o
    mesmo alvo. Ver docs/database.md e docs/scanning-engine.md.
    """

    class Kind(models.TextChoices):
        HOST = "host", "Host"
        DOMAIN = "domain", "Domínio"
        IP = "ip", "IP"
        CIDR = "cidr", "CIDR"

    name = models.CharField(max_length=255)
    value = models.CharField(max_length=255)
    kind = models.CharField(max_length=10, choices=Kind.choices)
    authorized_by = models.CharField(max_length=255)
    authorization_scope = models.TextField()
    authorization_expires_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="targets",
    )

    def __str__(self) -> str:
        return f"{self.name} ({self.value})"


class Scan(BaseModel):
    """Execução de análise autorizada sobre um alvo.

    A autorização (``authorized_by`` + ``authorization_scope``) é obrigatória
    antes da execução (RN007). Estados seguem a máquina definida em RN010.
    """

    class ScanType(models.TextChoices):
        DISCOVERY = "discovery", "Discovery"
        FINGERPRINT = "fingerprint", "Fingerprint"
        VULNERABILITY = "vulnerability", "Vulnerability"
        FULL = "full", "Full"

    class Status(models.TextChoices):
        PENDING = "pending", "Pendente"
        RUNNING = "running", "Executando"
        COMPLETED = "completed", "Concluído"
        FAILED = "failed", "Falhou"
        CANCELLED = "cancelled", "Cancelado"

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="scans",
    )
    target_ref = models.ForeignKey(
        Target,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scans",
    )
    target = models.CharField(max_length=255)
    scan_type = models.CharField(
        max_length=20, choices=ScanType.choices, default=ScanType.DISCOVERY
    )
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    authorized_by = models.CharField(max_length=255)
    authorization_scope = models.TextField()
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    failure_reason = models.TextField(blank=True, default="")
    options = models.JSONField(default=dict, blank=True)
    progress = models.PositiveSmallIntegerField(default=0)
    phase = models.CharField(max_length=255, blank=True, default="")
    celery_task_id = models.CharField(max_length=255, blank=True, default="")

    def __str__(self) -> str:
        return f"Scan {self.target} [{self.scan_type}] - {self.status}"


class Vulnerability(BaseModel):
    """Entrada de catálogo de vulnerabilidade (geralmente um CVE)."""

    cve = models.CharField(max_length=30, null=True, blank=True, db_index=True)
    title = models.CharField(max_length=255)
    severity = models.CharField(max_length=20, choices=Severity.choices)
    cvss_score = models.DecimalField(max_digits=3, decimal_places=1, null=True, blank=True)
    cvss_vector = models.CharField(max_length=100, null=True, blank=True)
    description = models.TextField()
    references = models.JSONField(default=list, blank=True)

    def __str__(self) -> str:
        return self.cve or self.title


class Finding(BaseModel):
    """Ocorrência concreta de uma vulnerabilidade num ativo (RN008).

    Nenhum finding pode ser salvo sem descrição, evidência e recomendação —
    validado em ``clean()``/``save()``, não apenas por convenção do parser.
    """

    scan = models.ForeignKey(Scan, on_delete=models.PROTECT, related_name="findings")
    asset = models.ForeignKey(Asset, on_delete=models.PROTECT, related_name="findings")
    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="findings",
    )
    category = models.CharField(max_length=50, choices=FindingCategory.choices)
    title = models.CharField(max_length=255)
    severity = models.CharField(max_length=20, choices=Severity.choices)
    cvss = models.DecimalField(max_digits=3, decimal_places=1, null=True, blank=True)
    description = models.TextField()
    evidence = models.TextField()
    recommendation = models.TextField()
    #: Hash estável (asset + category + título normalizado) que identifica o
    #: mesmo "achado lógico" entre execuções de scan distintas — ver
    #: ``parsers.compute_dedup_key`` e ``FindingTriage`` (Fase 5). Não é
    #: único aqui de propósito: cada reexecução cria um novo Finding (RN003),
    #: todos compartilhando o mesmo dedup_key.
    dedup_key = models.CharField(max_length=64, db_index=True, blank=True, default="")
    #: Chave estável da classe de vulnerabilidade (ex.: ``injection.sqli-error``,
    #: ``exposure.git``, ``credential.default``) — Fase 7+. Liga o finding ao
    #: ``ExploitationPlaybook`` curado (aba Evidências) e ao ``ExploitModule``
    #: correspondente (motor de exploração). Vazio em linhas antigas
    #: (retrocompatível) e em findings sem playbook/exploit mapeado.
    playbook_key = models.CharField(max_length=64, db_index=True, blank=True, default="")

    def __str__(self) -> str:
        return f"{self.title} ({self.severity})"

    def clean(self) -> None:
        """RN008: nenhum finding sem descrição, evidência e recomendação."""
        super().clean()
        missing = [
            field
            for field in ("description", "evidence", "recommendation")
            if not (getattr(self, field) or "").strip()
        ]
        if missing:
            raise ValidationError(
                {field: "Campo obrigatório para o finding (RN008)." for field in missing}
            )

    def save(self, *args, **kwargs):
        if isinstance(self.cvss, float):
            # DecimalField.to_python() em full_clean() usa
            # Decimal.from_float() para valores float, cujo binário exato
            # (ex.: 9.8 → 9.8000000000000007105...) arredonda para mais casas
            # decimais que o valor original tem — rejeitando um CVSS válido
            # como 9.8. Os adapters (ex.: NVD) entregam CVSS como float; a
            # conversão via string preserva o valor pretendido.
            self.cvss = Decimal(str(self.cvss))
        self.full_clean()
        super().save(*args, **kwargs)


class FindingTriage(BaseModel):
    """Estado de triagem mutável de um "achado lógico" (por ``dedup_key``) — Fase 5.

    ``Finding`` é imutável por scan (RN003) — toda reexecução cria um novo
    registro, mesmo quando é "o mesmo" achado de antes. ``FindingTriage`` é a
    camada mutável que permite a um analista classificar esse achado lógico
    (aberto/corrigido/falso positivo/risco aceito) sem jamais reescrever o
    histórico do ``Finding`` original — um único registro de triagem vale
    para todos os ``Finding`` (passados e futuros) que compartilham o mesmo
    ``dedup_key``. ``correlation.compute_risk`` exclui da soma os findings
    cujo ``dedup_key`` esteja triado como corrigido/falso-positivo/risco
    aceito — sem isso, o risk_score aditivo infla a cada reexecução do mesmo
    scan sobre o mesmo alvo, mesmo sem mudança real de risco.
    """

    class Status(models.TextChoices):
        OPEN = "open", "Aberto"
        FIXED = "fixed", "Corrigido"
        FALSE_POSITIVE = "false-positive", "Falso positivo"
        ACCEPTED_RISK = "accepted-risk", "Risco aceito"

    #: Status que retiram o achado do risk_score somado (compute_risk).
    RESOLVED_STATUSES = (Status.FIXED, Status.FALSE_POSITIVE, Status.ACCEPTED_RISK)

    dedup_key = models.CharField(max_length=64, unique=True, db_index=True)
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="finding_triages")
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    note = models.TextField(blank=True, default="")
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="finding_triages",
    )

    def __str__(self) -> str:
        return f"{self.dedup_key[:12]}... [{self.status}]"


class ImpactLevel(models.TextChoices):
    """Nível de impacto **comprovado** por uma exploração (aba Evidências).

    Diferente de ``Severity`` (gravidade teórica do finding), descreve o que a
    exploração de fato demonstrou alcançar — ex.: um XSS refletido tem
    severity ``high`` mas o impacto comprovado pode ser só ``session`` se o
    Byakugan não conseguiu encadear além disso.
    """

    RCE = "rce", "Execução remota de código"
    DB_READ = "db-read", "Leitura de banco de dados"
    FILE_READ = "file-read", "Leitura de arquivos do servidor"
    AUTH_BYPASS = "auth-bypass", "Bypass de autenticação"
    SSRF = "ssrf", "Acesso a rede/recursos internos"
    INFO_DISCLOSURE = "info-disclosure", "Vazamento de informação"
    SESSION = "session", "Roubo/manipulação de sessão"
    NONE = "none", "Sem impacto comprovado"


class ExploitationPlaybook(BaseModel):
    """Guia curado de exploração por classe de vulnerabilidade (aba Evidências).

    Conteúdo de referência **vivo** (como ``knowledge.KnowledgeArticle``, e ao
    contrário do histórico imutável de ``Finding``/``Evidence`` — RN003 não se
    aplica aqui): descreve como um pentester exploraria manualmente a falha,
    **até onde dá para ir** (cadeia de escalação) e como fazer. A UI interpola
    o playbook com o contexto real do finding (URL, parâmetro, ativo).

    Casado a findings por ``key`` == ``Finding.playbook_key`` (ex.:
    ``injection.sqli-error``). É o lado "manual/educacional" da aba; o lado
    "automatizado" (o que o Byakugan realmente executou) é ``Evidence``.
    """

    #: Classe de vulnerabilidade — casa com ``Finding.playbook_key``.
    key = models.SlugField(max_length=64, unique=True)
    title = models.CharField(max_length=255)
    category = models.CharField(max_length=50, choices=FindingCategory.choices)
    #: Rótulo curto da classe (ex.: "SQL Injection", "Path Traversal").
    vuln_class = models.CharField(max_length=100)
    summary = models.TextField()
    #: Pré-condições para a exploração ser viável (ex.: "parâmetro refletido").
    prerequisites = models.TextField(blank=True, default="")
    #: Passos manuais de prova de conceito: lista de
    #: ``{"action", "command", "expected"}`` (command é template com
    #: placeholders ``{url}``/``{param}``/``{host}`` interpolados na UI).
    steps = models.JSONField(default=list)
    #: "Até onde dá para ir": estágios de escalação, cada um
    #: ``{"stage", "impact", "description"}`` — do menor ao maior impacto.
    escalation_path = models.JSONField(default=list)
    #: Maior impacto atingível pela classe (``ImpactLevel``).
    max_impact = models.CharField(
        max_length=20, choices=ImpactLevel.choices, default=ImpactLevel.INFO_DISCLOSURE
    )
    #: Ferramentas típicas (ex.: ``["sqlmap", "Burp Suite", "curl"]``).
    tools = models.JSONField(default=list, blank=True)
    references = models.JSONField(default=list, blank=True)

    def __str__(self) -> str:
        return f"{self.title} ({self.key})"


class Evidence(BaseModel):
    """Resultado **imutável** de uma tentativa de exploração automatizada (RN003).

    Registra o que o motor de exploração (``apps/scans/exploit/``) de fato
    executou contra um ``Finding`` já detectado — sob Regras de Engajamento de
    não-dano (nunca destrói/DoS/persiste/exfiltra em massa; ver
    ``docs/exploitation-engine.md``). Cada tentativa gera um novo registro,
    amarrado ao scan, nunca sobrescrito — é histórico de auditoria.

    Combinado com o ``ExploitationPlaybook`` de mesmo ``playbook_key``, alimenta
    a aba Evidências: o playbook mostra "até onde dá para ir" manualmente; a
    ``Evidence`` mostra "até onde o Byakugan foi" automaticamente.
    """

    class Status(models.TextChoices):
        PROVEN = "proven", "Comprovado"
        ATTEMPTED = "attempted", "Tentado (sem prova)"
        FAILED = "failed", "Falhou"
        BLOCKED = "blocked", "Bloqueado (gating/RoE)"
        NOT_ATTEMPTED = "not-attempted", "Não tentado"

    finding = models.ForeignKey(Finding, on_delete=models.PROTECT, related_name="evidences")
    scan = models.ForeignKey(Scan, on_delete=models.PROTECT, related_name="evidences")
    asset = models.ForeignKey(Asset, on_delete=models.PROTECT, related_name="evidences")
    playbook_key = models.CharField(max_length=64, db_index=True, blank=True, default="")
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.ATTEMPTED)
    #: Impacto comprovado (``ImpactLevel``) — só significativo quando ``proven``.
    impact_level = models.CharField(
        max_length=20, choices=ImpactLevel.choices, default=ImpactLevel.NONE
    )
    #: Artefato benigno/limitado extraído como prova (versão do banco, saída de
    #: ``id``, amostra ≤3 linhas, usuários enumerados) — nunca dados sensíveis
    #: em massa (RoE).
    proof = models.TextField(blank=True, default="")
    #: Passos que o motor realmente executou: lista de
    #: ``{"action", "request", "response_excerpt", "result"}`` — é o "até onde foi".
    steps_performed = models.JSONField(default=list)
    #: Findings adjacentes encadeados nesta exploração (ex.: SSRF → metadata).
    chain = models.JSONField(default=list, blank=True)
    #: Perfil de RoE usado (ex.: ``extended``).
    roe_profile = models.CharField(max_length=20, blank=True, default="")

    def __str__(self) -> str:
        return f"Evidence[{self.status}] {self.playbook_key} ({self.impact_level})"

    def save(self, *args, **kwargs):
        # Imutável após criado (RN003) — como AuditLog. Reexecuções criam novos
        # registros; nunca reescrevem o histórico de exploração.
        if self._state.adding is False:
            raise ValueError("Evidence é imutável e não pode ser atualizada (RN003).")
        super().save(*args, **kwargs)
