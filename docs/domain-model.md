# Domain Model (DDD)

> Entidades, agregados e bounded contexts. O domínio é a camada mais interna (Clean Architecture): não depende de Django/DRF na regra de negócio.

## Bounded Contexts

| Contexto | Responsabilidade | Apps (Django) |
| --- | --- | --- |
| **Identity & Access** | Usuários, autenticação, RBAC | `accounts` |
| **Asset Management** | Inventário de ativos e serviços | `assets` |
| **Scanning** | Ciclo de vida do scan e scanner adapters | `scans` |
| **Vulnerability Management** | Catálogo CVE, findings e classificação OWASP/CWE | `scans` |
| **Exploitation** | Prova de impacto sob RoE (`Evidence`) e playbooks curados | `scans` (`scans/exploit/`) |
| **Risk & Correlation** | Risk score, priorização e cobertura OWASP | `scans` (`correlation.py`, `owasp_coverage.py`) |
| **Reporting** | Relatórios e exportações | `reports` |
| **Assistance** | Knowledge Base (e IA, planejada) | `knowledge` (IA: futura) |
| **Cross-cutting** | `BaseModel`, auditoria, health, logging | `core` |

> Nota: Vulnerability Management, Exploitation e Risk & Correlation são **contextos lógicos** hospedados no app `scans` (não são apps Django separados), refletindo a fronteira de código real. A IA é um contexto planejado (ver `docs/ai-assistant.md`), ainda sem app.

## Agregados e entidades

### Aggregate: Scan (raiz)
- **Scan** (raiz) — dono do ciclo de vida e da autorização.
- Entidades filhas: **Finding** (criadas pelo scan), **Evidence** (provas de exploração do scan).
- Value Objects: `Target`, `Authorization` (`authorized_by` + `scope`), `ScanStatus`, `OwaspClassification` (`owasp_2021` + `owasp_2025` + `cwe`).
- Invariantes: RN001, RN002, RN005, RN007, RN008, RN010, RN016, RN024 (todo Finding classificado no OWASP 2021/2025 + CWE).

### Aggregate: Evidence (raiz / prova de exploração)
- **Evidence** — resultado **imutável** de uma tentativa de exploração (RN003/RN023): status, `impact_level`, prova extraída (amostra limitada), passos executados, cadeia e perfil de RoE.
- Ligada a `Finding` + `Scan` + `Asset` por identidade, e à classe via `playbook_key`.
- Invariantes: RN021 (piso de não-dano), RN022 (gating fail-closed), RN023 (imutável).

### Aggregate: ExploitationPlaybook (raiz / conteúdo vivo)
- **ExploitationPlaybook** — guia curado de exploração por classe (`key` == `Finding.playbook_key`): pré-condições, passos de PoC manual, cadeia de escalação, impacto máximo, ferramentas e referências (OWASP 2021/2025 + CWE).
- Conteúdo **editável** (como a Knowledge Base) — RN003 não se aplica (RN023).

### Aggregate: Asset (raiz)
- **Asset** (raiz).
- Entidades filhas: **Service**.
- Value Objects: `IpAddress`, `Hostname`, `OsFingerprint`.

### Aggregate: Vulnerability (raiz / catálogo)
- **Vulnerability** — referência compartilhável (CVE).
- Value Objects: `Cvss` (score + vector), `Severity`.
- Invariante: RN004.

### Aggregate: Report (raiz)
- **Report** — rastreável ao Scan de origem (RN005).
- Value Objects: `ReportType`, `ReportFormat`.

### Entidade transversal: AuditLog
Registro imutável de eventos (RN011). Não pertence a um agregado de negócio; é infraestrutura de auditoria.

## Value Objects principais

| VO | Regras |
| --- | --- |
| `Target` | Formato válido de host/domínio/lista de IPs (RN001). |
| `Authorization` | `authorized_by` não vazio + `scope` definido (RN007). |
| `ScanStatus` | Transições válidas apenas (RN010). |
| `Severity` | Enum: critical/high/medium/low/info (gravidade teórica). |
| `Cvss` | Score 0.0–10.0 + vetor opcional. |
| `ImpactLevel` | Impacto **comprovado** por exploração: rce/db-read/file-read/auth-bypass/ssrf/info-disclosure/session/none. |
| `OwaspClassification` | `owasp_2021` + `owasp_2025` (A01–A10 de cada edição) + `cwe` primário; derivada da classe/categoria (RN024). |

## Relações entre agregados
- `Scan` referencia `Asset` e `Vulnerability` **por identidade** (IDs), não por composição direta, mantendo os agregados desacoplados.
- `Finding` liga `Scan` + `Asset` (+ opcionalmente `Vulnerability`).

## Linguagem ubíqua (glossário)
- **Asset**: host/serviço descoberto no ambiente.
- **Scan**: execução de análise autorizada sobre um alvo.
- **Finding**: ocorrência concreta de vulnerabilidade num ativo.
- **Vulnerability**: entrada de catálogo (geralmente um CVE).
- **Risk Score**: métrica derivada dos findings (CVSS + exposição + criticidade).
- **Evidence**: prova imutável do que o motor de exploração de fato executou e comprovou sobre um finding (o "até onde o Byakugan foi").
- **ExploitationPlaybook**: guia curado (vivo) de como explorar manualmente uma classe e "até onde dá para ir" (cadeia de escalação).
- **Impact Level**: nível de impacto *comprovado* por exploração (distinto da severidade teórica).
- **OWASP category**: categoria do OWASP Top 10 (edições 2021 e 2025) atribuída a um finding, com o CWE primário.
