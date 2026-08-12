# Domain Model (DDD)

> Entidades, agregados e bounded contexts. O domínio é a camada mais interna (Clean Architecture): não depende de Django/DRF na regra de negócio.

## Bounded Contexts

| Contexto | Responsabilidade | Apps |
| --- | --- | --- |
| **Identity & Access** | Usuários, autenticação, RBAC | `accounts` |
| **Asset Management** | Inventário de ativos e serviços | `assets` |
| **Scanning** | Ciclo de vida do scan e adapters | `scans` |
| **Vulnerability Management** | Catálogo CVE e findings | `vulnerabilities` |
| **Risk & Correlation** | Risk score e priorização | `correlation` |
| **Reporting** | Relatórios e exportações | `reporting` |
| **Assistance** | Knowledge Base e IA | `knowledge`, `ai` |

## Agregados e entidades

### Aggregate: Scan (raiz)
- **Scan** (raiz) — dono do ciclo de vida e da autorização.
- Entidades filhas: **Finding** (criadas pelo scan).
- Value Objects: `Target`, `Authorization` (`authorized_by` + `scope`), `ScanStatus`.
- Invariantes: RN001, RN002, RN005, RN007, RN008, RN010.

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
| `Severity` | Enum: critical/high/medium/low/info. |
| `Cvss` | Score 0.0–10.0 + vetor opcional. |

## Relações entre agregados
- `Scan` referencia `Asset` e `Vulnerability` **por identidade** (IDs), não por composição direta, mantendo os agregados desacoplados.
- `Finding` liga `Scan` + `Asset` (+ opcionalmente `Vulnerability`).

## Linguagem ubíqua (glossário)
- **Asset**: host/serviço descoberto no ambiente.
- **Scan**: execução de análise autorizada sobre um alvo.
- **Finding**: ocorrência concreta de vulnerabilidade num ativo.
- **Vulnerability**: entrada de catálogo (geralmente um CVE).
- **Risk Score**: métrica derivada dos findings (CVSS + exposição + criticidade).
