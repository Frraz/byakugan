# Modelo de Dados

> Banco: **PostgreSQL**. Todas as tabelas herdam de um `BaseModel` com `id` (UUID), `created_at`, `updated_at`. Resultados de scan são **imutáveis** (RN003).

## Diagrama de relacionamentos (visão lógica)

```
User ──< Target ──< Scan ──< Finding
             │          │        │
             │          │        └──> Vulnerability (CVE)
             │          ▼
             │       Asset ──< Service
             │          │ └──< Technology
             │          │
             └──────────┘  (Scan ──< Report)

User ──< AuditLog
```

## Tabelas

### users
Usuário do sistema (autenticação por email).

| Campo | Tipo | Notas |
| --- | --- | --- |
| id | UUID (PK) | |
| email | string | único, login |
| password | string | hash Argon2 — nunca em texto puro |
| role | enum | `admin` \| `analyst` \| `viewer` (RBAC) |
| is_active | bool | |
| created_at / updated_at | datetime | |

### targets
Alvo cadastrado com autorização reutilizável. Centraliza o registro de autorização (RN007) para que vários scans possam referenciar o mesmo alvo sem redigitar a autorização.

| Campo | Tipo | Notas |
| --- | --- | --- |
| id | UUID (PK) | |
| name | string | rótulo amigável (ex.: "DMZ empresa X") |
| value | string | host, domínio, IP ou CIDR |
| kind | enum | `host` \| `domain` \| `ip` \| `cidr` (derivado da validação RN001) |
| authorized_by | string | quem autorizou (nome/papel) |
| authorization_scope | text | escopo permitido (domínios, IPs, sub-redes) |
| authorization_expires_at | datetime | validade da autorização (nullable) |
| is_active | bool | alvo ativo para novos scans |
| created_by | FK → users | quem cadastrou |
| created_at / updated_at | datetime | |

> Um `Scan` pode referenciar um `Target` (FK nullable), mas **copia** `target`, `authorized_by` e `authorization_scope` para os próprios campos no momento da criação — assim o histórico do scan permanece imutável (RN003) mesmo que o Target seja editado ou desativado depois.

### assets
Ativo descoberto (host/serviço na infraestrutura).

| Campo | Tipo | Notas |
| --- | --- | --- |
| id | UUID (PK) | |
| ip | inet | nullable |
| hostname | string | nullable |
| domain | string | nullable |
| os | string | fingerprint do sistema operacional (nullable) |
| status | enum | `active` \| `inactive` |
| created_at / updated_at | datetime | |

### technologies
Tecnologia identificada num ativo pelo fingerprinting (Fase 2). Compõe o *technology profile* do ambiente.

| Campo | Tipo | Notas |
| --- | --- | --- |
| id | UUID (PK) | |
| asset | FK → assets | ativo onde a tecnologia foi identificada |
| category | enum | `os` \| `web-server` \| `framework` \| `language` \| `frontend` \| `cms` \| `database` \| `tls` \| `other` |
| name | string | ex.: `nginx`, `Django`, `WordPress` |
| version | string | nullable (ex.: `1.24.0`) |
| source | string | origem da detecção (`http-header`, `http-cookie`, `html`, `tls`) |
| evidence | text | trecho que sustentou a detecção (RN008) |
| confidence | enum | `high` \| `medium` \| `low` |
| created_at / updated_at | datetime | |

> Chave natural: (`asset`, `category`, `name`). Reexecuções de fingerprint atualizam versão/evidência em vez de duplicar. Uma tecnologia de categoria `os` também preenche `assets.os`; uma `web-server` complementa `product`/`version` do `service` da porta correspondente.

### scans
Execução de análise sobre um ou mais alvos.

| Campo | Tipo | Notas |
| --- | --- | --- |
| id | UUID (PK) | |
| created_by | FK → users | quem criou |
| target_ref | FK → targets | alvo cadastrado de origem (nullable; ver nota de imutabilidade) |
| target | string | alvo (host/domínio/lista) — cópia denormalizada |
| scan_type | enum | `discovery` \| `fingerprint` \| `vulnerability` \| `full` |
| status | enum | `pending` \| `running` \| `completed` \| `failed` \| `cancelled` |
| authorized_by | string | registro de autorização (RNF010 / RN007) |
| authorization_scope | text | escopo permitido |
| started_at / finished_at | datetime | nullable |
| created_at / updated_at | datetime | |

### services
Serviço exposto em um ativo.

| Campo | Tipo | Notas |
| --- | --- | --- |
| id | UUID (PK) | |
| asset | FK → assets | |
| port | int | |
| protocol | enum | `tcp` \| `udp` |
| service_name | string | ex.: `ssh`, `http` |
| product | string | ex.: `OpenSSH`, `nginx` (nullable) |
| version | string | nullable |
| created_at / updated_at | datetime | |

### vulnerabilities
Vulnerabilidade conhecida (catálogo, referenciável por vários findings).

| Campo | Tipo | Notas |
| --- | --- | --- |
| id | UUID (PK) | |
| cve | string | ex.: `CVE-2024-XXXXX` (nullable p/ vulns sem CVE) |
| title | string | |
| severity | enum | `critical` \| `high` \| `medium` \| `low` \| `info` |
| cvss_score | decimal(3,1) | 0.0–10.0 |
| cvss_vector | string | nullable |
| description | text | |
| references | jsonb | lista de URLs |
| created_at / updated_at | datetime | |

> Populado pelo `CveLookupAdapter` (Fase 3) via correlação NVD CVE 2.0 por produto/versão. Chave natural: `cve` — reaproveitado entre scans (`get_or_create`), nunca duplicado.

### findings
Ocorrência concreta de uma vulnerabilidade num ativo, detectada por um scan.

| Campo | Tipo | Notas |
| --- | --- | --- |
| id | UUID (PK) | |
| scan | FK → scans | rastreabilidade (RN005) |
| asset | FK → assets | |
| vulnerability | FK → vulnerabilities | nullable |
| category | string | ex.: `web`, `network`, `tls` |
| title | string | |
| severity | enum | ver acima |
| cvss | decimal(3,1) | nullable |
| description | text | obrigatório (RN — finding sem contexto não é salvo) |
| evidence | text | obrigatório |
| recommendation | text | obrigatório |
| created_at / updated_at | datetime | |

> Diferente de `assets`/`services`/`technologies` (inventário corrente, deduplicado), cada `finding` é **imutável e amarrado ao scan que o gerou** (RN003/RN005) — reexecuções criam novos registros, nunca sobrescrevem os anteriores.

### reports
Relatório gerado a partir de um scan.

| Campo | Tipo | Notas |
| --- | --- | --- |
| id | UUID (PK) | |
| scan | FK → scans | rastreabilidade (RN005) |
| report_type | enum | `executive` \| `technical` |
| format | enum | `pdf` \| `csv` \| `json` |
| file_path | string | artefato gerado |
| created_by | FK → users | |
| created_at | datetime | |

### audit_logs
Trilha de auditoria imutável.

| Campo | Tipo | Notas |
| --- | --- | --- |
| id | UUID (PK) | |
| user | FK → users | nullable (eventos de sistema) |
| action | string | ex.: `login`, `scan.create`, `report.export` |
| severity | enum | `info` \| `warning` \| `critical` |
| source | string | ip/origem |
| metadata | jsonb | detalhes do evento |
| timestamp | datetime | |

## Regras de integridade

- **Imutabilidade**: registros de `scans`, `findings` e `reports` não são atualizados após conclusão nem apagados (exceto por admin, conforme RN006).
- **Findings sempre com contexto**: `description`, `evidence` e `recommendation` são obrigatórios.
- **Autorização**: `scans.authorized_by` obrigatório antes da execução.
