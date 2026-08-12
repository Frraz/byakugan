# API REST

> Base: `/api`. Formato: JSON. Autenticação: **Bearer JWT** (exceto `login`, `register` público conforme política e `health`). Erros seguem `{ "detail": "..." }` ou `{ "campo": ["erro"] }`.

## Convenções

- Versionamento por prefixo (`/api/...`; futura `/api/v1/...`).
- Paginação: `?page=&page_size=` → `{ count, next, previous, results }`.
- Filtros comuns: `?ordering=`, `?search=`, filtros por campo conforme recurso.
- Status codes: `200` ok, `201` criado, `204` sem conteúdo, `400` validação, `401` não autenticado, `403` sem permissão (RBAC), `404` não encontrado, `409` conflito (ex.: scan duplicado), `429` rate limit.

---

## Health

### `GET /api/health/`
Verifica se a API está no ar. Público.

**200**
```json
{ "status": "ok", "service": "byakugan-api", "version": "0.1.0", "time": "2026-08-12T12:00:00Z" }
```

---

## Autenticação

> Tokens JWT: **access** expira em 15 min, **refresh** em 7 dias (rotação + blacklist no logout). Ver `docs/security.md`.

### `POST /api/auth/login/`
```json
// request
{ "email": "analyst@empresa.com", "password": "***" }
// 200
{ "access": "<jwt>", "refresh": "<jwt>", "user": { "id": "...", "email": "...", "role": "analyst" } }
```

### `POST /api/auth/refresh/`
```json
{ "refresh": "<jwt>" }  // → 200 { "access": "<jwt>" }
```

### `POST /api/auth/logout/`
Invalida o refresh token (blacklist). Requer autenticação.
```json
{ "refresh": "<jwt>" }  // → 205 Reset Content
```

### `GET /api/auth/me/`
Retorna o usuário autenticado.
```json
// 200
{ "id": "...", "email": "analyst@empresa.com", "role": "analyst" }
```

### `POST /api/auth/register/`
Criação de usuário (restrito a `admin`).
```json
{ "email": "...", "password": "***", "role": "analyst" }  // → 201
```

---

## Targets

### `GET /api/targets/`
Lista alvos cadastrados. Filtros: `?is_active=`, `?kind=`, `?search=` (name/value). Cada item inclui `scans_count` (nº de scans vinculados — usado pela UI para avisar antes de excluir).

### `POST /api/targets/`
Cadastra um alvo com autorização (papel `analyst` ou `admin`). O `value` é validado (RN001) e `kind` é derivado.
```json
// request
{
  "name": "DMZ empresa X",
  "value": "192.168.10.0/24",
  "authorized_by": "João Silva (CISO)",
  "authorization_scope": "192.168.10.0/24",
  "authorization_expires_at": "2026-12-31T00:00:00Z"
}
// 201
{ "id": "...", "name": "DMZ empresa X", "value": "192.168.10.0/24", "kind": "cidr", "is_active": true }
// 400 — value malformado (RN001)
{ "value": ["Alvo inválido: informe host, domínio, IP ou CIDR válido."] }
```

### `GET /api/targets/{id}/` · `PATCH` · `DELETE`
Detalhe, atualização e exclusão (exclusão apenas `admin`, auditada — RN006).

- `PATCH`: papel `analyst`/`admin`. Se `value` mudar, `kind` é **reclassificado** automaticamente (RN001) e o evento `target.update` é auditado (RN011).
- `DELETE`: os scans vinculados são **preservados** — ficam com `target_ref` nulo, mantendo as cópias de `target`/`authorized_by`/`authorization_scope` feitas na criação.

---

## Assets

### `GET /api/assets/`
Lista ativos. Filtros: `?status=`, `?search=` (ip/hostname/domain).
```json
// 200 (results[])
{ "id": "...", "ip": "192.168.0.10", "hostname": "web-01", "domain": "empresa.com", "os": "Ubuntu 24.04", "status": "active" }
```

### `GET /api/assets/{id}/`
Detalhe do ativo, incluindo serviços e findings relacionados.

### `GET /api/assets/{id}/services/`
Lista serviços do ativo.
```json
{ "id": "...", "port": 443, "protocol": "tcp", "service_name": "https", "product": "nginx", "version": "1.24.0" }
```

### `GET /api/assets/{id}/technologies/`
Lista as tecnologias identificadas no ativo pelo fingerprinting (*technology profile* — Fase 2).
```json
{
  "id": "...", "asset": "...", "category": "web-server", "name": "nginx",
  "version": "1.24.0", "source": "http-header", "evidence": "Server: nginx/1.24.0",
  "confidence": "high"
}
```
> `category`: `os` · `web-server` · `framework` · `language` · `frontend` · `cms` · `database` · `tls` · `other`. O detalhe do ativo (`GET /api/assets/{id}/`) já inclui `technologies` aninhadas.

---

## Scans

### `GET /api/scans/`
Lista scans. Filtros: `?status=`, `?scan_type=`, `?search=` (target). Cada item inclui contexto agregado para a UI: `target_name` (nome do Target cadastrado, se vinculado), `findings_count` e `severity_counts` (`{"critical": n, "high": n, "medium": n, "low": n, "info": n}`).

### `POST /api/scans/`
Cria e enfileira um scan. Requer papel `analyst` ou `admin`. Aceita **um `target_ref`** (id de um Target cadastrado — a autorização é herdada) **ou** os campos de alvo/autorização inline. O alvo é validado contra o escopo antes de enfileirar (RN007) e a varredura só executa se `BYAKUGAN_SCANNING_ENABLED` estiver ativo.
```json
// request (via target cadastrado)
{ "target_ref": "<target-id>", "scan_type": "discovery" }

// request (inline)
{
  "target": "empresa.com",
  "scan_type": "full",
  "authorized_by": "João Silva (CISO)",
  "authorization_scope": "domínio empresa.com e sub-redes internas"
}
// 201
{ "id": "...", "status": "pending", "target": "empresa.com", "scan_type": "full", "created_at": "..." }
// 400 — alvo fora do escopo autorizado (RN007)
{ "detail": "Alvo fora do escopo autorizado." }
// 409 — se já houver scan em execução para o mesmo alvo (RN002)
{ "detail": "Já existe um scan em execução para este alvo." }
```

### `GET /api/scans/{id}/`
Detalhe e estado do scan (`pending|running|completed|failed|cancelled`).

### `POST /api/scans/{id}/cancel/`
Cancela um scan em execução.

### `GET /api/scans/{id}/findings/`
Findings produzidos pelo scan.

### `GET /api/scans/{id}/services/`
Serviços descobertos pelo scan (via ativos relacionados aos findings).

### `DELETE /api/scans/{id}/`
Exclui um scan **em cascata** (RN014): remove findings, relatórios e artefatos em disco. Restrito a `admin` (RN006); auditado com contagens (`scan.delete`).
```json
// 409 — scan ainda ativo (pending/running)
{ "detail": "Cancele o scan antes de excluí-lo." }
```

---

## Vulnerabilities & Findings

### `GET /api/vulnerabilities/`
Catálogo de vulnerabilidades. Filtros: `?severity=`, `?search=` (cve/título).

### `GET /api/findings/`
Findings do ambiente. Filtros: `?severity=`, `?asset=`, `?scan=`, `?category=`, `?search=` (título/categoria/CVE). `asset`, `scan` e `vulnerability` vêm **aninhados** (resumo) para a UI exibir contexto sem requests extras.
```json
{
  "id": "...", "category": "tls",
  "asset": { "id": "...", "hostname": "web-01", "ip": "192.168.0.10", "domain": "" },
  "scan": { "id": "...", "target": "empresa.com", "scan_type": "full", "created_at": "..." },
  "vulnerability": {
    "id": "...", "cve": "CVE-2024-1111", "title": "...", "severity": "high",
    "cvss_score": "7.5", "cvss_vector": "CVSS:3.1/...", "references": ["https://..."]
  },
  "title": "TLS 1.0 habilitado", "severity": "medium", "cvss": 5.9,
  "description": "...", "evidence": "...", "recommendation": "Desabilitar TLS 1.0/1.1"
}
```

---

## Risk & Correlation (Correlation Engine)

### `GET /api/risk/overview/`
Risk assessment computado sob demanda a partir dos `Finding` persistidos — não é um recurso armazenado, então reflete sempre os dados mais recentes. Ver `docs/scanning-engine.md` (seção Correlation Engine) para a fórmula do `risk_score`. Filtro: `?limit=` (quantos ativos priorizados retornar; padrão `10`).
```json
// 200
{
  "summary": {
    "assets": 12,
    "findings": 47,
    "severity": { "critical": 5, "high": 18, "medium": 32, "low": 45, "info": 10 },
    "risk_score": 82.0,
    "risk_level": "high"
  },
  "top_assets": [
    {
      "asset": "<asset-id>",
      "ip": "192.168.0.10",
      "hostname": "web-01",
      "domain": null,
      "risk_score": 95.0,
      "risk_level": "critical",
      "findings": 6,
      "severity": { "critical": 1, "high": 3, "medium": 2, "low": 0, "info": 0 }
    }
  ],
  "heatmap": [
    { "category": "tls", "severity": "medium", "count": 3 },
    { "category": "software", "severity": "high", "count": 12 }
  ]
}
```
> `top_assets` vem ordenado por `risk_score` decrescente (priorização automática). `heatmap` é uma lista plana de células `{category, severity, count}` — o frontend faz o pivô para a grade.

---

## Reports

### `GET /api/reports/`
Lista relatórios gerados. Filtros: `?scan=`, `?report_type=` (`executive`\|`technical`), `?format=` (`pdf`\|`csv`\|`json`).

### `POST /api/reports/`
Gera um relatório para um scan. Requer papel `analyst` ou `admin`. O scan precisa estar `completed` (RN012); do contrário retorna `409`.
```json
// request
{ "scan": "<id>", "report_type": "executive", "format": "pdf" }
// 201
{
  "id": "...", "scan": "<id>", "scan_target": "empresa.com", "scan_type": "full",
  "scan_finished_at": "...", "report_type": "executive", "format": "pdf",
  "file_path": "reports/<uuid>.pdf", "file_size": 24576,
  "created_by": "...", "created_at": "..."
}
// 409 — scan ainda não concluído (RN012)
{ "detail": "Relatórios só podem ser gerados a partir de scans concluídos (RN012)." }
```
> `report_type=executive` produz resumo + risk score + top riscos priorizados + heatmap (payload/PDF); `report_type=technical` produz inventário de ativos + lista completa de findings com evidência/recomendação. O CSV é sempre uma linha por finding, independente do `report_type` (ver `docs/reporting.md`).

### `GET /api/reports/{id}/`
Detalhe do relatório.

### `DELETE /api/reports/{id}/`
Exclui o relatório e o artefato em disco. Restrito a `admin` (RN006).

### `GET /api/reports/{id}/download/`
Baixa o artefato do relatório (`Content-Type` conforme o formato). Acesso auditado (RN011).

---

## Knowledge Base

### `GET /api/knowledge-base/`
Lista artigos. Filtros: `?category=`, `?search=` (título/resumo/categoria).

### `POST /api/knowledge-base/`
Cria um artigo. Requer papel `analyst` ou `admin`.
```json
// request
{
  "slug": "weak-tls", "title": "Protocolos TLS obsoletos ou configuração fraca",
  "category": "tls", "summary": "...", "impact": "...",
  "remediation_steps": ["Desabilite TLS 1.0 e TLS 1.1...", "Exija TLS 1.2 como mínimo..."],
  "references": ["https://ssl-config.mozilla.org/"]
}
// 201 → mesmo shape + id/created_at/updated_at
// 400 — sem passo de remediação (RN013)
{ "remediation_steps": ["Informe ao menos um passo de remediação (RN013)."] }
```

### `GET /api/knowledge-base/{id}/`
Detalhe do artigo.

### `PATCH /api/knowledge-base/{id}/`
Atualiza o artigo. Requer papel `analyst` ou `admin`. **Diferente de Scan/Report/Finding, artigos não são histórico imutável** — podem ser editados conforme o entendimento evolui.

### `DELETE /api/knowledge-base/{id}/`
Exclui o artigo. Restrito a `admin` (RN006).

> Artigos são correlacionados a findings por `category` (não por FK) — ver `apps/knowledge/services.py:find_article_for_category`, com fallback para a categoria `general`. O relatório técnico (`GET /api/reports/`, `report_type=technical`) já inclui os artigos relacionados às categorias dos findings do scan em `knowledge_articles`.

---

## Audit Logs

### `GET /api/audit-logs/`
Trilha de auditoria imutável. **Somente `admin`** (RNF007 / RN011). Read-only. Filtros: `?action=`, `?severity=`, `?search=`.
```json
{
  "id": "...", "user": "...", "action": "scan.create", "severity": "info",
  "source": "192.168.0.5", "metadata": { "scan_id": "...", "target": "empresa.com" },
  "timestamp": "2026-08-12T12:00:00Z"
}
```

---

## AI Assistant (futuro)

### `POST /api/ai/explain/`
```json
{ "finding": "<id>" }
// 200
{ "summary": "...", "evidence": "...", "impact": "...", "recommendation": "...", "confidence": "high" }
```

Ver `docs/ai-assistant.md` para o formato completo e limitações.
