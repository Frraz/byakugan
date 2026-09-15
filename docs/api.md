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
Cadastra um alvo (papel `analyst` ou `admin`). **Deployment privado: só `name` + `value` são necessários.** O `value` é validado (RN001) e aceita **host, domínio (ex.: `byakugan.com.br`), IPv4, IPv6 e CIDR**; `kind` é derivado. A autorização é opcional (RN007): `authorized_by` é auto-preenchido com o e-mail do usuário autenticado e `authorization_scope`, quando omitido, assume o próprio `value`.
```json
// request (mínimo)
{ "name": "Site institucional", "value": "byakugan.com.br" }
// 201
{
  "id": "...", "name": "Site institucional", "value": "byakugan.com.br", "kind": "domain",
  "authorized_by": "warley@byakugan.test", "authorization_scope": "byakugan.com.br", "is_active": true
}

// request (opcional: escopo explícito + expiração)
{
  "name": "DMZ empresa X", "value": "192.168.10.0/24",
  "authorization_scope": "192.168.10.0/24", "authorization_expires_at": "2026-12-31T00:00:00Z"
}
// 201 → kind: "cidr"

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
Lista ativos. Filtros: `?status=`, `?search=` (ip/hostname/domain). Cada item inclui `findings_count`.
```json
// 200 (results[])
{ "id": "...", "ip": "192.168.0.10", "hostname": "web-01", "domain": "empresa.com", "os": "Ubuntu 24.04", "status": "active", "findings_count": 3 }
```

### `GET /api/assets/{id}/`
Detalhe do ativo, incluindo serviços e findings relacionados.

### `DELETE /api/assets/{id}/`
Exclui um ativo **em cascata** (RN020): remove os findings associados a ele. Serviços, tecnologias, registros DNS e triagens cascadeiam automaticamente. Restrito a `admin` (RN006); auditado com a contagem removida (`asset.delete`).
```json
// 204 No Content
```

### `GET /api/assets/{id}/services/`
Lista serviços do ativo.
```json
{ "id": "...", "port": 443, "protocol": "tcp", "service_name": "https", "product": "nginx", "version": "1.24.0" }
```

### `GET /api/assets/{id}/technologies/`
Lista as tecnologias identificadas no ativo pelo fingerprinting (*technology profile*).
```json
{
  "id": "...", "asset": "...", "category": "web-server", "name": "nginx",
  "version": "1.24.0", "source": "http-header", "evidence": "Server: nginx/1.24.0",
  "confidence": "high"
}
```
> `category`: `os` · `web-server` · `framework` · `language` · `frontend` · `cms` · `database` · `tls` · `other`. O detalhe do ativo (`GET /api/assets/{id}/`) já inclui `technologies` aninhadas.

### `GET /api/assets/{id}/dns-records/`
Lista registros DNS não-host descobertos do domínio do ativo (MX/NS/TXT/SOA/SRV — A/AAAA viram o próprio `Asset`).
```json
{ "id": "...", "asset": "...", "domain": "empresa.com", "record_type": "TXT", "value": "v=spf1 -all" }
```

---

## Scans

### `GET /api/scans/`
Lista scans. Filtros: `?status=`, `?scan_type=`, `?search=` (target). Cada item inclui contexto agregado para a UI: `target_name` (nome do Target cadastrado, se vinculado), `options` (perfil normalizado — ver `docs/scanning-engine.md`), `progress` (0–100), `phase` (adapter/host corrente, ex. `"tls @ 192.168.0.10"`), `findings_count`, `severity_counts` (`{"critical": n, "high": n, "medium": n, "low": n, "info": n}`) e `exploitable_findings_count` (nº de findings cuja `playbook_key` tem módulo de exploração automatizado — o que "Explorar" pode de fato provar; alimenta o aviso da UI quando um scan não tem findings exploráveis).

### `POST /api/scans/`
Cria e enfileira um scan. Requer papel `analyst` ou `admin`. Aceita **um `target_ref`** (id de um Target cadastrado — a autorização é herdada) **ou** o alvo inline, e opcionalmente `options` (perfil de intensidade — normalizado por `profiles.normalize_options`, campos ausentes assumem o padrão de `intensity`). No modo inline, `authorized_by`/`authorization_scope` são **opcionais** (deployment privado, RN007) — auto-preenchidos com o usuário autenticado e o próprio alvo. O alvo é validado contra o escopo antes de enfileirar (RN007), a autorização do `target_ref` não pode estar expirada (RN015), e a varredura só executa se `BYAKUGAN_SCANNING_ENABLED` estiver ativo.
```json
// request (via target cadastrado)
{ "target_ref": "<target-id>", "scan_type": "discovery" }

// request (inline, com opções — inclui opt-in de exploração)
{
  "target": "empresa.com",
  "scan_type": "full",
  "options": { "intensity": "aggressive", "exploit": true, "port_set": "top1000", "enabled_checks": ["dns", "tls", "cve-lookup"] }
}
// 201
{
  "id": "...", "status": "pending", "target": "empresa.com", "scan_type": "full",
  "options": { "intensity": "aggressive", "exploit": true, "port_set": "top1000", "wordlist_size": 1000, "max_hosts": 256, "max_pages": 100, "max_workers": 32, "rate_delay": 0.0, "enabled_checks": ["dns", "tls", "cve-lookup"] },
  "progress": 0, "phase": "", "findings_count": 0, "exploitable_findings_count": 0, "created_at": "..."
}
// 403 — alvo fora do escopo autorizado (RN007)
{ "detail": "Alvo fora do escopo autorizado." }
// 403 — autorização do target_ref expirada (RN015)
{ "detail": "Autorização do alvo expirou." }
// 409 — se já houver scan em execução para o mesmo alvo (RN002)
{ "detail": "Já existe um scan em execução para este alvo." }
```
> Campos de `options`: `intensity` (`safe`\|`normal`\|`aggressive`), `exploit` (bool — opt-in de exploração ativa; só honrado com `intensity=aggressive`, ver `docs/exploitation-engine.md`), `port_set` (`top16`\|`top100`\|`top1000`), `wordlist_size`, `max_hosts`, `max_pages`, `max_workers`, `rate_delay`, `enabled_checks` (lista de nomes de adapter; `null`/ausente = todos do `scan_type`). Ver `docs/scanning-engine.md` para os tetos absolutos e o efeito de cada perfil.

### `GET /api/scans/{id}/`
Detalhe e estado do scan (`pending|running|completed|failed|cancelled`), incluindo `progress`/`phase` atualizados durante a execução (poll este endpoint enquanto `pending`/`running`).

### `POST /api/scans/{id}/cancel/`
Cancela um scan em execução. Cooperativo: o worker interrompe entre lotes de probe (`ScanContext.check_cancelled()`), e a task Celery é revogada quando possível.

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
  "description": "...", "evidence": "...", "recommendation": "Desabilitar TLS 1.0/1.1",
  "dedup_key": "a3f5...", "triage_status": "open"
}
```
> `category`: uma das 18 categorias de `FindingCategory` (ver `docs/scanning-engine.md`). `dedup_key` identifica o achado lógico entre execuções de scan distintas; `triage_status` (`open`\|`fixed`\|`false-positive`\|`accepted-risk`) reflete a triagem mais recente para esse `dedup_key` (`open` se nunca triado). Os findings também podem ser filtrados por `?owasp_2021=`, `?owasp_2025=` e `?cwe=`.

### `GET /api/findings/grouped/`
**Vulnerabilidades consolidadas entre alvos** (RN025) — a tela principal de Vulnerabilidades. Agrupa os `Finding` pela assinatura cross-target `(category, título)` (distinta do `dedup_key`, que é por-ativo), para que a mesma falha em vários alvos apareça **uma única vez**. Filtros: `?severity=`, `?category=`, `?search=`, `?page=`. Paginado. Cada grupo traz a severidade/CVSS **máximas** entre as ocorrências, a contagem de alvos afetados distintos, o total de ocorrências, o mapeamento OWASP/CWE, um finding representativo (descrição + evidência de "como foi detectado") e a lista `affected` (onde foi encontrada, com o ativo, o scan e a triagem de cada ocorrência).
```json
// 200 (results[])
{
  "group_key": "SQL Injection", "category": "injection", "title": "SQL Injection",
  "severity": "critical", "cvss": 9.8,
  "targets": 3, "occurrences": 5, "open_count": 4, "triage_status": "open",
  "last_seen": "...", "finding_id": "<representativo>",
  "playbook_key": "injection.sqli-error", "owasp_2021": "A03", "owasp_2025": "A05", "cwe": "CWE-89",
  "cve": null, "description": "...", "evidence": "...", "recommendation": "...",
  "affected": [
    { "id": "<finding-id>", "severity": "critical", "cvss": 9.8, "triage_status": "open",
      "created_at": "...",
      "asset": { "id": "...", "hostname": "app-01", "ip": "10.0.0.5", "domain": "" },
      "scan": { "id": "...", "target": "app-01", "scan_type": "full", "created_at": "..." } }
  ]
}
```
> A triagem continua sendo **por ocorrência** (`dedup_key`, RN018): `POST /api/findings/{id}/triage/` com o `id` de uma ocorrência da lista `affected`.

### `POST /api/findings/{id}/triage/`
Classifica o achado lógico (por `dedup_key`, RN018) — afeta **todos** os `Finding` passados e futuros que compartilham o mesmo `dedup_key`, sem alterar o `Finding` em si (RN003). Requer papel `analyst` ou `admin`; auditado (`finding.triage`, RN011).
```json
// request
{ "status": "false-positive", "note": "Confirmado falso positivo em revisão manual." }
// 200
{
  "id": "...", "dedup_key": "a3f5...", "asset": "<asset-id>", "status": "false-positive",
  "note": "Confirmado falso positivo em revisão manual.", "updated_by": "<user-id>",
  "created_at": "...", "updated_at": "..."
}
```
> Idempotente: triar o mesmo `dedup_key` de novo **atualiza** a triagem existente em vez de duplicar. Achados triados como `fixed`/`false-positive`/`accepted-risk` são excluídos da soma do `risk_score` e do heatmap em `GET /api/risk/overview/` — ver `docs/scanning-engine.md` (seção Dedup & triagem).

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
    { "category": "tls", "category_label": "TLS", "severity": "medium", "count": 3 },
    { "category": "software", "category_label": "Software (CVE)", "severity": "high", "count": 12 }
  ]
}
```
> `top_assets` vem ordenado por `risk_score` decrescente (priorização automática). `heatmap` é uma lista plana de células `{category, category_label, severity, count}` — o frontend faz o pivô para a grade; `category_label` já vem em PT-BR pronto para exibição. Achados triados como resolvidos (`fixed`/`false-positive`/`accepted-risk` — RN018) são excluídos de `summary`, `top_assets` e `heatmap`.

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

## Exploitation & Evidences (motor de exploração)

Ver `docs/exploitation-engine.md` para a doutrina de RoE e o gating completo.

### `POST /api/scans/{id}/exploit/`
Dispara a fase de exploração (prova de impacto) sobre os findings de um scan **concluído**. Requer papel `analyst`/`admin` — é o opt-in explícito (dispensa `options.exploit`/aggressive), mas continua gated pelo kill-switch `BYAKUGAN_EXPLOITATION_ENABLED` (`503` se desligado) e pela revalidação de escopo por finding. Enfileira `scans.exploit_scan` (assíncrono) e nunca reescreve findings — só cria `Evidence` imutável.
```json
// 202 Accepted
{ "detail": "Exploração enfileirada.", "task_id": "..." }
// 503 se BYAKUGAN_EXPLOITATION_ENABLED=False
{ "detail": "Exploração ativa está desabilitada neste ambiente (BYAKUGAN_EXPLOITATION_ENABLED=False)." }
```

### `GET /api/evidence/`
Evidências de exploração automatizada (aba Evidências) — **read-only** (RN003, `Evidence` é imutável). Filtros: `?status=`, `?impact_level=`, `?scan=`, `?asset=`, `?finding=`, `?playbook_key=`.
```json
{
  "id": "...", "finding": { "id": "...", "title": "Possível SQL injection (baseada em erro)", "severity": "critical", "category": "injection", "playbook_key": "injection.sqli-error" },
  "scan": "...", "asset": { "id": "...", "hostname": "app.lab", "ip": "10.0.0.5", "domain": null },
  "playbook_key": "injection.sqli-error", "status": "proven", "impact_level": "db-read",
  "proof": "Versão do SGBD: 10.4.11-MariaDB\nTabelas acessíveis: users, sessions",
  "steps_performed": [ { "action": "Extrair versão do SGBD", "request": "id=' AND extractvalue(...)", "response_excerpt": "...", "result": "10.4.11-MariaDB" } ],
  "chain": [], "roe_profile": "extended", "created_at": "..."
}
```

### `GET /api/playbooks/` · `GET /api/playbooks/{key}/`
Guias curados de exploração por classe de vulnerabilidade (`key` = `Finding.playbook_key`, ex.: `injection.sqli-error`). Leitura para qualquer autenticado. Cada playbook traz `steps` (PoC manual), `escalation_path` ("até onde dá para ir"), `max_impact`, `tools`, `references`.

### `POST /api/playbooks/` · `PATCH /api/playbooks/{key}/` · `DELETE /api/playbooks/{key}/`
CRUD de playbooks (conteúdo vivo, como a Knowledge Base). Escrita: `analyst`/`admin`; exclusão: `admin` (RN006).

> **Findings** (`GET /api/findings/`) agora incluem `playbook_key` — o elo com o playbook e a evidência de exploração.

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

## Cobertura OWASP Top 10

Todo `Finding` retornado pela API inclui a classificação OWASP das duas edições e o CWE primário (RN024):

```json
{ "category": "injection", "playbook_key": "injection.sqli-error",
  "owasp_2021": "A03", "owasp_2025": "A05", "cwe": "CWE-89" }
```

Os findings podem ser filtrados por `?owasp_2021=A03`, `?owasp_2025=A05` ou `?cwe=CWE-89` (em `/api/findings/`).

**`GET /api/scans/{id}/owasp-coverage/`** — matriz de cobertura OWASP do scan (2021 + 2025). Leitura (analyst/viewer). Resposta:

```json
{
  "2021": [
    { "code": "A03", "label": "A03:2021 - Injection", "tested": true,
      "limited_coverage": false, "findings": 2, "highest_severity": "critical",
      "proven": true, "status": "proven" },
    { "code": "A04", "label": "A04:2021 - Insecure Design", "tested": false,
      "limited_coverage": true, "findings": 0, "highest_severity": null,
      "proven": false, "status": "limited" }
  ],
  "2025": [ ... 10 categorias ... ],
  "summary": {
    "2021": { "tested": 8, "found": 3, "proven": 1, "limited": 2, "total": 10 },
    "2025": { "tested": 7, "found": 3, "proven": 1, "limited": 3, "total": 10 }
  }
}
```

`status` de cada célula: `proven` > `found` > `tested` > `limited` > `not-tested`. Ver `docs/owasp-coverage.md`.
