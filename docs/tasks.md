# Backlog & Progresso

> Legenda: `[x]` concluído · `[~]` em andamento · `[ ]` pendente. Ver `docs/roadmap.md` para o detalhamento por fase.

> **Pivô para motor ofensivo (pós-V1)**: após o V1 defensivo estar completo, o motor de scan foi expandido para uma plataforma de **pentest ofensivo autorizado** — cobertura máxima de vulnerabilidades (11 adapters, **18 categorias de finding**), depois um **motor de exploração** (prova de impacto sob RoE) e a **cobertura OWASP Top 10 (2021 + 2025)**, mantendo os guardrails (dois kill-switches, escopo fail-closed, autorização com expiração enforçada, detecção não-destrutiva). As seções abaixo refletem o estado expandido. Ver `docs/scanning-engine.md`, `docs/exploitation-engine.md` e `docs/owasp-coverage.md`.

## Fase 0 — Fundação
- [x] Documentação canônica (`CLAUDE.md`, `docs/`)
- [x] Estrutura de monorepo
- [x] Docker Compose (postgres, redis, backend, celery, frontend)
- [x] Backend Django + DRF (esqueleto)
- [x] Endpoint de health check (`GET /api/health/`)
- [x] Frontend React + Vite + Tailwind (tela mínima consumindo o health)
- [x] `BaseModel` (UUID + timestamps) e logging estruturado
- [x] Modelos-esqueleto (accounts, assets, scans) alinhados ao `database.md`
- [x] Interface `ScannerAdapter`
- [x] Configuração de deploy do servidor Ferzion (`docker-compose.prod.yml`, gunicorn/whitenoise, nginx template, `DEPLOY.md`)
- [x] Autenticação JWT (login/refresh/logout+blacklist/register/me)
- [x] RBAC (admin/analyst/viewer) — permission classes aplicadas
- [x] Auditoria básica (modelo `AuditLog` imutável + serviço + endpoint admin)
- [x] CI/CD inicial (GitHub Actions: lint, testes, cobertura, SCA)

## MVP (Fases 1–3)
### Asset Discovery
- [x] Cadastro de alvos + autorização (modelo `Target`, validação RN001, enforcement de escopo RN007, **expiração enforçada — RN015**)
- [x] Kill-switch global de varredura (`BYAKUGAN_SCANNING_ENABLED`)
- [x] Descoberta de hosts (DnsAdapter — dnspython)
- [x] Descoberta de serviços — portas TCP top16/top100/top1000 (`PortDiscoveryAdapter`) com banner grabbing → produto/versão (`banners.py`) + probes UDP leves (`UdpProbeAdapter` — DNS/NTP/SNMP/NetBIOS/mDNS)
- [x] Enumeração de subdomínios (`SubdomainAdapter` — wordlist + Certificate Transparency/crt.sh, revalidação de escopo por candidato) e transferência de zona (`ZoneTransferAdapter` — AXFR)
- [x] Segurança de e-mail (`EmailSecurityAdapter` — SPF/DMARC/DKIM)
- [x] Expansão de alvo (CIDR/lista → hosts individuais, fail-closed por host — RN017) + perfis de intensidade (`safe`/`normal`/`aggressive` — `profiles.py`)
- [x] Inventário de ativos (API de assets + frontend) + registros DNS não-host (`assets.DnsRecord`)
- [x] Histórico de descobertas (imutável — RN003)

### Fingerprinting
- [x] Servidores web (`HttpFingerprintAdapter` — header `Server`)
- [x] Frameworks / linguagens / CMS / tecnologias frontend (assinaturas HTTP + HTML — `signatures.py`)
- [x] TLS (`TlsAdapter` — versões suportadas + cipher negociado via stdlib `ssl`) e análise completa de certificado (`cryptography` — expiração, self-signed, hostname mismatch, chave/assinatura fracas, `tls_analysis.py`)
- [x] Modelo `Technology` + API (`/assets/{id}/technologies/`) + frontend (detalhe do ativo)
- [~] Sistema operacional (dica via header `Server`; fingerprint de OS por rede fica para evolução futura)

### Vulnerability Assessment
- [x] Integração base CVE (NVD CVE 2.0 — `CveLookupAdapter`, `apps/scans/cve.py`)
- [x] Correlação por CPE (`virtualMatchString`, formato CPE 2.3) com fallback para `keywordSearch` produto+versão
- [x] Classificação CVSS (v3.1 > v3.0 > v2) e severidade (RN004)
- [x] Evidências técnicas (produto/versão/porta/fonte) + recomendação por finding (RN008, **agora enforçado no modelo — RN019**)
- [x] Teste de credenciais default (`DefaultCredsAdapter` — FTP anônimo, Redis, Elasticsearch, painéis HTTP; só `intensity=aggressive` — RN016)
- [x] Testes ativos em aplicação web (`WebScanAdapter` — headers de segurança, cookies, CORS, exposição de paths sensíveis com baseline diffing, métodos HTTP perigosos, injeção XSS/SQLi/traversal/SSTI/cmdi/open redirect — sempre detecção não-destrutiva, RN016)
- [x] API global (`/vulnerabilities/`, `/findings/`) + frontend (VulnerabilitiesPage, findings no detalhe do ativo)

## V1
- [x] Correlation Engine (risk score 0–100, priorização automática por ativo, agrupamento por criticidade, heatmap por categoria com `category_label` — `apps/scans/correlation.py` + `GET /api/risk/overview/`, computado sob demanda)
- [x] Dedup & triagem de findings (`Finding.dedup_key`, modelo `FindingTriage`, `POST /api/findings/{id}/triage/`, exclusão do risk score para achados resolvidos — RN018)
- [x] Reporting (PDF profissional via `reportlab` — capa, gráficos, numeração, narrativa, referências; CSV / JSON; executivo e técnico, app `apps/reports`, RN012 — só a partir de scan `completed`; download autenticado e auditado; preview in-app)
- [x] Knowledge Base (artigos por categoria — descrição/impacto/referências/remediação, RN013; app `apps/knowledge`; CRUD via `/api/knowledge-base/`; correlação por `Finding.category` sem FK, fallback `general`; seed com 6 artigos reais; integrado ao relatório técnico via `knowledge_articles`)
- [x] UI/UX profissional (design system shadcn/ui sobre a identidade Byakugan; CRUD completo de targets, exclusão em cascata de scans — RN014; explorer de vulnerabilidades com detalhe de finding e controles de triagem; perfis de scan (intensidade/portas/wordlist/checks) e progresso em tempo real no formulário/detalhe/lista de scans; paginação, filtros, toasts, confirmações destrutivas, navegação mobile, gráficos recharts)
- [~] Dashboards executivo e técnico (Dashboard SOC com KPIs de risco, donut de severidade, heatmap e ativos priorizados entregue; relatório executivo em PDF cobre a visão de gestão — dashboard executivo dedicado no frontend fica para evolução futura)
- [ ] AI Assistant (explicação, correção, resumo)
- [x] Cobertura de testes > 80% (backend: 464 testes, ~89,70%)

## Motor de Exploração (pós-V1)
- [x] Contrato `ExploitModule` + registro por `playbook_key` (`exploit/registry.py`) espelhando o modelo de adapters
- [x] Piso de não-dano central no seam de rede (`exploit/base.py` — allowlist de método, denylist de payload checada após decodificar, orçamento por finding — RN021)
- [x] Orquestração com gating fail-closed (`exploit/runner.py` — kill-switch `BYAKUGAN_EXPLOITATION_ENABLED` + opt-in/aggressive ou manual + escopo por finding — RN022)
- [x] Entidades `Evidence` (imutável — RN023), `ExploitationPlaybook` (vivo, 25 playbooks semeados), `ImpactLevel`
- [x] Módulos: SQLi (erro/booleana), command injection, LFI, SSRF, SSTI, XSS, open redirect, forced browsing, IDOR, enumeração de usuário
- [x] Endpoints (`POST /scans/{id}/exploit/`, `GET /evidence/`, `GET/POST /playbooks/`) + gatilho inline no `run_scan`
- [x] Testes puros de RoE e de extração por módulo (fetch falso, sem rede/banco)

## Cobertura expandida de detecção (pós-V1, Fase C)
- [x] CSRF (`web/csrf.py` — puramente estático sobre formulários POST já rastreados, sem token anti-CSRF)
- [x] JWT fraco (`web/auth_checks.py` — `alg: none`, segredo HS256 comum via HMAC local, `exp` ausente; sem requisição extra)
- [x] Host Header Injection (`web/injection.py` — GET com header Host trocado, detecta reflexão em Location/corpo)
- [x] NoSQL injection booleana (`web/injection.py` — operadores MongoDB `$ne`/`$eq` como chave de query string)
- [x] Exposição de source map (`web/exposure.py` + `web/crawler.py` coleta `<script src>`)
- [x] Introspecção GraphQL exposta (`web/graphql_checks.py` — GET idempotente, candidatos comuns)
- [x] 6 novos playbooks curados (migration `0011_seed_expanded_coverage_playbooks.py`) + classificação OWASP/CWE (`owasp.py`)
- [x] 34 novos testes puros/adapter (CSRF, JWT, Host Header, NoSQLi, source map, GraphQL, extração de `<script>` no crawler)
- [x] LDAP injection booleana, CRLF Injection/HTTP Response Splitting e referência a cloud storage (S3/GCS/Azure — puramente passivo, nunca requisita o bucket de terceiros) — Fase C2
- [x] 2º playbook seed (migration `0012_seed_phase_c2_playbooks.py`) + mais 18 testes puros/adapter
- [x] Qualidade de CSP (unsafe-inline/unsafe-eval/wildcard de origem/object-src/frame-ancestors — zero requisições extras) e exposição de documentação de API (Swagger/OpenAPI) — Fase C3
- [x] 3º playbook seed (migration `0013_seed_phase_c3_playbooks.py`) + mais 13 testes puros/adapter
- [x] Fingerprint de WAF/CDN (Cloudflare, Akamai, CloudFront, Sucuri, Incapsula, F5 ASM, FortiWeb, Barracuda, ModSecurity, Wordfence, Azure Front Door, Fastly — `signatures.py`, sem requisição extra); novas categorias `Technology.Category.WAF`/`CDN` (migration `apps/assets/0004`) — contextualiza falsos negativos de injeção
- [x] Correção de drift no frontend: `FindingCategory` (types.ts + category-badge.tsx) não tinha `access-control`/`auth`/`integrity` (categorias da Fase B nunca propagadas) — teste trava a exaustividade contra o enum do backend
- [x] 2 novos módulos de exploração (`exploit/source_map.py`, `exploit/graphql.py`) — rebaixam o artefato já identificado e extraem uma amostra real do que foi exposto (caminhos-fonte / nomes de tipo), registrados em `exploit/registry.py`; decisão documentada (`docs/exploitation-engine.md`) de por que CSRF/NoSQLi/LDAP/cloud-storage/api-docs/CSP ficam só com playbook manual por ora
- [x] 3º módulo de exploração (`exploit/jwt_weak.py`) — resolvido o bloqueio original de "não sabe contra qual endpoint reenviar": detecção agora guarda a página onde o token foi visto (`source_url`), permitindo forjar (`alg: none`/segredo fraco, claims elevadas) e reenviar para provar auth-bypass por mudança observável de comportamento
- [x] Marcadores de desserialização insegura (`web/deserialization.py`, Fase C7) — objeto Java serializado (cookie `rememberMe` do Apache Shiro + assinatura genérica), PHP Object Injection e ASP.NET ViewState sem criptografia explícita; puramente passivo (zero requisições extras); playbooks curados até RCE via ysoserial/ysoserial.net/PHPGGC (migration `0014`)
- [x] Auditoria de falso positivo (Fase C8, RN026) — corrigido SSTI que não comparava contra baseline (`49` mundano na página gerava falso positivo); mesma guarda estendida a cmdi/sqli-error/SSRF; reconfirmação obrigatória para toda detecção booleana (SQLi/NoSQLi/LDAP) antes de reportar, mesma disciplina do sqlmap
- [x] Regras de detecção Sigma — purple team (Fase C9) — `ExploitationPlaybook.detection_rule`, seedado para 20 classes (migration `0016`); validado por teste real (YAML + schema Sigma + IDs únicos, `test_detection_rules.py`); exposto na API e renderizado na aba Evidências com botão de copiar; primeiro passo concreto rumo à "Integração SIEM" do V3 (gera o CONTEÚDO da regra; falta o PUSH automático a um SIEM)
- [x] Cadeias de risco entre findings — purple team (Fase C10) — `correlation.compute_chains`/`FINDING_CHAINS`, 5 combinações conservadoras (XSS+CSP fraca, credenciais default+sem rate limit, JWT fraco+forced browsing, IDOR+sem rate limit, SQLi+credenciais em texto claro); exposto em `GET /api/risk/overview/` (`chains`) e no Dashboard (painel dedicado, só aparece quando há alguma)
- [x] Classificação MITRE ATT&CK — terceira dimensão (Fase C11, RN027) — `Finding.mitre_technique`, fonte única `apps/scans/mitre.py`, mesmo padrão arquitetural do OWASP (RN024); 27 de 42 classes mapeadas (honestidade — nunca especulativo); migrations `0017`/`0018` (schema + backfill); filtro `?mitre_technique=`; exibido no detalhe do finding e da vulnerabilidade agrupada (badge `MonoBadge` extraído para componente compartilhado)
- [x] Narrativa de Ataque no relatório técnico (Fase C12) — `build_attack_narrative`: por ativo, passos **comprovados** (`Evidence.proven`, nunca especulação) ordenados por impacto, com técnica MITRE ATT&CK + cadeias de risco aplicáveis; seção dedicada no PDF (`_attack_narrative_section`), ausente quando não há exploração comprovada

## Cobertura OWASP Top 10 (pós-V1)
- [x] Taxonomia fonte única `apps/scans/owasp.py` (2021 + 2025 + CWE) e `resolve_owasp`
- [x] Campos `owasp_2021`/`owasp_2025`/`cwe` no `Finding` (migration 0007 + backfill) — RN024; enriquecimento central em `persist_findings`
- [x] Novos detectores: A01 (`web/access_control.py` — forced browsing + IDOR), A07 (`web/auth_checks.py` — enumeração de usuário), A08 (`web/integrity.py` — SRI + JS desatualizado), reforços A02/A05 em `web/passive.py`
- [x] 3 novas categorias de finding (`access-control`, `auth`, `integrity`) + 10 playbooks OWASP (migration 0008)
- [x] Matriz de cobertura (`owasp_coverage.py` + `GET /scans/{id}/owasp-coverage/`) e seção OWASP nos relatórios (payload + PDF)
- [x] Filtros OWASP/CWE na API de findings; testes de taxonomia, detectores, matriz, endpoint e relatório

## Overhaul de UX/UI (deployment privado)
- [x] Autorização opcional: "Autorizado por" removido da UI; `authorized_by`/`authorization_scope` `blank` + auto-preenchidos (migration `0010`) — RN007 mantida (fail-closed)
- [x] RBAC do frontend relaxado (qualquer autenticado escreve) — corrige botões primários que "sumiam"; backend inalterado
- [x] Novo alvo enxuto (nome + valor; aceita domínio/IPv4/IPv6/CIDR) com ícone (i) explicando o escopo
- [x] Novo scan profissional (cards de tipo/intensidade, toggle de exploração, ajustes finos, resumo)
- [x] Vulnerabilidades consolidadas entre alvos (`GET /findings/grouped/` — RN025) + `VulnerabilityGroupSheet` (como detectada / como explorar / onde encontrada)
- [x] Aba Evidências mostra todos os status (proven/attempted/blocked/failed) com filtro; feedback do "Explorar" via `Scan.exploitable_findings_count`
- [x] Abas Assets e Knowledge Base removidas da navegação (dados mantidos inline/drill-down)

### Backlog de UI/UX (evolução futura)
- [~] Acabamento e QA do redesign (Fase 6 do plano / referência “Fase E” nos tokens) — ver [ponto de retomada](redesign-status.md)
- [x] Aba Evidências no frontend (prova de exploração + playbook curado por finding)
- [x] Painel/visualização da matriz de cobertura OWASP (2021 × 2025) no detalhe do scan (`OwaspCoverageMatrix`)
- [ ] Formulários com react-hook-form + zod (validação client-side rica)
- [ ] Busca global (cmd-k) na topbar
- [ ] Geração de relatórios assíncrona (Celery) para scans com muitos findings
- [x] Tela de Audit Logs (`AuditLogPage`, rota `/audit-log`)
- [ ] Telas de perfil (`/me`) e gestão de usuários

## V2
- [ ] OpenSearch (busca/agregação de findings)
- [ ] IA com contexto completo (chat)
- [ ] Correlação avançada
- [ ] Multi-tenant

## V3
- [ ] Integração SIEM
- [ ] Integração SOAR
- [ ] Agendamento automático de scans
