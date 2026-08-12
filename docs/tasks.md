# Backlog & Progresso

> Legenda: `[x]` concluído · `[~]` em andamento · `[ ]` pendente. Ver `docs/roadmap.md` para o detalhamento por fase.

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
- [x] Cadastro de alvos + autorização (modelo `Target`, validação RN001, enforcement de escopo RN007)
- [x] Kill-switch global de varredura (`BYAKUGAN_SCANNING_ENABLED`)
- [x] Descoberta de hosts (DnsAdapter — dnspython)
- [x] Descoberta de serviços (PortDiscoveryAdapter — socket TCP)
- [x] Inventário de ativos (API de assets + frontend)
- [x] Histórico de descobertas (imutável — RN003)

### Fingerprinting
- [x] Servidores web (`HttpFingerprintAdapter` — header `Server`)
- [x] Frameworks / linguagens / CMS / tecnologias frontend (assinaturas HTTP + HTML — `signatures.py`)
- [x] TLS (`TlsAdapter` — versão/cipher negociado via stdlib `ssl`)
- [x] Modelo `Technology` + API (`/assets/{id}/technologies/`) + frontend (detalhe do ativo)
- [~] Sistema operacional (dica via header `Server`; fingerprint de OS por rede fica para evolução futura)

### Vulnerability Assessment
- [x] Integração base CVE (NVD CVE 2.0 — `CveLookupAdapter`, `apps/scans/cve.py`)
- [x] Busca por versões vulneráveis (keywordSearch produto+versão sobre `Service`/`Technology`)
- [x] Classificação CVSS (v3.1 > v3.0 > v2) e severidade (RN004)
- [x] Evidências técnicas (produto/versão/porta/fonte) + recomendação por finding (RN008)
- [x] API global (`/vulnerabilities/`, `/findings/`) + frontend (VulnerabilitiesPage, findings no detalhe do ativo)

## V1
- [x] Correlation Engine (risk score 0–100, priorização automática por ativo, agrupamento por criticidade, heatmap por categoria — `apps/scans/correlation.py` + `GET /api/risk/overview/`, computado sob demanda)
- [x] Reporting (PDF via `reportlab` / CSV / JSON, executivo e técnico, app `apps/reports`, RN012 — só a partir de scan `completed`; download autenticado e auditado)
- [ ] Knowledge Base
- [~] Dashboards executivo e técnico (Dashboard SOC com KPIs de risco, ativos priorizados e heatmap entregue; relatório executivo em PDF cobre a visão de gestão — dashboard executivo dedicado no frontend fica para evolução futura)
- [ ] AI Assistant (explicação, correção, resumo)
- [ ] Cobertura de testes > 80%

## V2
- [ ] OpenSearch (busca/agregação de findings)
- [ ] IA com contexto completo (chat)
- [ ] Correlação avançada
- [ ] Multi-tenant

## V3
- [ ] Integração SIEM
- [ ] Integração SOAR
- [ ] Agendamento automático de scans
