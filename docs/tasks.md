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
- [ ] Integração base CVE (NVD)
- [ ] Busca por versões vulneráveis
- [ ] Classificação CVSS
- [ ] Evidências técnicas

## V1
- [ ] Correlation Engine (risk score, priorização, heatmaps)
- [ ] Reporting (PDF executivo/técnico, CSV, JSON)
- [ ] Knowledge Base
- [ ] Dashboards executivo e técnico
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
