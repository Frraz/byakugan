<div align="center">

# BYAKUGAN 👁️

**CYBERSECURITY PLATFORM**

_See Everything. Detect Everything._

Plataforma ofensiva de **pentest profissional autorizado** — descoberta de ativos, fingerprinting, testes ativos de vulnerabilidade não-destrutivos, correlação de risco e apoio à remediação, em uma única interface.

Projeto acadêmico do curso de **Segurança Cibernética da FIAP**.

</div>

---

## ⚠️ Aviso de uso autorizado

O Byakugan é uma ferramenta **ofensiva**: executa testes ativos (credenciais default, injeção, exposição de arquivos, transferência de zona, etc.) contra serviços e sistemas reais. **Use somente contra alvos que você possui ou está explicitamente autorizado a testar.** Varredura não autorizada é ilegal.

Este é um **protótipo de uso restrito** (nunca destinado ao público). Várias salvaguardas reforçam isso:

- **Autorização obrigatória por escopo (RN007):** todo scan valida o alvo — inclusive cada host expandido de um CIDR/lista — contra um `authorization_scope` registrado antes de executar; alvos fora do escopo são bloqueados e auditados.
- **Expiração de autorização enforçada (RN015):** um `Target` com `authorization_expires_at` vencido bloqueia novos scans, reavaliado a cada tentativa.
- **Kill-switch global (`BYAKUGAN_SCANNING_ENABLED`, padrão `False`):** com o switch desligado, scans são registrados mas **não** executam varredura real — falham de forma controlada e auditada. Ative-o apenas em um laboratório autorizado.
- **Testes ativos são sempre detecção, nunca exploração (RN016):** não-destrutivos, idempotentes, com marcadores inertes em vez de payloads vivos — nenhuma funcionalidade altera, apaga ou indisponibiliza dados/serviços do alvo.

Ver [`docs/scanning-engine.md`](docs/scanning-engine.md) e [`docs/security.md`](docs/security.md).

---

## Visão geral

Em vez de competir com nmap, Burp Suite, OWASP ZAP, OpenVAS/Nessus, sqlmap etc., o Byakugan é uma **camada de orquestração pure-Python** (sem binários externos) que integra e descomplica essas análises — cobrindo o máximo possível de superfície (rede, DNS, TLS, web, credenciais) — entregando resultados consolidados, priorizados por risco e acompanhados de recomendações de correção, voltado para equipes de pentest, Red Team, SOC, Blue Team e DevSecOps.

Arquitetura: **modular monolith** (Clean Architecture + DDD), API-first, processamento assíncrono de scans via Celery, histórico imutável para auditoria. Detalhes em [`docs/architecture.md`](docs/architecture.md).

## Status do roadmap

| Fase | Módulo | Status |
| --- | --- | --- |
| 0 | Fundação (Docker, Postgres, Redis, health, logging) | ✅ Concluída |
| 0 | Auth JWT + RBAC + Auditoria imutável + CI | ✅ Concluída |
| 1 | Asset Discovery (targets, hosts/portas/UDP, subdomínios, AXFR, e-mail, inventário) | ✅ Concluída |
| 2 | Fingerprinting (servidores, frameworks, CMS, TLS + certificado, technology profile) | ✅ Concluída |
| 3 | Vulnerability Assessment (CVE por CPE, credenciais default, testes ativos web) | ✅ Concluída |
| 4 | Correlation Engine (risk score, priorização, heatmaps, dedup/triagem) | ✅ Concluída |
| 5 | Reporting (PDF profissional / CSV / JSON) | ✅ Concluída |
| 6 | Knowledge Base | ✅ Concluída |
| — | Overhaul de UI/UX (design system shadcn/ui, CRUD de targets, exclusão de scans, relatórios profissionais) | ✅ Concluída |
| — | Motor ofensivo (11 scanner adapters, perfis de intensidade, progresso/cancelamento, dedup/triagem) | ✅ Concluída |
| 7 | AI Assistant | ⏳ Planejada |

Ver [`docs/roadmap.md`](docs/roadmap.md) e [`docs/tasks.md`](docs/tasks.md) para o detalhamento.

## Funcionalidades entregues

- **Autenticação JWT** — login, refresh, logout com blacklist, `me`; criação de usuários restrita a admin.
- **RBAC** — papéis `admin` / `analyst` / `viewer` aplicados por permission classes em cada endpoint.
- **Auditoria imutável** — todo evento sensível (login, criação/cancelamento de scan, triagem de achado, cadastro/exclusão de alvo) é registrado em uma trilha append-only, consultável por admins.
- **Cadastro de alvos (`Target`)** — autorização reutilizável, validação de formato (host/domínio/IP/CIDR), escopo e **expiração enforçada a cada scan** (RN015).
- **Motor de scan ofensivo (11 adapters, pure-Python)** — enfileiramento assíncrono, máquina de estados (`pending → running → completed/failed/cancelled`), progresso (`0–100%`) e fase corrente em tempo real, cancelamento cooperativo, **perfis de intensidade** (`safe`/`normal`/`aggressive` — portas, wordlist, checks habilitados). Cobre: descoberta de hosts/DNS, portas TCP (top16/100/1000) com banner grabbing, probes UDP, **enumeração de subdomínios** (wordlist + Certificate Transparency), **transferência de zona (AXFR)**, **segurança de e-mail** (SPF/DMARC/DKIM), fingerprint HTTP, **TLS e certificado completo** (protocolo/cipher fracos, expiração, self-signed, hostname mismatch, chave/assinatura fracas), **correlação de CVE por CPE** (NVD, fallback por palavra-chave), **credenciais default** (FTP/Redis/Elasticsearch/painéis HTTP, só `aggressive`) e **testes ativos web** (headers de segurança, cookies, CORS, exposição de arquivos sensíveis, métodos HTTP perigosos, detecção de injeção XSS/SQLi/traversal/SSTI/cmdi/open redirect) — todos **não-destrutivos por design** (RN016).
- **Inventário de ativos** — hosts, serviços, registros DNS e tecnologias descobertos (*technology profile*: SO, servidor web, framework, linguagem, CMS, frontend, TLS), com histórico imutável.
- **Vulnerability Assessment** — catálogo de vulnerabilidades (CVE, CVSS, referências) e findings por ativo/scan em **15 categorias**, com evidência e recomendação (RN008, enforçado no modelo); pipeline em duas fases por host garante que os adapters de vulnerabilidade sempre leiam o profile mais recente do próprio scan.
- **Correlation Engine** — risk score (0–100) e priorização automática de ativos, agrupamento por criticidade e heatmap por categoria, computados sob demanda a partir dos findings (sem cache a invalidar — sempre atualizado). **Dedup & triagem**: achados marcados como corrigido/falso-positivo/risco aceito são excluídos do score, evitando que reexecuções do mesmo scan o inflem artificialmente.
- **Reporting** — relatórios executivo (risco + top riscos + heatmap) e técnico (inventário + findings completos) em PDF profissional (`reportlab`: capa com identidade, gráficos de severidade/categoria, numeração de páginas, sumário narrativo e seção de referências CVE/NVD), CSV e JSON, gerados só a partir de scans concluídos (RN012); download autenticado e auditado (RN011); histórico imutável (RN003).
- **Knowledge Base** — artigos por categoria (descrição, impacto, passo a passo de remediação, referências), correlacionados a findings por `category` sem FK, com fallback genérico; seed inicial com 6 artigos reais; único conteúdo do domínio editável (CRUD completo, não é histórico imutável); integrado ao relatório técnico.
- **Gestão de alvos e scans** — alvos podem ser **editados e excluídos** (a exclusão preserva o histórico de scans, que apenas perdem o vínculo); scans concluídos podem ser **excluídos em cascata por admin** (removendo findings e relatórios associados, incluindo os arquivos — RN014), com bloqueio para scans em execução (409) e trilha de auditoria.
- **Frontend completo** — construído sobre **shadcn/ui** na identidade visual oficial (ver abaixo): login, dashboard SOC (KPIs, donut de severidade, heatmap, ativos priorizados), CRUD de targets, scans (formulário com perfil de intensidade/portas/checks, detalhe com timeline/progresso/serviços/findings), explorer de Vulnerabilidades com painel de detalhe do finding (evidência, CVE→NVD, remediação da Knowledge Base, **controles de triagem**), assets, Reports (geração + **pré-visualização in-app** + download) e Knowledge Base — tudo com busca, filtros, paginação, confirmações destrutivas, toasts e navegação responsiva.

## Identidade visual

A identidade da marca está em [`docs/ui.md`](docs/ui.md) e nos assets `Byakugan logo.png` / `Byakugan identidade visual.png` (raiz). Estética **dark-first**, glassmorphism e neon glow, no espírito de plataformas de cyber intelligence.

| Uso | Cor | Hex |
| --- | --- | --- |
| Fundo (Cyber Navy) | ▉ | `#0B1220` |
| Primária (Electric Blue) | ▉ | `#00D4FF` |
| Acento (Byakugan Lavender) | ▉ | `#C8B6FF` |
| Sucesso / Atenção / Crítico | ▉ ▉ ▉ | `#22C55E` / `#F59E0B` / `#EF4444` |

A UI é construída sobre **shadcn/ui** (primitivos Radix) com tokens de cor em CSS variables HSL (tema claro em `:root`, Cyber Navy em `.dark` — o padrão); ícones **lucide-react**, toasts **sonner** e gráficos **recharts**. Detalhes do design system em [`docs/ui.md`](docs/ui.md). O logo é renderizado a partir da arte raster em [`frontend/src/components/brand/Logo.tsx`](frontend/src/components/brand/Logo.tsx).

## Stack

| Camada | Tecnologias |
| --- | --- |
| Frontend | React, TypeScript, Vite, TailwindCSS, shadcn/ui (Radix), lucide-react, sonner, recharts, React Query, Zustand, React Router |
| Backend | Python 3.13+, Django, Django REST Framework, SimpleJWT, django-filter |
| Assíncrono | Celery, Redis |
| Scanners | socket (TCP/UDP), dnspython (DNS/subdomínios/AXFR), requests (HTTP fingerprint + NVD + web active testing), ssl + cryptography (TLS/certificado), ftplib (credenciais default) |
| Relatórios | reportlab (PDF) |
| Banco / busca | PostgreSQL, OpenSearch (futuro) |
| Infra | Docker, Docker Compose |

---

## Como executar (desenvolvimento)

### Pré-requisitos
- Docker + Docker Compose

### Subir tudo com Docker (recomendado)

```bash
# 1. Copie e ajuste as variáveis de ambiente
cp .env.example .env

# 2. Suba todos os serviços
docker compose up --build
```

Serviços expostos:
- Backend (Django/DRF): http://localhost:8000
- Health check: http://localhost:8000/api/health/
- Frontend (Vite): http://localhost:5173

> As portas `5432` (Postgres) e `6379` (Redis) são publicadas no host. Se já estiverem em uso na sua máquina, ajuste os mapeamentos em [`docker-compose.yml`](docker-compose.yml).

### Primeiro acesso

```bash
# Crie um usuário admin para logar no frontend
docker compose run --rm backend python manage.py createsuperuser
```

Depois acesse http://localhost:5173 e faça login. Para executar varreduras reais em laboratório, defina `BYAKUGAN_SCANNING_ENABLED=True` no `.env` (leia o aviso de uso autorizado).

### Comandos úteis

```bash
# Migrações
docker compose run --rm backend python manage.py migrate

# Testes do backend (com cobertura)
docker compose run --rm backend pytest --cov=apps --cov-report=term-missing

# Lint / format do backend
docker compose run --rm backend ruff check apps config
docker compose run --rm backend black --check apps config

# Frontend: build (typecheck + vite) e testes
docker compose run --rm frontend npm run build
docker compose run --rm frontend npm test
```

### Execução local (sem Docker)

**Backend:**
```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
python manage.py migrate
python manage.py runserver
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

### Produção / deploy no servidor

O deploy segue as convenções do servidor Ferzion (nginx do host como único dono das portas 80/443; app em porta loopback; sem interferir nos demais sistemas). Use [`docker-compose.prod.yml`](docker-compose.prod.yml) e siga o passo a passo em [`DEPLOY.md`](DEPLOY.md).

---

## API (resumo)

Base: `/api`. Autenticação: **Bearer JWT** (exceto health e login). Contrato completo em [`docs/api.md`](docs/api.md).

| Método | Endpoint | Descrição | Acesso |
| --- | --- | --- | --- |
| GET | `/api/health/` | Health check | Público |
| POST | `/api/auth/login/` | Login (retorna access/refresh + user) | Público |
| POST | `/api/auth/refresh/` | Renova o access token | Público |
| POST | `/api/auth/logout/` | Invalida o refresh (blacklist) | Autenticado |
| GET | `/api/auth/me/` | Usuário atual | Autenticado |
| POST | `/api/auth/register/` | Cria usuário | admin |
| GET/POST | `/api/targets/` | Lista / cadastra alvos autorizados | criar: analyst, admin |
| PATCH | `/api/targets/{id}/` | Edita um alvo (recalcula o tipo; auditado) | analyst, admin |
| DELETE | `/api/targets/{id}/` | Exclui um alvo (scans preservados sem vínculo) | admin |
| GET/POST | `/api/scans/` | Lista / cria scans | criar: analyst, admin |
| POST | `/api/scans/{id}/cancel/` | Cancela um scan | analyst, admin |
| DELETE | `/api/scans/{id}/` | Exclui scan em cascata (findings + relatórios; 409 se ativo — RN014) | admin |
| GET | `/api/scans/{id}/findings/` | Findings do scan | Autenticado |
| GET | `/api/scans/{id}/services/` | Serviços descobertos pelo scan | Autenticado |
| GET | `/api/assets/` | Inventário de ativos | Autenticado |
| GET | `/api/assets/{id}/services/` | Serviços de um ativo | Autenticado |
| GET | `/api/assets/{id}/technologies/` | Tecnologias identificadas (technology profile) | Autenticado |
| GET | `/api/assets/{id}/dns-records/` | Registros DNS não-host descobertos (MX/NS/TXT/SOA/SRV) | Autenticado |
| GET | `/api/vulnerabilities/` | Catálogo de vulnerabilidades (CVE/CVSS) | Autenticado |
| GET | `/api/findings/` | Findings do ambiente (filtros: severity/asset/scan/category) | Autenticado |
| POST | `/api/findings/{id}/triage/` | Triar um achado lógico (aberto/corrigido/falso-positivo/risco aceito) | analyst, admin |
| GET | `/api/risk/overview/` | Risk score, ativos priorizados e heatmap (Correlation Engine) | Autenticado |
| GET/POST | `/api/reports/` | Lista / gera relatórios (executivo/técnico, PDF/CSV/JSON) | criar: analyst, admin |
| GET | `/api/reports/{id}/download/` | Baixa o artefato do relatório | Autenticado |
| DELETE | `/api/reports/{id}/` | Exclui relatório | admin |
| GET/POST | `/api/knowledge-base/` | Lista / cria artigos (descrição/impacto/remediação) | criar: analyst, admin |
| PATCH | `/api/knowledge-base/{id}/` | Atualiza artigo (único conteúdo editável do domínio) | analyst, admin |
| DELETE | `/api/knowledge-base/{id}/` | Exclui artigo | admin |
| GET | `/api/audit-logs/` | Trilha de auditoria | admin |

---

## Testes & CI

- **Backend:** pytest + pytest-django + factory-boy (Postgres efêmero). Regras de negócio testadas por ID de RN. **464 testes, cobertura ~89,70%** (gate 80%). Todo adapter mantém a lógica de decisão em módulos puros testáveis sem rede real, com um seam de rede fino monkeypatchável.
- **Frontend:** Vitest + Testing Library (jsdom); `tsc -b` como checagem de tipos.
- **CI:** GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) roda lint (ruff/black), testes com cobertura (gate ≥ 80%), build do frontend e SCA (`pip-audit` / `npm audit`). Ativa após `git init` + push.

Ver [`docs/testing.md`](docs/testing.md).

---

## Estrutura do repositório

```
backend/           # Django + DRF + Celery
  apps/core/       # BaseModel, AuditLog, permissions, health, logging
  apps/accounts/   # User (email + RBAC), auth JWT
  apps/assets/     # Asset, Service, Technology, DnsRecord (inventário + technology profile)
  apps/scans/      # Target, Scan, Vulnerability, Finding, FindingTriage; 11 adapters (discovery/fingerprint/vulnerability);
                   # módulos puros: signatures, banners, cve, tls_analysis, dns_analysis, correlation (risk score + triagem),
                   # profiles (perfis de intensidade), targets (expansão de alvo), web/ (crawler/passive/exposure/methods/injection),
                   # data/ (ports/udp_probes/subdomains/web_paths/default_creds); services, tasks
  apps/reports/    # Report, payload (executivo/técnico + narrativa/referências), rendering (dispatcher), pdf (PDF profissional), services
  apps/knowledge/  # KnowledgeArticle, services (correlação por categoria), seed de conteúdo
frontend/          # React + TS + Vite; design system shadcn/ui em src/components/ui/
  src/components/  # ui/ (primitivos + kit Byakugan), targets/, scans/, findings/, reports/, charts/, brand/, layout/
  src/pages/       # login, dashboard, targets, scans, assets, vulnerabilities, reports, knowledge
  src/hooks/       # useData (React Query), usePermissions, useDebounce, useChartColors…
  src/lib/         # api (fetch + JWT refresh), format, errors, utils, types
docs/              # documentação canônica (comece por docs/architecture.md)
infra/             # configs de produção
scripts/           # helpers de desenvolvimento
```

## Documentação

A documentação completa está em [`docs/`](docs/) e o guia de desenvolvimento (convenções, princípios, regras) em [`CLAUDE.md`](CLAUDE.md). Comece por [`docs/architecture.md`](docs/architecture.md) e [`docs/roadmap.md`](docs/roadmap.md).

## Licença

MIT.
