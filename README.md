<div align="center">

# BYAKUGAN 👁️

**CYBERSECURITY PLATFORM**

_See Everything. Detect Everything._

Plataforma defensiva de **Security Assessment** — descoberta de ativos, análise de exposição, gestão de vulnerabilidades, correlação de risco e apoio à remediação, em uma única interface.

Projeto acadêmico do curso de **Segurança Cibernética da FIAP**.

</div>

---

## ⚠️ Aviso de uso autorizado

O Byakugan realiza varreduras contra serviços e sistemas reais. **Use somente contra alvos que você possui ou está explicitamente autorizado a testar.** Varredura não autorizada é ilegal.

Este é um **protótipo de uso restrito** (nunca destinado ao público). Duas salvaguardas reforçam isso:

- **Autorização obrigatória por escopo (RN007):** todo scan valida o alvo contra um `authorization_scope` registrado antes de executar; alvos fora do escopo são bloqueados e auditados.
- **Kill-switch global (`BYAKUGAN_SCANNING_ENABLED`, padrão `False`):** com o switch desligado, scans são registrados mas **não** executam varredura real — falham de forma controlada e auditada. Ative-o apenas em um laboratório autorizado.

Ver [`docs/scanning-engine.md`](docs/scanning-engine.md) e [`docs/security.md`](docs/security.md).

---

## Visão geral

Em vez de competir com nmap, Burp Suite, OWASP ZAP, OpenVAS/Nessus, etc., o Byakugan é uma **camada de orquestração** que integra e descomplica essas análises, entregando resultados consolidados, priorizados por risco e acompanhados de recomendações de correção — voltado para equipes SOC, Blue Team e DevSecOps.

Arquitetura: **modular monolith** (Clean Architecture + DDD), API-first, processamento assíncrono de scans via Celery, histórico imutável para auditoria. Detalhes em [`docs/architecture.md`](docs/architecture.md).

## Status do roadmap

| Fase | Módulo | Status |
| --- | --- | --- |
| 0 | Fundação (Docker, Postgres, Redis, health, logging) | ✅ Concluída |
| 0 | Auth JWT + RBAC + Auditoria imutável + CI | ✅ Concluída |
| 1 | Asset Discovery (targets, descoberta de hosts/serviços, inventário) | ✅ Concluída |
| 2 | Fingerprinting (OS, servidores, frameworks) | ⏳ Planejada |
| 3 | Vulnerability Assessment (CVE/NVD, CVSS, findings) | ⏳ Planejada |
| 4 | Correlation Engine (risk score, priorização, heatmaps) | ⏳ Planejada |
| 5 | Reporting (PDF/CSV/JSON) | ⏳ Planejada |
| 6 | Knowledge Base | ⏳ Planejada |
| 7 | AI Assistant | ⏳ Planejada |

Ver [`docs/roadmap.md`](docs/roadmap.md) e [`docs/tasks.md`](docs/tasks.md) para o detalhamento.

## Funcionalidades entregues (Fases 0–1)

- **Autenticação JWT** — login, refresh, logout com blacklist, `me`; criação de usuários restrita a admin.
- **RBAC** — papéis `admin` / `analyst` / `viewer` aplicados por permission classes em cada endpoint.
- **Auditoria imutável** — todo evento sensível (login, criação/cancelamento de scan, cadastro/exclusão de alvo) é registrado em uma trilha append-only, consultável por admins.
- **Cadastro de alvos (`Target`)** — autorização reutilizável, validação de formato (host/domínio/IP/CIDR) e escopo.
- **Scans de descoberta** — enfileiramento assíncrono, máquina de estados (`pending → running → completed/failed/cancelled`), cancelamento e polling de status; adapters reais de **descoberta de portas** (socket TCP) e **DNS** (dnspython).
- **Inventário de ativos** — hosts e serviços descobertos, com histórico imutável.
- **Frontend completo** — login, dashboard SOC, targets, scans, assets e telas de detalhe, na identidade visual oficial (ver abaixo).

## Identidade visual

A identidade da marca está em [`docs/ui.md`](docs/ui.md) e nos assets `Byakugan logo.png` / `Byakugan identidade visual.png` (raiz). Estética **dark-first**, glassmorphism e neon glow, no espírito de plataformas de cyber intelligence.

| Uso | Cor | Hex |
| --- | --- | --- |
| Fundo (Cyber Navy) | ▉ | `#0B1220` |
| Primária (Electric Blue) | ▉ | `#00D4FF` |
| Acento (Byakugan Lavender) | ▉ | `#C8B6FF` |
| Sucesso / Atenção / Crítico | ▉ ▉ ▉ | `#22C55E` / `#F59E0B` / `#EF4444` |

O logo é renderizado em SVG vetorial ([`frontend/src/components/brand/Logo.tsx`](frontend/src/components/brand/Logo.tsx)).

## Stack

| Camada | Tecnologias |
| --- | --- |
| Frontend | React, TypeScript, Vite, TailwindCSS, React Query, Zustand, React Router |
| Backend | Python 3.13+, Django, Django REST Framework, SimpleJWT, django-filter |
| Assíncrono | Celery, Redis |
| Scanners | socket (TCP connect), dnspython |
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
| GET/POST | `/api/targets/` | Lista / cadastra alvos autorizados | analyst, admin |
| GET/POST | `/api/scans/` | Lista / cria scans | criar: analyst, admin |
| POST | `/api/scans/{id}/cancel/` | Cancela um scan | analyst, admin |
| GET | `/api/scans/{id}/findings/` | Findings do scan | Autenticado |
| GET | `/api/assets/` | Inventário de ativos | Autenticado |
| GET | `/api/assets/{id}/services/` | Serviços de um ativo | Autenticado |
| GET | `/api/audit-logs/` | Trilha de auditoria | admin |

---

## Testes & CI

- **Backend:** pytest + pytest-django + factory-boy (Postgres efêmero). Regras de negócio testadas por ID de RN.
- **Frontend:** Vitest + Testing Library (jsdom).
- **CI:** GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) roda lint (ruff/black), testes com cobertura (gate ≥ 80%), build do frontend e SCA (`pip-audit` / `npm audit`). Ativa após `git init` + push.

Ver [`docs/testing.md`](docs/testing.md).

---

## Estrutura do repositório

```
backend/           # Django + DRF + Celery
  apps/core/       # BaseModel, AuditLog, permissions, health, logging
  apps/accounts/   # User (email + RBAC), auth JWT
  apps/assets/     # Asset, Service (inventário)
  apps/scans/      # Target, Scan, Finding, adapters, services, tasks
frontend/          # React + TS + Vite (auth, layout, páginas, brand)
docs/              # documentação canônica (comece por docs/architecture.md)
infra/             # configs de produção
scripts/           # helpers de desenvolvimento
```

## Documentação

A documentação completa está em [`docs/`](docs/) e o guia de desenvolvimento (convenções, princípios, regras) em [`CLAUDE.md`](CLAUDE.md). Comece por [`docs/architecture.md`](docs/architecture.md) e [`docs/roadmap.md`](docs/roadmap.md).

## Licença

MIT.
