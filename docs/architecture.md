# Arquitetura

## Visão geral

O Byakugan é um **modular monolith** com processamento assíncrono. O frontend consome uma API REST; a API delega trabalho pesado (scans) a workers Celery, que persistem resultados e alimentam o motor de correlação de risco.

```
Frontend (React)
      │  HTTP/REST (JSON)
      ▼
API (Django + DRF)
      │  regras em Services
      ▼
Fila (Redis / Celery)
      │
      ▼
Workers (Scanner Adapters)
      │
      ▼
PostgreSQL  ──►  Correlation Engine  ──►  Dashboards / Reports
```

## Camadas (Clean Architecture)

1. **Apresentação** — Views/Serializers do DRF e componentes React. Finas, sem regra de negócio.
2. **Aplicação** — Services orquestram casos de uso (`apps/<app>/services.py`).
3. **Domínio** — Entidades e regras (modelos + value objects). Ver `docs/domain-model.md`.
4. **Infraestrutura** — ORM, Celery, adapters de scan, integrações externas (NVD/CVE, IA).

Dependências sempre apontam para dentro (domínio não conhece Django/DRF diretamente na regra de negócio).

## Módulos

### Authentication & Accounts
JWT (access/refresh) + RBAC (Administrator, Security Analyst, Viewer). Ver `docs/security.md`.

### Asset Discovery
Descoberta de hosts, DNS, subdomínios e serviços. Gera o inventário de ativos.

### Fingerprinting
Identificação de OS, servidores web, frameworks e tecnologias → Technology Profile.

### Vulnerability Assessment
Correlação de software/versão com base CVE e cálculo/importação de CVSS → Findings.

### Correlation Engine
Agrupa vulnerabilidades, elimina duplicidades, calcula risk score e prioriza → Risk Assessment.

### Reporting
Geração de relatórios executivo e técnico (PDF/CSV/JSON) com rastreabilidade ao scan de origem.

### Knowledge Base
Descrição, impacto, referências e passos de correção por vulnerabilidade.

### AI Assistant
Explica findings, sugere correções e resume em linguagem executiva. Nunca executa ações.

### Audit & Observability
Logs estruturados (JSON) e trilha de auditoria imutável de todos os eventos sensíveis.

## Fluxo principal (criação de scan)

1. Usuário cria um scan informando alvo(s) e confirma a autorização.
2. API valida (formato, duplicidade, permissões) e persiste o scan como `PENDING`.
3. Scan é enfileirado no Celery; muda para `RUNNING`.
4. Workers executam os módulos (Discovery → Fingerprint → Vulnerability) via **scanner adapters**.
5. Parsers normalizam a saída; resultados são persistidos (assets, services, findings).
6. Correlation Engine processa os findings e calcula o risco.
7. Scan vira `COMPLETED`; dashboards e relatórios refletem os novos dados.

Ver `docs/scanning-engine.md` para os estados e o detalhamento do motor.

## Decisões arquiteturais

- **Modular monolith primeiro**: menor complexidade operacional para um MVP acadêmico; apps bem isolados permitem extrair microservices depois.
- **Async por padrão** para scans: evita bloquear a API e permite escala horizontal de workers.
- **API-First**: o contrato (`docs/api.md`) precede a implementação.
- **Histórico imutável**: resultados de scan nunca são sobrescritos (auditoria).
