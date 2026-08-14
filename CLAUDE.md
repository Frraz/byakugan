# CLAUDE.md — Cérebro do Projeto Byakugan

> Este arquivo é a **fonte única da verdade** para qualquer pessoa (ou agente de IA) que desenvolva o Byakugan. Leia antes de escrever qualquer linha de código. Documentação em **PT-BR**; código, identificadores e mensagens de commit em **inglês**.

---

## 1. O que é o Byakugan

**Byakugan** é uma **plataforma ofensiva de Security Assessment / pentest profissional autorizado**: uma camada de orquestração que centraliza descoberta de ativos, fingerprinting, testes ativos de vulnerabilidade, correlação de risco, relatórios executivos/técnicos e um assistente de IA.

O objetivo é **descomplicar** o trabalho de equipes de pentest, Red Team, SOC, Blue Team, DevSecOps e analistas de segurança, reunindo em uma única interface a **cobertura máxima possível** de descoberta e detecção de vulnerabilidades — o que hoje exige dezenas de ferramentas separadas (nmap, Burp/ZAP, OpenVAS/Nessus, sqlmap, etc.) — sem depender de binários externos (motor 100% pure-Python).

> **Posicionamento**: o Byakugan **é** uma ferramenta ofensiva — executa testes ativos de vulnerabilidade (credenciais default, injeção, exposição de arquivos, etc.) **e explora as falhas detectadas para comprovar impacto real** (motor de exploração — ver `docs/exploitation-engine.md`). A exploração é **detecção-para-prova sob Regras de Engajamento (RoE) de não-dano**: o Byakugan vai até comprovar o impacto e mostrar *até onde a falha chega* (ex.: extrair versão/amostra do banco via SQLi, rodar `id` via command injection, alcançar metadata interna via SSRF), **mas nunca destrói ou altera dados, nunca causa DoS, nunca cria persistência/backdoor e nunca exfiltra dados em massa**. Só roda contra alvos com **autorização explícita, documentada e não-expirada**, com opt-in por scan, atrás de um kill-switch dedicado, e tudo auditado. Esse enquadramento — ofensivo e capaz de provar impacto, porém seguro e legal por design (é como um pentest real opera sob contrato) — é o que torna a ferramenta defensável perante a banca da FIAP e utilizável em um pentest real. Ver `docs/scanning-engine.md` (detecção) e `docs/exploitation-engine.md` (exploração + RoE) para os guardrails técnicos.

Projeto acadêmico do curso de **Segurança Cibernética da FIAP**.

### Origem do nome
Inspirado no dōjutsu Byakugan (Naruto): "enxergar tudo ao redor e revelar o que está oculto". A ferramenta faz o mesmo com uma infraestrutura — revela ativos e riscos ocultos.

---

## 2. ⚠️ Uso autorizado apenas (regra inegociável)

O Byakugan varre serviços e sistemas reais, incluindo testes ativos. **Só pode ser usado contra alvos para os quais exista autorização explícita e documentada** (ambiente próprio, laboratório, ou contrato de pentest/consultoria).

- Todo scan deve registrar quem autorizou e o escopo permitido (ver `docs/scanning-engine.md` → Política de Autorização de Alvos).
- **Kill-switch global** (`BYAKUGAN_SCANNING_ENABLED`, default `False`): sem ele ativo, nenhuma varredura real executa — o scan falha de forma controlada e auditada.
- **Kill-switch de exploração** (`BYAKUGAN_EXPLOITATION_ENABLED`, default `False`): kill-switch **dedicado e independente** do de varredura. A exploração ativa (prova de impacto) é a operação mais invasiva e só roda com este switch ligado **+** opt-in por scan (`options.exploit=True` + `intensity=aggressive`) ou gatilho manual, **+** escopo revalidado por finding. Ver `docs/exploitation-engine.md`.
- **Escopo fail-closed**: todo alvo — inclusive hosts expandidos de um CIDR ou lista — é revalidado contra o `authorization_scope` antes de qualquer probe **e antes de cada tentativa de exploração**. Nada fora do escopo é tocado, mesmo que faça parte do alvo original.
- **Expiração de autorização enforçada** (`authorization_expires_at`): reavaliada a cada tentativa de scan, não só no cadastro do alvo.
- **Detecção é não-destrutiva; exploração é detecção-para-prova sob RoE de não-dano**: a detecção usa requisições idempotentes (GET/OPTIONS/TRACE) e marcadores inertes. A exploração **executa o exploit para comprovar impacto real**, mas sob um piso inegociável, aplicado centralmente no seam de rede do motor (`apps/scans/exploit/base.py`): nunca destrói/altera dados, nunca causa DoS, nunca cria persistência, nunca exfiltra em massa (amostra limitada), nunca emite payload destrutivo (denylist de tokens), com orçamento de requisições por finding. `Evidence` (o que foi provado) é imutável (RN003).
- **Auditoria** de todo evento sensível (criação/cancelamento de scan, triagem de achados, exportação, exclusão, **e cada evento de exploração** — `exploit.attempted`/`proven`/`blocked`/`failed`).
- Nenhuma funcionalidade deve facilitar uso não autorizado, evasão de detecção para fins maliciosos, DoS, ou ataque a terceiros.
- Varredura sem autorização é crime. Isto vale para o desenvolvimento, testes e demonstrações.

---

## 3. Objetivos do sistema

O sistema deve:
1. Descobrir ativos de rede (hosts, sub-redes, DNS, subdomínios, transferência de zona).
2. Identificar tecnologias utilizadas (fingerprinting de OS, servidores, frameworks, TLS/certificado).
3. Avaliar exposição de serviços (portas, protocolos, headers, cookies, CORS, credenciais default).
4. Detectar vulnerabilidades conhecidas e ativas, de forma não-destrutiva (CVE/CVSS via CPE, injeção, exposição de arquivos).
5. Correlacionar riscos, deduplicar/triar achados entre execuções e priorizar correções.
6. Gerar relatórios executivos e técnicos.
7. Auxiliar na remediação (Knowledge Base + IA assistente).
8. Manter histórico imutável de análises para auditoria.

---

## 4. Princípios arquiteturais

- **Clean Architecture** — dependências apontam para o domínio.
- **Domain-Driven Design (DDD)** — entidades, agregados, bounded contexts (ver `docs/domain-model.md`).
- **SOLID**.
- **API-First** — o contrato da API (`docs/api.md`) é definido antes da implementação.
- **Security by Design** — segurança é requisito, não adendo (ver `docs/security.md`).
- **Observability First** — logs estruturados, auditoria e métricas desde o início.
- **Modular Monolith** inicialmente, **preparado para microservices** no futuro.

---

## 5. Stack oficial

### Frontend
- React + TypeScript
- Vite
- TailwindCSS + Shadcn/UI
- React Query (dados do servidor) + Zustand (estado de UI)

### Backend
- Python 3.13+
- Django + Django REST Framework
- Celery + Redis (processamento assíncrono de scans)

### Banco de dados / busca
- PostgreSQL
- OpenSearch (futuro — busca e agregação de findings)

### Infraestrutura
- Docker + Docker Compose

---

## 6. Convenções

### Backend (Python/Django)
- Seguir **PEP8**.
- **Type hints obrigatórios**.
- **Docstrings obrigatórias** em módulos, classes e funções públicas.
- Lógica de negócio em **services** (`apps/<app>/services.py`), nunca em views.
- **Views finas**: apenas orquestram request/response.
- **Serializers apenas para validação/serialização**, sem regra de negócio.
- Lint/format: `ruff` + `black`.

### Frontend (React/TS)
- Componentes reutilizáveis e pequenos.
- Hooks customizados para lógica; **separar UI de lógica**.
- **Nunca** colocar regra de negócio em componentes de UI.
- Chamadas de API isoladas em `src/lib/` / hooks.

### Segurança do próprio código
**Nunca:** armazenar senhas em texto puro · expor segredos em código · desabilitar autenticação · desabilitar logs de auditoria.
**Sempre:** usar RBAC · validar entradas · registrar auditoria · usar HTTPS em produção · ler segredos do `.env`.

---

## 7. Estrutura de pastas

```
byakugan/
├── CLAUDE.md            # este arquivo
├── README.md
├── .env.example
├── docker-compose.yml
├── docs/                # documentação canônica (fonte da verdade)
├── backend/             # Django + DRF + Celery
│   ├── config/          # projeto Django (settings, urls, celery)
│   └── apps/            # apps de domínio (core, accounts, assets, scans, ...)
├── frontend/            # React + TS + Vite
├── infra/               # configs de produção (nginx, CI/CD)
└── scripts/             # helpers de desenvolvimento
```

---

## 8. Padrões de commit

Formato: `tipo(escopo): descrição` em inglês, imperativo.

Tipos: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`.

Exemplos:
```
feat(asset-discovery): add host scanner adapter
fix(scans): prevent duplicate concurrent scan on same target
docs(api): document reports endpoints
```

---

## 9. Prioridade de desenvolvimento

1. Fundação (monorepo, Docker, health check) ← **fase atual**
2. Autenticação (JWT + RBAC) + auditoria
3. Asset Discovery
4. Fingerprinting
5. Vulnerability Assessment
6. Correlation Engine
7. Reporting
8. Dashboard
9. IA Assistente

Ver `docs/roadmap.md` para o detalhamento das fases.

---

## 10. Regra fundamental

**Toda funcionalidade deve possuir:**

- Requisito (`docs/requirements.md`)
- Regra de negócio (`docs/rules.md`)
- Endpoint documentado (`docs/api.md`)
- Testes (`docs/testing.md`)
- Documentação atualizada

Nenhuma feature é considerada "pronta" sem esses cinco itens.

---

## 11. Mapa da documentação

| Arquivo | Conteúdo |
| --- | --- |
| `docs/architecture.md` | Arquitetura, módulos e fluxo da aplicação |
| `docs/requirements.md` | Requisitos funcionais (RF) e não funcionais (RNF) |
| `docs/database.md` | Modelo de dados, tabelas e relacionamentos |
| `docs/api.md` | Endpoints, contratos e exemplos |
| `docs/rules.md` | Regras de negócio (RN) |
| `docs/tasks.md` | Backlog e progresso (MVP → V3) |
| `docs/ui.md` | Identidade visual e componentes |
| `docs/testing.md` | Estratégia de testes |
| `docs/roadmap.md` | Planejamento por fases até a 1.0 |
| `docs/security.md` | Arquitetura de segurança do próprio Byakugan |
| `docs/scanning-engine.md` | Motor de análise e scanner adapters (detecção) |
| `docs/exploitation-engine.md` | Motor de exploração (prova de impacto + RoE) e aba Evidências |
| `docs/ai-assistant.md` | Analista virtual de IA |
| `docs/modules.md` | Especificação de cada módulo |
| `docs/domain-model.md` | Entidades, agregados e bounded contexts (DDD) |
| `docs/reporting.md` | Modelos dos relatórios executivo e técnico |
| `docs/deployment.md` | Docker, ambientes e CI/CD |
