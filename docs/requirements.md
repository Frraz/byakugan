# Requisitos

## Requisitos Funcionais (RF)

| ID | Requisito | Descrição | Fase |
| --- | --- | --- | --- |
| RF001 | Login | Autenticação de usuário com emissão de tokens JWT | Fundação |
| RF002 | Cadastro de usuários | Criação de contas (por admin) | Fundação |
| RF003 | RBAC | Controle de acesso por papéis (Administrator, Security Analyst, Viewer) | Fundação |
| RF004 | Criar scan | Registrar um scan com alvo(s) e confirmação de autorização | Asset Discovery |
| RF005 | Executar scan | Enfileirar e processar o scan de forma assíncrona | Asset Discovery |
| RF006 | Consultar scans | Listar/detalhar scans e seus estados | Asset Discovery |
| RF007 | Consultar ativos | Listar hosts, portas, protocolos e serviços descobertos | Asset Discovery |
| RF008 | Consultar vulnerabilidades | Listar findings por ativo, com severidade e CVSS | Vuln. Assessment |
| RF009 | Gerar relatório | Produzir relatório executivo/técnico de um scan | Reporting |
| RF010 | Exportar relatório | Exportar em PDF/CSV/JSON | Reporting |
| RF011 | Histórico de análises | Manter e consultar scans passados (imutáveis) | Asset Discovery |
| RF012 | Dashboard executivo | Visão de risco consolidada para gestão | Dashboard |
| RF013 | Dashboard técnico | Visão detalhada para analistas | Dashboard |
| RF014 | Base de conhecimento | Consultar descrição/impacto/correção de vulnerabilidades | Knowledge Base |
| RF015 | Recomendações de correção | Sugerir remediação (Knowledge Base + IA) | AI Assistant |

## Requisitos Não Funcionais (RNF)

| ID | Requisito | Meta |
| --- | --- | --- |
| RNF001 | API REST | Contrato documentado, versionável (`/api/...`) |
| RNF002 | Containerização | Todo o sistema sobe via Docker Compose |
| RNF003 | Persistência | PostgreSQL como banco principal |
| RNF004 | Performance | Tempo de resposta da API < 500ms (p95) para operações não-scan |
| RNF005 | Testes | Cobertura de testes > 80% |
| RNF006 | Observabilidade | Logs estruturados em JSON |
| RNF007 | Auditoria | Trilha de auditoria completa e imutável de eventos sensíveis |
| RNF008 | Segurança de transporte | HTTPS obrigatório em produção (TLS 1.2+) |
| RNF009 | Escalabilidade | Workers escaláveis horizontalmente; meta de até 100 ativos simultâneos |
| RNF010 | Autorização de alvos | Nenhum scan executa sem registro de autorização |

## Rastreabilidade

Cada RF deve estar ligado a: regra de negócio (`rules.md`), endpoint (`api.md`), testes (`testing.md`) e item de backlog (`tasks.md`).
