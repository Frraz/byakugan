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
| RF016 | Perfis de intensidade | Configurar profundidade do scan (`safe`/`normal`/`aggressive`), conjunto de portas, tamanho de wordlist e checks habilitados por execução | Motor Ofensivo |
| RF017 | Progresso do scan | Acompanhar `progress` (0–100) e `phase` (adapter/host atual) de um scan em execução; cancelamento cooperativo | Motor Ofensivo |
| RF018 | Varredura de serviços de rede | Banner grabbing (TCP) e probes UDP leves (DNS/NTP/SNMP/NetBIOS/mDNS) para até 1000 portas, com produto/versão quando identificável | Motor Ofensivo |
| RF019 | Teste de credenciais default | Testar credenciais padrão/sem autenticação em serviços descobertos (FTP anônimo, Redis, Elasticsearch, painéis HTTP), restrito à intensidade `aggressive` | Motor Ofensivo |
| RF020 | Análise de TLS/certificado | Detectar protocolos/ciphers obsoletos e problemas de certificado (expirado, self-signed, hostname mismatch, chave/assinatura fracas) | Motor Ofensivo |
| RF021 | Enumeração de subdomínios | Descobrir subdomínios via wordlist e Certificate Transparency (crt.sh), com revalidação de escopo por candidato | Motor Ofensivo |
| RF022 | Transferência de zona (AXFR) | Testar e reportar transferência de zona DNS mal configurada | Motor Ofensivo |
| RF023 | Segurança de e-mail | Analisar SPF/DMARC/DKIM do domínio | Motor Ofensivo |
| RF024 | Testes ativos em aplicação web | Crawling same-origin e detecção não-destrutiva de headers de segurança ausentes, cookies inseguros, CORS mal configurado, exposição de arquivos sensíveis, métodos HTTP perigosos (TRACE) e injeção (XSS/SQLi/traversal/SSTI/cmdi/open redirect) | Motor Ofensivo |
| RF025 | Correlação CVE por CPE | Buscar CVEs na NVD por `virtualMatchString` (CPE 2.3), com fallback para busca por palavra-chave | Motor Ofensivo |
| RF026 | Triagem de achados | Classificar um achado lógico como aberto/corrigido/falso-positivo/risco aceito, excluindo-o do risk score enquanto resolvido | Motor Ofensivo |
| RF027 | Exploração para prova de impacto | Executar o exploit sobre findings detectados para comprovar impacto real (ex.: extrair versão/tabelas do banco via SQLi, `id` via command injection, ler arquivos via LFI, alcançar metadata interna via SSRF), sob RoE de não-dano (RN021) | Motor de Exploração |
| RF028 | Aba Evidências | Exibir, por vulnerabilidade, a prova de exploração automatizada (`Evidence`: passos executados + artefato extraído) e o guia curado de exploração (`ExploitationPlaybook`: PoC manual + cadeia de escalação "até onde dá para ir" + ferramentas + referências) | Motor de Exploração |
| RF029 | Gatilho e gating de exploração | Disparar a exploração inline (opt-in por scan) ou manualmente sobre um scan concluído, atrás do kill-switch dedicado e da revalidação de escopo por finding (RN022), com cada evento auditado | Motor de Exploração |

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
