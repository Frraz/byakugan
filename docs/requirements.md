# Requisitos

## Requisitos Funcionais (RF)

| ID | Requisito | Descrição | Fase |
| --- | --- | --- | --- |
| RF001 | Login | Autenticação de usuário com emissão de tokens JWT | Fundação |
| RF002 | Cadastro de usuários | Criação de contas (por admin) | Fundação |
| RF003 | RBAC | Controle de acesso por papéis (Administrator, Security Analyst, Viewer) | Fundação |
| RF004 | Criar scan | Registrar um scan com alvo(s); a autorização (`authorized_by` + escopo) é registrada — opcional na entrada em deployment privado, auto-preenchida e sempre validada contra o escopo (RN007) | Asset Discovery |
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
| RF030 | Classificação OWASP Top 10 | Classificar todo finding no OWASP Top 10 2021 **e** 2025 + CWE primário (RN024), consultável/filtrável na API | Cobertura OWASP |
| RF031 | Detecção de Broken Access Control (A01) | Forced browsing a endpoints administrativos sem autenticação e IDOR heurístico em ids numéricos (não-destrutivo, GET) | Cobertura OWASP |
| RF032 | Detecção de Auth Failures (A07) | Enumeração de usuário via mensagem de erro (idempotente) além das credenciais default; login sobre HTTP | Cobertura OWASP |
| RF033 | Detecção de Integrity Failures (A08) | Subresource Integrity (SRI) ausente em recursos de terceiros e bibliotecas JS de front-end desatualizadas/vulneráveis | Cobertura OWASP |
| RF034 | Matriz de cobertura OWASP | `GET /scans/{id}/owasp-coverage/` e seção nos relatórios: por categoria (2021/2025), testado × encontrado × provado, com "cobertura limitada" onde não detectável | Cobertura OWASP |
| RF035 | Vulnerabilidades consolidadas | Agrupar a mesma vulnerabilidade lógica entre alvos numa única linha (`GET /findings/grouped/`, RN025), com contagem de alvos afetados e um detalhe que separa como foi detectada, como explorá-la e onde foi encontrada | UX/Consolidação |
| RF036 | Cobertura expandida de detecção | CSRF (formulário POST sem token), JWT fraco (`alg: none`, segredo HS256 comum, `exp` ausente), Host Header Injection, NoSQL injection booleana, exposição de source map e introspecção GraphQL exposta — todos não-destrutivos (RN016); CSRF/JWT sem nenhuma requisição extra ao alvo | Cobertura OWASP |
| RF037 | Cobertura expandida de detecção (2) | LDAP injection booleana (wildcard/fechamento de filtro), CRLF Injection/HTTP Response Splitting (header de resposta sintético) e referência a cloud storage de terceiros (S3/GCS/Azure, **sem jamais requisitar o bucket** — fora do `authorization_scope` do alvo) | Cobertura OWASP |
| RF038 | Cobertura expandida de detecção (3) | Qualidade da Content-Security-Policy (unsafe-inline/unsafe-eval/wildcard de origem/object-src/frame-ancestors — sem requisição extra, mesmo header já obtido) e exposição de documentação de API (Swagger/OpenAPI) | Cobertura OWASP |
| RF039 | Fingerprint de WAF/CDN | Identificar WAF/CDN comuns (Cloudflare, Akamai, CloudFront, Sucuri, Incapsula, F5 ASM, FortiWeb, Barracuda, ModSecurity, Wordfence, Azure Front Door, Fastly) por header/cookie/corpo já obtidos no fingerprint HTTP — contextualiza possíveis falsos negativos de injeção, sem requisição extra | Motor Ofensivo |
| RF040 | Exploração de exposição de source map/GraphQL | Rebaixar o source map já identificado e extrair os caminhos-fonte originais; reenviar introspecção GraphQL mais ampla e extrair nomes de tipo reais — ambos amostra ≤ `max_sample_rows`, mesmo GET idempotente da detecção | Motor de Exploração |
| RF041 | Exploração de JWT fraco | Forjar um JWT (`alg: none`/segredo HS256 fraco), elevando claims de privilégio já existentes no payload, e reenviar a página onde o token foi visto (coordenada capturada pela detecção) para provar bypass de autenticação por mudança observável de comportamento | Motor de Exploração |
| RF042 | Detecção de desserialização insegura | Reconhecer marcadores de objeto Java serializado (cookie `rememberMe` do Apache Shiro ou assinatura genérica), PHP Object Injection e ASP.NET ViewState sem criptografia explícita — puramente passivo, zero requisições extras (reaproveita corpo/cookies já obtidos pelo crawl) | Motor Ofensivo |
| RF043 | Redução de falso positivo em detecção | Comparar sinais mundanos (SSTI/cmdi/sqli-error/SSRF) contra o baseline sem payload antes de reportar; reconfirmar toda detecção booleana (SQLi/NoSQLi/LDAP) com um segundo par verdadeiro/falso independente antes de criar o finding (RN026) | Motor Ofensivo |
| RF044 | Regra de detecção por classe de vulnerabilidade (purple team) | `ExploitationPlaybook.detection_rule`: regra Sigma (YAML) pronta para o time de defesa detectar, nos logs, o ataque que o Byakugan comprovou — seedada para 20 classes com assinatura de log confiável; vazia (nunca forçada) quando não há uma | Motor de Exploração |
| RF045 | Cadeias de risco entre findings (purple team) | `GET /api/risk/overview/` retorna `chains`: combinações de classes que, no mesmo ativo, formam um risco mais grave que a soma das partes (ex.: XSS + CSP fraca, credenciais default + sem rate limit); catálogo pequeno e conservador, nunca especulativo | Correlation Engine |
| RF046 | Classificação MITRE ATT&CK por finding | `Finding.mitre_technique`: técnica ATT&CK primária (ex.: `T1190`), terceira dimensão de classificação junto de OWASP 2021/2025 + CWE (RN027); 27 das 42 classes mapeadas (honestidade — nunca uma correspondência especulativa); filtrável via `?mitre_technique=`, exposto em `/findings/`, `/findings/grouped/` e no detalhe do finding/vulnerabilidade na UI | Cobertura OWASP |
| RF047 | Narrativa de Ataque no relatório técnico | `build_attack_narrative`: por ativo, os passos de exploração **comprovados** (`Evidence.proven`) em sequência, cada um com a técnica MITRE ATT&CK e as cadeias de risco aplicáveis; ausente (nunca especulativa) quando o scan não tem exploração comprovada; seção dedicada no PDF técnico | Reporting |

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
| RNF010 | Autorização de alvos | Todo scan carrega registro de autorização e é validado contra o escopo (fail-closed); em deployment privado o registro é auto-preenchido, nunca ausente |

## Rastreabilidade

Cada RF deve estar ligado a: regra de negócio (`rules.md`), endpoint (`api.md`), testes (`testing.md`) e item de backlog (`tasks.md`).
