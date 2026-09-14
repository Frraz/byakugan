# Roadmap

## Visão

O Byakugan é desenvolvido incrementalmente: parte de um MVP funcional de descoberta de ativos e evolui para uma **plataforma ofensiva de pentest profissional autorizado** — cobertura máxima de vulnerabilidades, testes ativos não-destrutivos e **exploração para prova de impacto** sob RoE, com correlação de riscos e apoio à remediação.

> **Norte:** ser um sistema ofensivo autorizado que ajuda profissionais e empresas de cibersegurança a **encontrar** cada brecha que um atacante mal-intencionado poderia explorar, **documentar** cada uma com evidência/prova de impacto, e **orientar a remediação** — evoluindo continuamente rumo à cobertura mais completa possível da superfície de ataque, sempre sob autorização e RoE de não-dano. A cobertura total é aspiração de longo prazo (norte), não garantia. Ver a seção **Visão de longo prazo** no fim deste documento.

> **Pivô de posicionamento**: as Fases 1–4 abaixo (Asset Discovery, Fingerprinting, Vulnerability Assessment, Correlation Engine) descreviam originalmente um motor defensivo minimalista (5 adapters, CVE por palavra-chave). Após a V1 estar completa, o motor foi expandido para 11 adapters cobrindo rede/serviços, TLS/certificado, DNS/subdomínios/AXFR/e-mail e testes ativos web, mantendo a stack pure-Python e reforçando os guardrails legais (kill-switch, escopo fail-closed, expiração de autorização enforçada, testes ativos só de detecção não-destrutiva). As descrições abaixo já refletem o estado expandido; ver `docs/scanning-engine.md` para o detalhamento técnico.

---

## Fase 0 — Fundação ✅ (concluída)
**Objetivo:** infraestrutura base rodável de ponta a ponta.
- Estrutura de monorepo · Docker Compose · PostgreSQL · Redis
- Backend Django + DRF · Frontend React · Health check ponta a ponta · logging estruturado
- Autenticação JWT (login/refresh/logout+blacklist/register/me) · RBAC (admin/analyst/viewer)
- Auditoria imutável (`AuditLog`) · CI/CD inicial (GitHub Actions: lint, testes, cobertura, SCA)

## Fase 1 — Asset Discovery ✅ (concluída — MVP + expandida pós-V1)
**Objetivo:** identificar ativos no ambiente.
- Cadastro de alvos com autorização (`Target`, validação RN001, enforcement de escopo RN007, **expiração enforçada — RN015**)
- Kill-switch global (`BYAKUGAN_SCANNING_ENABLED`)
- Descoberta de hosts (DNS) e serviços — portas TCP (top16/100/1000) com banner grabbing e probes UDP leves — via adapters reais
- **Expansão pós-V1**: enumeração de subdomínios (wordlist + Certificate Transparency), transferência de zona (AXFR), segurança de e-mail (SPF/DMARC/DKIM), expansão fail-closed de CIDR/lista (RN017), perfis de intensidade (`safe`/`normal`/`aggressive`)
- Inventário (incl. registros DNS não-host) · histórico imutável
- Frontend: login, dashboard, targets, scans (com polling/cancelamento/progresso), assets e detalhes
- **Resultado entregue:** o usuário visualiza hosts, portas, protocolos, serviços, subdomínios e postura de e-mail ponta a ponta.

## Fase 2 — Fingerprinting ✅ (concluída — MVP + expandida pós-V1)
**Objetivo:** identificar tecnologias.
- OS · servidores web · frameworks · linguagens · CMS · tecnologias frontend · TLS
- Adapters reais: `HttpFingerprintAdapter` (headers + assinaturas HTML) e `TlsAdapter` (versões suportadas + cipher TLS via stdlib)
- **Expansão pós-V1**: análise completa de certificado via `cryptography` (expiração, self-signed, hostname mismatch, chave/assinatura fracas) — gera findings, não apenas o technology profile
- Modelo `Technology` (technology profile por ativo) · API `/assets/{id}/technologies/` · frontend no detalhe do ativo
- **Resultado entregue:** mapa tecnológico do ambiente por ativo, com evidência, nível de confiança e postura de TLS/certificado.

## Fase 3 — Vulnerability Assessment ✅ (concluída — MVP + expandida pós-V1)
**Objetivo:** relacionar ativos a vulnerabilidades conhecidas e detectar exposições ativamente.
- Adapter real `CveLookupAdapter`: correlaciona o technology profile (Fase 2) com a API NVD CVE 2.0, priorizando busca por CPE (`virtualMatchString`) com fallback por palavra-chave
- Classificação CVSS (v3.1 > v3.0 > v2) e severidade (RN004) · catálogo `Vulnerability` reaproveitado entre scans · `Finding` imutável por scan (RN003/RN005, RN008 enforçado no modelo — RN019)
- **Expansão pós-V1**: teste de credenciais default (`DefaultCredsAdapter`, só `aggressive`) e testes ativos em aplicação web (`WebScanAdapter` — headers de segurança, cookies, CORS, exposição de arquivos sensíveis, métodos HTTP perigosos, detecção de injeção XSS/SQLi/traversal/SSTI/cmdi/open redirect) — sempre detecção não-destrutiva (RN016)
- API global `/vulnerabilities/` (catálogo) e `/findings/` (ocorrências, filtráveis por severidade/ativo/scan/categoria) · frontend com página de Vulnerabilities e seção de findings no detalhe do ativo
- **Resultado entregue:** lista de vulnerabilidades e exposições por ativo, com CVE, CVSS, evidência e recomendação, cobrindo rede, web e credenciais.

## Fase 4 — Correlation Engine ✅ (concluída — V1 + expandida pós-V1)
**Objetivo:** transformar vulnerabilidades em risco de negócio.
- Risk score (0–100, soma de CVSS saturada) · priorização automática de ativos · agrupamento por criticidade · heatmap por categoria (18 categorias, com rótulo PT-BR)
- Computado sob demanda a partir dos `Finding` (sem modelo próprio, sempre atualizado) · API `GET /api/risk/overview/` · Dashboard com KPIs de risco, ativos priorizados e heatmap
- **Expansão pós-V1**: dedup/triagem de achados (`Finding.dedup_key` + modelo `FindingTriage`, `POST /api/findings/{id}/triage/`) — achados marcados como corrigidos/falso-positivo/risco aceito são excluídos da soma do risk score, evitando que reexecuções do mesmo scan o inflem artificialmente (RN018)
- **Resultado entregue:** o usuário vê, de relance, quais ativos são mais críticos e onde o risco está concentrado — e pode triar achados para manter o score fiel ao risco real e aberto.

## Fase 5 — Reporting ✅ (concluída — V1)
**Objetivo:** relatórios profissionais.
- Relatório executivo (resumo, risk score, top riscos priorizados, heatmap) e técnico (inventário, findings completos com evidência/recomendação, metadados do scan)
- PDF (via `reportlab`) · CSV (uma linha por finding) · JSON (payload completo) · histórico de relatórios (imutáveis — RN003)
- App dedicado `apps/reports`, reaproveita o Correlation Engine (Fase 4) para o risk score · download autenticado e auditado (RN011) · só gera a partir de scan `completed` (RN012)
- **Resultado entregue:** o usuário exporta um relatório profissional (PDF/CSV/JSON) de qualquer scan concluído, com um clique.

## Fase 6 — Knowledge Base ✅ (concluída — V1)
**Objetivo:** explicar vulnerabilidades e correções.
- Artigos por categoria: descrição/resumo · impacto · referências · passo a passo de remediação (RN013)
- App dedicado `apps/knowledge`; correlação com findings por `category` (sem FK), com fallback genérico · seed inicial com 6 artigos reais (software, tls, web, network, cms, general)
- CRUD completo (leitura para todos, escrita analyst/admin, exclusão admin) — único modelo do domínio que não é histórico imutável (RN003 não se aplica)
- Integrado ao relatório técnico (Fase 5): `knowledge_articles` traz a remediação relacionada às categorias dos findings do scan
- **Resultado entregue:** o usuário consulta impacto e passo a passo de correção a partir de qualquer finding, e o relatório técnico já vem com essa orientação.

## Fase 7 — Motor de Exploração ✅ (concluída — pós-V1)
**Objetivo:** transformar detecção em **prova de impacto** sob Regras de Engajamento de não-dano.
- Motor `apps/scans/exploit/` espelhando o modelo de plugin dos adapters: contrato `ExploitModule` registrado por `playbook_key` (`registry.py`), orquestrado pelo `runner.py`
- Piso de não-dano **central** no seam de rede (`base.py`): allowlist de método, denylist de payload destrutivo (checada após decodificar), orçamento de requisições por finding — RN021
- Gating fail-closed (RN022): kill-switch dedicado `BYAKUGAN_EXPLOITATION_ENABLED` + opt-in por scan (aggressive) **ou** gatilho manual `POST /scans/{id}/exploit/` + revalidação de escopo por finding; tudo auditado
- Entidades `Evidence` (prova **imutável** — RN023) e `ExploitationPlaybook` (guia curado **vivo**), `ImpactLevel`; aba Evidências (`GET /evidence/`, `GET /playbooks/`)
- Módulos: SQLi (erro/booleana), command injection, LFI, SSRF, SSTI, XSS, open redirect
- **Resultado entregue:** o Byakugan comprova *até onde a falha chega* (ex.: versão/amostra do banco via SQLi, `id` via cmdi, metadata interna via SSRF), sem jamais destruir/DoS/persistir/exfiltrar em massa.

## Fase 8 — Cobertura OWASP Top 10 ✅ (concluída — pós-V1)
**Objetivo:** responder objetivamente "o alvo tem cada uma das 10?" nas duas edições vigentes.
- Taxonomia de primeira classe (fonte única `apps/scans/owasp.py`): todo `Finding` classificado em **OWASP 2021 e 2025** + CWE primário (RN024), preenchido centralmente em `persist_findings`
- Novos detectores fechando buracos: **A01** (forced browsing + IDOR), **A07** (enumeração de usuário), **A08** (SRI ausente + bibliotecas JS desatualizadas), reforços em **A02/A05** (login sobre HTTP, mixed content, debug exposto) — 18 categorias de finding
- Novos módulos de prova (Fase 7): forced browsing, IDOR, enumeração de usuário
- **Matriz de cobertura por scan** (`GET /scans/{id}/owasp-coverage/`) — testado × encontrado × provado, com "cobertura limitada" honesta onde não é detectável remotamente (Insecure Design, Logging, Mishandling); seção OWASP nos relatórios
- **Resultado entregue:** cada finding rastreável ao OWASP/CWE, e uma matriz que mostra, por edição, o que foi coberto — o entregável central para banca e clientes. Ver `docs/owasp-coverage.md`.

## Fase 9 — AI Assistant (V1)
**Objetivo:** analista virtual de segurança.
- Explicação de findings (com OWASP/CWE e a `Evidence` provada) · sugestão de correções · resumos executivos · consultas em linguagem natural · nunca executa ações (RN009)

## Fase 10 — Enterprise Features (pós-1.0)
**Objetivo:** preparar para ambientes corporativos.
- Multi-tenant · SSO · integração SIEM · integração SOAR · agendamento avançado

---

## Critério para a Versão 1.0

A 1.0 é concluída quando estiverem funcionais e integrados:
- [x] Asset Discovery
- [x] Fingerprinting
- [x] Vulnerability Assessment
- [x] Correlation Engine
- [x] Reporting
- [x] Knowledge Base
- [x] Motor de Exploração (prova de impacto sob RoE)
- [x] Cobertura OWASP Top 10 (2021 + 2025)
- [x] Cobertura de testes > 80%
- [ ] AI Assistant
- [~] Documentação completa (sincronização em andamento)

## Visão de longo prazo (rumo ao norte)

Para caminhar rumo a "encontrar cada brecha explorável, documentar e orientar a correção", as frentes concretas previstas são:

- **Scanning autenticado** — testar áreas logadas (sessões/cookies/tokens) para alcançar controle de acesso e lógica de negócio pós-login.
- **APIs modernas** — testes específicos de REST/GraphQL (introspection, mass assignment, BOLA/BFLA), além do HTML clássico.
- **Ampliar OWASP/CWE** — mais classes por categoria (ex.: deserialization, request smuggling, prototype pollution) e cobertura crescente do CWE Top 25.
- **Cloud, IaC e contêineres** — misconfig de buckets/IAM, análise de imagens/Dockerfiles, secrets expostos em repositórios/artefatos (supply chain — A03:2025).
- **Monitoramento contínuo** — reexecução agendada, detecção de regressões e diffing de superfície ao longo do tempo.
- **Remediação assistida por IA** — a partir do finding + OWASP/CWE + `Evidence`, gerar orientação de correção acionável e priorizada (Fase 9), mantendo o humano no comando (RN009).
- **Integração ao ecossistema** — exportação para SIEM/SOAR e fluxos de ticketing (Fase 10).

> Cada frente é incremental e mantém os invariantes inegociáveis: autorização explícita por escopo, kill-switches, e o piso de não-dano da exploração. A "cobertura total" é o **norte** que orienta as prioridades, não uma promessa.
