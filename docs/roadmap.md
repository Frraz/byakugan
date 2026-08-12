# Roadmap

## Visão

O Byakugan é desenvolvido incrementalmente: parte de um MVP funcional de descoberta de ativos e evolui para uma plataforma completa de gestão de vulnerabilidades, correlação de riscos e apoio à remediação.

---

## Fase 0 — Fundação ✅ (concluída)
**Objetivo:** infraestrutura base rodável de ponta a ponta.
- Estrutura de monorepo · Docker Compose · PostgreSQL · Redis
- Backend Django + DRF · Frontend React · Health check ponta a ponta · logging estruturado
- Autenticação JWT (login/refresh/logout+blacklist/register/me) · RBAC (admin/analyst/viewer)
- Auditoria imutável (`AuditLog`) · CI/CD inicial (GitHub Actions: lint, testes, cobertura, SCA)

## Fase 1 — Asset Discovery ✅ (concluída — MVP)
**Objetivo:** identificar ativos no ambiente.
- Cadastro de alvos com autorização (`Target`, validação RN001, enforcement de escopo RN007)
- Kill-switch global (`BYAKUGAN_SCANNING_ENABLED`)
- Descoberta de hosts (DNS) e serviços (portas TCP) via adapters reais · inventário · histórico imutável
- Frontend: login, dashboard, targets, scans (com polling/cancelamento), assets e detalhes
- **Resultado entregue:** o usuário visualiza hosts, portas, protocolos e serviços ponta a ponta.

## Fase 2 — Fingerprinting ✅ (concluída — MVP)
**Objetivo:** identificar tecnologias.
- OS · servidores web · frameworks · linguagens · CMS · tecnologias frontend · TLS
- Adapters reais: `HttpFingerprintAdapter` (headers + assinaturas HTML) e `TlsAdapter` (versão/cipher TLS via stdlib)
- Modelo `Technology` (technology profile por ativo) · API `/assets/{id}/technologies/` · frontend no detalhe do ativo
- **Resultado entregue:** mapa tecnológico do ambiente por ativo, com evidência e nível de confiança.

## Fase 3 — Vulnerability Assessment ✅ (concluída — MVP)
**Objetivo:** relacionar ativos a vulnerabilidades conhecidas.
- Adapter real `CveLookupAdapter`: correlaciona o technology profile (Fase 2) com a API NVD CVE 2.0 por palavra-chave produto/versão
- Classificação CVSS (v3.1 > v3.0 > v2) e severidade (RN004) · catálogo `Vulnerability` reaproveitado entre scans · `Finding` imutável por scan (RN003/RN005)
- API global `/vulnerabilities/` (catálogo) e `/findings/` (ocorrências, filtráveis por severidade/ativo/scan) · frontend com página de Vulnerabilities e seção de findings no detalhe do ativo
- **Resultado entregue:** lista de vulnerabilidades por ativo, com CVE, CVSS, evidência e recomendação.

## Fase 4 — Correlation Engine ✅ (concluída — V1)
**Objetivo:** transformar vulnerabilidades em risco de negócio.
- Risk score (0–100, soma de CVSS saturada) · priorização automática de ativos · agrupamento por criticidade · heatmap por categoria
- Computado sob demanda a partir dos `Finding` (sem modelo próprio, sempre atualizado) · API `GET /api/risk/overview/` · Dashboard com KPIs de risco, ativos priorizados e heatmap
- **Resultado entregue:** o usuário vê, de relance, quais ativos são mais críticos e onde o risco está concentrado.

## Fase 5 — Reporting (V1)
**Objetivo:** relatórios profissionais.
- PDF executivo · PDF técnico · CSV · JSON · histórico de relatórios

## Fase 6 — Knowledge Base (V1)
**Objetivo:** explicar vulnerabilidades e correções.
- Descrição · impacto · referências · mitigações · passo a passo de correção

## Fase 7 — AI Assistant (V1)
**Objetivo:** analista virtual de segurança.
- Explicação de findings · sugestão de correções · resumos executivos · consultas em linguagem natural

## Fase 8 — Enterprise Features (pós-1.0)
**Objetivo:** preparar para ambientes corporativos.
- Multi-tenant · SSO · integração SIEM · integração SOAR · agendamento avançado

---

## Critério para a Versão 1.0

A 1.0 é concluída quando estiverem funcionais e integrados:
- [ ] Asset Discovery
- [ ] Fingerprinting
- [ ] Vulnerability Assessment
- [ ] Reporting
- [ ] AI Assistant
- [ ] Cobertura de testes > 80%
- [ ] Documentação completa
