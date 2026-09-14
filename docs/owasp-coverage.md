# Cobertura OWASP Top 10 (2021 + 2025)

> Fonte da verdade do mapeamento: [`backend/apps/scans/owasp.py`](../backend/apps/scans/owasp.py). A matriz por scan é computada por [`owasp_coverage.py`](../backend/apps/scans/owasp_coverage.py) e exposta em `GET /api/scans/{id}/owasp-coverage/` (ver `docs/api.md`) e na seção "Cobertura OWASP Top 10" dos relatórios.

> O OWASP Top 10 é o **primeiro marco mensurável** rumo ao norte do projeto (cobrir cada brecha explorável). A matriz por edição torna o progresso auditável: ampliar a cobertura de A01–A10 (e depois CWE Top 25 e além) é uma frente contínua do roadmap (`docs/roadmap.md` → Visão de longo prazo).

## 1. Por que duas edições

O Byakugan classifica **todo finding** nas duas edições vigentes do OWASP Top 10, porque elas divergem de forma relevante e ambas são usadas no mercado:

- **2025** absorveu **SSRF** em *Broken Access Control* (A01), promoveu *Security Misconfiguration* para A02, e criou **A03 Software Supply Chain Failures** e **A10 Mishandling of Exceptional Conditions**.
- **2021** ainda é a edição mais citada em contratos, materiais e certificações.

Cada `Finding` grava `owasp_2021`, `owasp_2025` e `cwe` (campos consultáveis e filtráveis na API), preenchidos centralmente em `parsers.persist_findings` via `owasp.resolve_owasp(playbook_key, category)`.

## 2. Dimensões da matriz de cobertura

Para cada uma das 10 categorias de cada edição, a matriz responde:

| Dimensão | Origem | Significado |
| --- | --- | --- |
| **tested** | `owasp.ADAPTER_TESTED_CLASSES` × adapters do scan | Algum detector do scan exercita a categoria (mesmo sem achar nada). |
| **findings** / **highest_severity** | `Finding` do scan (exclui triados como resolvidos) | Quantos achados e a maior severidade. |
| **proven** | `Evidence` com status `proven` | O motor de exploração comprovou impacto. |
| **limited_coverage** | `owasp.LIMITED_COVERAGE` | Categoria não detectável remotamente de forma confiável — reportada honestamente como "cobertura limitada", nunca como falso "ok". |
| **status** | derivado | `proven` > `found` > `tested` > `limited` > `not-tested`. |

## 3. Matriz de detecção → OWASP

Legenda de cobertura: ✅ detecção ativa + prova · 🟢 detecção ativa (sem módulo de prova) · ⚠️ cobertura limitada (não detectável remotamente).

### OWASP 2021

| Cat. 2021 | Cobertura | Detectores (adapters/checks) | Prova (ExploitModule) | CWE principais |
| --- | --- | --- | --- | --- |
| A01 Broken Access Control | ✅ | forced browsing (`web/access_control`), IDOR, path traversal, open redirect | `access-control.forced-browsing`, `access-control.idor`, `injection.path-traversal` | 22, 425, 601, 639 |
| A02 Cryptographic Failures | 🟢 | TLS/cert (`tls_analysis`), cookies inseguros, login sobre HTTP, mixed content | — | 295, 319, 327, 614 |
| A03 Injection | ✅ | SQLi (erro/booleana/tempo), XSS, SSTI, command injection (`web/injection`) | `injection.sqli-*`, `injection.xss`, `injection.ssti`, `injection.command-injection` | 78, 79, 89, 1336 |
| A04 Insecure Design | ⚠️ | — (exige revisão de design) | — | — |
| A05 Security Misconfiguration | 🟢 | headers, exposição (`web/exposure`), métodos HTTP, CORS, debug/stack trace, default creds | `exposure.*`, `credential.default`, `cors.misconfig` | 16, 200, 209, 489, 942 |
| A06 Vulnerable & Outdated Components | 🟢 | CVE via NVD (`cve.py`), bibliotecas JS desatualizadas (`web/integrity`) | — | 1104, 1035 |
| A07 Identification & Auth Failures | ✅ | credenciais default, enumeração de usuário (`web/auth_checks`) | `credential.default`, `auth.user-enumeration` | 204, 307, 614, 1392 |
| A08 Software & Data Integrity Failures | 🟢 | SRI ausente (`web/integrity`) | — | 353, 494 |
| A09 Security Logging & Monitoring Failures | ⚠️ | sinal indireto (debug/verbose error) | — | 778 |
| A10 SSRF | ✅ | SSRF (`web/injection`) | `injection.ssrf` | 918 |

### OWASP 2025

| Cat. 2025 | Cobertura | Observação vs. 2021 |
| --- | --- | --- |
| A01 Broken Access Control | ✅ | agora **inclui SSRF** (era A10:2021). |
| A02 Security Misconfiguration | 🟢 | subiu de A05:2021. |
| A03 Software Supply Chain Failures | 🟢 | absorve *Vulnerable & Outdated Components* (CVE engine + JS desatualizado). |
| A04 Cryptographic Failures | 🟢 | era A02:2021. |
| A05 Injection | ✅ | era A03:2021. |
| A06 Insecure Design | ⚠️ | não detectável remotamente. |
| A07 Authentication Failures | ✅ | era A07:2021. |
| A08 Software or Data Integrity Failures | 🟢 | SRI. |
| A09 Logging & Alerting Failures | ⚠️ | sinal indireto apenas. |
| A10 Mishandling of Exceptional Conditions | ⚠️ | nova categoria; não detectável remotamente. |

## 4. Como adicionar uma nova classe ao mapeamento

1. Adicione a `playbook_key` em `CLASS_TO_OWASP` (`owasp.py`) com `(código 2021, código 2025, CWE)`.
2. Se um adapter passa a exercitá-la, inclua a classe em `ADAPTER_TESTED_CLASSES` do adapter.
3. O enriquecimento no `Finding` é automático (via `resolve_owasp` em `persist_findings`) — nenhum detector precisa saber de OWASP.
4. Seed do playbook curado em uma migration de dados (ver `migrations/0008_seed_owasp_playbooks.py`).

## 5. Honestidade de cobertura

As categorias marcadas ⚠️ (Insecure Design, Logging, Mishandling) **não** são reportadas como cobertas. A matriz as exibe como *cobertura limitada* com a justificativa de que exigem revisão de design/código ou acesso a logs internos — o que é a postura correta num relatório de pentest e defensável perante a banca.
