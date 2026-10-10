# Estratégia de Testes

> Meta global: **cobertura > 80%** (RNF005). Nenhuma feature é "pronta" sem testes (regra fundamental do `CLAUDE.md`).

## Pirâmide de testes

```
        E2E (Playwright)        ← poucos, fluxos críticos
     Integração (API + DB)      ← médios
   Unitários (services/utils)   ← muitos, base
```

## Backend

- Framework: **pytest** + `pytest-django`.
- Fixtures/fábricas: `factory_boy`.
- Banco de teste: PostgreSQL efêmero (mesma engine da produção); SQLite em memória é aceitável para iteração local rápida, nunca no CI.
- **Unitários**: services e regras de negócio isolados (mock de adapters de scan e integrações externas).
- **Integração**: endpoints via `APIClient` do DRF, cobrindo status codes, permissões (RBAC) e validações.
- **Motor de scan (seams)**: todo adapter mantém a lógica de decisão em **módulos puros** (`signatures.py`, `cve.py`, `banners.py`, `tls_analysis.py`, `dns_analysis.py`, `web/passive.py`, `web/injection.py`, `web/exposure.py`, `web/methods.py`, `correlation.py`, `profiles.py`, `targets.py`) testáveis sem rede real, e um **seam de rede fino e monkeypatchável** por adapter (`_fetch`/`_probe`/`_probe_udp`/`_probe_versions`/`_get_cert`/`_query_nvd`/`_axfr`/`_fetch_crtsh`/`_try_login`/`_resolve`) — nenhum teste varre alvos reais, nem no CI nem localmente.
- **Disciplina de verificação empírica**: antes de confiar em parsing/regex/hashing escritos à mão (bytes de payload UDP, extração de certificado, AXFR), valida-se com um script standalone contra a biblioteca real (`cryptography`, `dnspython`) antes de escrever os testes formais — já pegou bugs reais (regex de banner SSH, `relativize=True` do AXFR truncando hostnames, mock de teste inconsistente) que só apareceriam em uso real.
- **Estado atual**: 765 testes, cobertura ~90% (`--cov=apps --cov-fail-under=80`).

Rodar:
```bash
docker compose run --rm backend pytest
docker compose run --rm backend pytest --cov=apps --cov-report=term-missing --cov-fail-under=80
```

## Frontend

- Unit/componentes: **Vitest** + **React Testing Library**.
- Foco em comportamento (o que o usuário vê/faz), não em detalhes de implementação.
- Mock de rede via MSW (Mock Service Worker) quando aplicável.

Rodar:
```bash
docker compose run --rm frontend npm test
```

## E2E

- **Playwright** cobrindo fluxos críticos: login → criar scan → ver findings → gerar relatório.
- Executado contra o ambiente Docker Compose.

## Boas práticas

- Um teste por comportamento; nomes descritivos.
- Testes de regra de negócio devem citar o ID da RN coberta (ex.: `test_rn002_prevents_duplicate_scan`).
- Smoke test mínimo: `GET /api/health/` retorna `200`.
- CI executa: lint (`ruff`/`black --check`, `eslint`) → testes → cobertura.

## Cobertura OWASP e motor de exploração (Fase B → C6)

- **Puros (sem banco/rede)**: `test_owasp.py` (taxonomia + matriz `compute_owasp_coverage`), `test_web_access_control.py`, `test_web_auth_checks.py` (user enum, rate limit, **JWT fraco + forja**), `test_web_integrity.py`, `test_web_passive.py`/`test_web_passive_owasp.py` (headers, **qualidade de CSP**), `test_web_injection.py` (XSS/SQLi/traversal/redirect/SSTI/cmdi/SSRF/CRLF, **booleanas SQLi/NoSQLi/LDAP**), `test_web_crawler.py` (BFS + extração de `<script>`), `test_web_exposure.py` (paths sensíveis + source map), `test_web_csrf.py`, `test_web_graphql.py`, `test_web_cloud_exposure.py`, `test_web_deserialization.py`, `test_signatures.py` (fingerprint HTTP + **WAF/CDN**), `test_exploit_owasp.py`/`test_exploit_modules.py` (todos os `ExploitModule`, com fetch falso).
- **Com banco/API**: `test_owasp_api.py` (enriquecimento OWASP **e MITRE** em `persist_findings`, divergência SSRF entre edições, endpoint `owasp-coverage`, campos OWASP/MITRE no `FindingSerializer`, filtro `?mitre_technique=`), `test_exploit_api.py`/`test_exploit_runner.py`/`test_exploit_roe.py` (gating, piso de não-dano, orçamento), `test_detection_rules.py` (as 20 regras Sigma seedadas são **YAML válido** — parseado com PyYAML, dependência só de teste, nunca de produção — com o schema mínimo do Sigma e IDs únicos; mesma disciplina de verificação empírica contra a biblioteca real descrita acima, aplicada a conteúdo em vez de parsing), `test_mitre.py` (mapeamento MITRE ATT&CK puro — trava o tamanho do mapeamento, 27 classes, para que crescer seja uma decisão consciente), `test_correlation.py`/`test_risk_api.py` (cadeias de risco — `compute_chains`).
- **Adapter-level** (`test_adapters.py`): o `WebScanAdapter.run()` completo, com `_fetch` monkeypatchado — cobre a fiação real de cada detector + exploit, não só a função pura isolada.
- **Relatório**: `apps/reports/tests/test_owasp_report.py` (seção OWASP no payload e no PDF de ambos os tipos).

### Disciplina de falso positivo (RN026)

Além de testar que um detector **acerta** (payload malicioso → finding), todo detector de sinal mundano (SSTI, cmdi, sqli-error, SSRF) tem um teste que prova que ele **não erra** quando o mesmo sinal já está no baseline sem relação com a injeção — ex.: `test_ssti_does_not_false_positive_when_49_already_in_baseline`. Para as detecções booleanas (SQLi/NoSQLi/LDAP), há um par de testes de nível adapter que simula ruído de página dinâmica com um `fetch` falso **stateful** (contador de chamadas): um sinal que aparece só na 1ª amostra e não se repete na reconfirmação não gera finding (`test_web_scan_rejects_boolean_sqli_signal_that_does_not_reproduce`); a contraprova confirma que um sinal que se repete continua sendo reportado (`test_web_scan_confirms_boolean_sqli_signal_that_reproduces`). Esse par (ataque positivo + não-regressão de falso positivo) é o padrão esperado para qualquer detector novo baseado em heurística/sinal — não só para injeção booleana.
