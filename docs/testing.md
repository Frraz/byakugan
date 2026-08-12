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
- **Estado atual**: 464 testes, cobertura ~89,70% (`--cov=apps --cov-fail-under=80`).

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
