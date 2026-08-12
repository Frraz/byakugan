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
- Banco de teste: PostgreSQL efêmero (mesma engine da produção).
- **Unitários**: services e regras de negócio isolados (mock de adapters de scan e integrações externas).
- **Integração**: endpoints via `APIClient` do DRF, cobrindo status codes, permissões (RBAC) e validações.
- **Scanner adapters**: testados com saídas de exemplo (fixtures), sem varrer alvos reais no CI.

Rodar:
```bash
docker compose run --rm backend pytest
docker compose run --rm backend pytest --cov=apps --cov-report=term-missing
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
