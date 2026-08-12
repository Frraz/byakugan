# Deployment

> Toda a stack sobe via **Docker Compose** (RNF002). Este documento cobre ambientes, serviços e o caminho para CI/CD e produção.

## Serviços (docker-compose)

| Serviço | Imagem/base | Porta | Papel |
| --- | --- | --- | --- |
| `postgres` | postgres:16 | 5432 | Banco principal |
| `redis` | redis:7 | 6379 | Broker/result do Celery |
| `backend` | build `backend/` | 8000 | API Django/DRF |
| `celery` | build `backend/` | — | Worker assíncrono de scans |
| `frontend` | build `frontend/` | 5173 | Vite dev server |

`backend` e `celery` compartilham a mesma imagem (comandos diferentes). `backend` depende de `postgres` e `redis` saudáveis (healthchecks).

## Ambientes

| Ambiente | Settings | Notas |
| --- | --- | --- |
| Desenvolvimento | `config.settings.dev` | `DEBUG=True`, CORS liberado p/ `localhost:5173`, hot reload |
| Produção | `config.settings.production` | `DEBUG=False`, HTTPS/HSTS, `ALLOWED_HOSTS` restrito, static via WhiteNoise/nginx |

Configuração por `.env` (ver `.env.example`). Segredos nunca versionados.

## Comandos

```bash
# subir tudo
docker compose up --build

# migrações
docker compose run --rm backend python manage.py migrate

# criar superusuário
docker compose run --rm backend python manage.py createsuperuser

# testes
docker compose run --rm backend pytest
docker compose run --rm frontend npm test
```

## Servidor Ferzion (deploy atual)

O ambiente de testes é um VPS compartilhado por vários sistemas Docker atrás de
um único nginx no host. O deploy do Byakugan respeita essas convenções e está
documentado em [`DEPLOY.md`](../DEPLOY.md), usando `docker-compose.prod.yml`.

Pontos-chave (para não interferir nos outros sistemas):
- **Nenhum container mapeia 80/443** — só o nginx do host.
- `web` publica apenas em `127.0.0.1:8012` (loopback); nginx do host faz proxy.
- `db` e `redis` sem portas expostas (rede interna do compose).
- `container_name` prefixado com `byakugan_`.
- SPA servido pelo nginx do host a partir de `frontend/dist`; `/api`, `/admin` e
  `/static` vão por proxy ao gunicorn.

## Produção (evolução)

- **Reverse proxy**: nginx com TLS (Let's Encrypt), HSTS e cabeçalhos de segurança.
- **Backend**: Gunicorn/Uvicorn atrás do nginx; containers não-root, não privilegiados.
- **Static/media**: servidos por nginx ou storage de objetos.
- **Escala**: múltiplas réplicas do worker Celery (escala horizontal — RNF009).
- **Backups**: dumps automáticos do PostgreSQL.
- **Observabilidade**: logs JSON centralizados; métricas/health expostos.

## CI/CD (planejado)

Pipeline (GitHub Actions):
1. **Lint** — `ruff`, `black --check`, `eslint`.
2. **Testes** — `pytest` (cobertura > 80%) + `vitest`.
3. **SCA** — `pip-audit` / `npm audit` (ver `security.md`).
4. **Build** — imagens Docker.
5. **Deploy** — ambiente alvo (manual approval para produção).
