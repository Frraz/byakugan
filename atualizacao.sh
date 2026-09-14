#!/usr/bin/env bash
#
# atualizacao.sh — Atualiza o Byakugan em produção (VPS Ferzion) após um pull.
#
# Executa o redeploy completo seguindo o DEPLOY.md (seção "Atualizações"):
#   1. (opcional) git pull --ff-only            — traz a atualização
#   2. docker compose -f docker-compose.prod.yml up -d --build
#        → rebuilda web + celery; o entrypoint.sh do web roda migrate +
#          collectstatic automaticamente (não precisa rodar à mão)
#   3. ./deploy/build-frontend.sh               — rebuilda o SPA em frontend/dist
#   4. (opcional) nginx -t && systemctl reload nginx   — só se o .conf mudou
#   5. health check no loopback (127.0.0.1:8012/api/health/)
#
# Uso (na VPS, dentro de /var/www/docker-instances/Byakugan):
#   ./atualizacao.sh                # pull + rebuild backend + build frontend + health
#   ./atualizacao.sh --no-pull      # você já deu o git pull; só reconstrói/reinicia
#   ./atualizacao.sh --reload-nginx # também recarrega o nginx do host (mudou o .conf)
#   ./atualizacao.sh --prune        # remove imagens Docker antigas ao final (libera disco)
#   ./atualizacao.sh -h             # ajuda
#
# Idempotente e seguro: para na primeira falha e mostra os logs do container.
# Não expõe portas novas nem toca em 80/443 (regras de ouro do servidor).

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="docker-compose.prod.yml"
WEB_CONTAINER="byakugan_web"
HEALTH_URL="http://127.0.0.1:8012/api/health/"   # loopback (nginx do host faz o proxy)
HEALTH_RETRIES=20
HEALTH_DELAY=3                                     # segundos entre tentativas

DO_PULL=1
DO_RELOAD_NGINX=0
DO_PRUNE=0

# ---------------------------------------------------------------------------
# Helpers de log
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  C_BLUE="\033[1;34m"; C_GREEN="\033[1;32m"; C_YELLOW="\033[1;33m"; C_RED="\033[1;31m"; C_OFF="\033[0m"
else
  C_BLUE=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_OFF=""
fi
log()  { echo -e "${C_BLUE}[atualizacao]${C_OFF} $*"; }
ok()   { echo -e "${C_GREEN}[atualizacao] ✔${C_OFF} $*"; }
warn() { echo -e "${C_YELLOW}[atualizacao] ⚠${C_OFF} $*"; }
err()  { echo -e "${C_RED}[atualizacao] ✗ $*${C_OFF}" >&2; }

usage() {
  sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
}

# ---------------------------------------------------------------------------
# Argumentos
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --no-pull)      DO_PULL=0 ;;
    --reload-nginx) DO_RELOAD_NGINX=1 ;;
    --prune)        DO_PRUNE=1 ;;
    -h|--help)      usage ;;
    *) err "Opção desconhecida: $1 (use -h para ajuda)"; exit 2 ;;
  esac
  shift
done

# ---------------------------------------------------------------------------
# docker compose: prefere o plugin novo (docker compose), cai para docker-compose
# ---------------------------------------------------------------------------
if docker compose version >/dev/null 2>&1; then
  DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  DC=(docker-compose)
else
  err "Docker Compose não encontrado (nem 'docker compose' nem 'docker-compose')."
  exit 1
fi

# ---------------------------------------------------------------------------
# Pré-condições
# ---------------------------------------------------------------------------
cd "$PROJECT_DIR"
log "Diretório do projeto: $PROJECT_DIR"

command -v docker >/dev/null 2>&1 || { err "Docker não está instalado/no PATH."; exit 1; }
docker info >/dev/null 2>&1 || { err "Docker daemon indisponível ou sem permissão (tente com o usuário do deploy)."; exit 1; }
[ -f "$COMPOSE_FILE" ] || { err "Não encontrei $COMPOSE_FILE — rode este script na raiz do projeto na VPS."; exit 1; }
[ -f ".env" ] || { err "Arquivo .env ausente — a produção exige o .env (ver DEPLOY.md §2)."; exit 1; }

# ---------------------------------------------------------------------------
# 1. Trazer a atualização (git pull)
# ---------------------------------------------------------------------------
if [ "$DO_PULL" -eq 1 ]; then
  if [ -d .git ] && command -v git >/dev/null 2>&1; then
    BEFORE="$(git rev-parse --short HEAD 2>/dev/null || echo '?')"
    BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'HEAD')"
    log "git pull --ff-only (branch '$BRANCH', HEAD atual $BEFORE)..."
    if ! git pull --ff-only; then
      err "git pull falhou (provável divergência de histórico). Resolva manualmente e rode com --no-pull."
      exit 1
    fi
    AFTER="$(git rev-parse --short HEAD 2>/dev/null || echo '?')"
    if [ "$BEFORE" = "$AFTER" ]; then
      log "Já estava atualizado ($AFTER) — seguindo com rebuild/restart mesmo assim."
    else
      ok "Atualizado: $BEFORE → $AFTER"
    fi
  else
    warn "Sem repositório git aqui — pulando o pull (use --no-pull para silenciar)."
  fi
else
  log "Pulando git pull (--no-pull)."
fi

# ---------------------------------------------------------------------------
# 2. Backend: rebuild + restart (entrypoint roda migrate + collectstatic)
# ---------------------------------------------------------------------------
log "Reconstruindo e subindo os containers (web + celery + db + redis)..."
if ! "${DC[@]}" -f "$COMPOSE_FILE" up -d --build; then
  err "Falha no 'up --build'. Últimos logs do $WEB_CONTAINER:"
  docker logs "$WEB_CONTAINER" --tail 40 2>/dev/null || true
  exit 1
fi
ok "Containers no ar. As migrações e o collectstatic rodam no entrypoint do web."

# ---------------------------------------------------------------------------
# 3. Frontend: rebuild do SPA (nginx do host serve frontend/dist)
# ---------------------------------------------------------------------------
if [ -x "./deploy/build-frontend.sh" ]; then
  log "Reconstruindo o frontend (SPA)..."
  ./deploy/build-frontend.sh
  ok "Frontend reconstruído em frontend/dist."
else
  warn "deploy/build-frontend.sh ausente/sem permissão — pulei o build do frontend."
fi

# ---------------------------------------------------------------------------
# 4. nginx do host (opcional — só quando o .conf mudou)
# ---------------------------------------------------------------------------
if [ "$DO_RELOAD_NGINX" -eq 1 ]; then
  log "Testando e recarregando o nginx do host..."
  if sudo nginx -t; then
    sudo systemctl reload nginx
    ok "nginx recarregado."
  else
    err "nginx -t falhou — NÃO recarreguei (config inválida)."
    exit 1
  fi
else
  log "nginx: sem reload (use --reload-nginx se você mudou deploy/nginx/*.conf; o SPA novo já é servido do disco sem reload)."
fi

# ---------------------------------------------------------------------------
# 5. Health check (no loopback, como o healthcheck do compose)
# ---------------------------------------------------------------------------
log "Verificando a saúde do backend em $HEALTH_URL ..."
healthy=0
for i in $(seq 1 "$HEALTH_RETRIES"); do
  # X-Forwarded-Proto: https evita o redirect HTTP->HTTPS do SECURE_SSL_REDIRECT.
  if curl -fsS -H "X-Forwarded-Proto: https" "$HEALTH_URL" >/dev/null 2>&1; then
    healthy=1
    break
  fi
  sleep "$HEALTH_DELAY"
  printf '.'
done
echo

if [ "$healthy" -eq 1 ]; then
  ok "Backend saudável: $(curl -fsS -H 'X-Forwarded-Proto: https' "$HEALTH_URL" 2>/dev/null)"
else
  err "Backend NÃO respondeu saudável após $((HEALTH_RETRIES * HEALTH_DELAY))s. Últimos logs:"
  docker logs "$WEB_CONTAINER" --tail 50 2>/dev/null || true
  err "Dica: se for 'password authentication failed', a POSTGRES_PASSWORD do .env divergiu do volume — ver DEPLOY.md §Atualizações."
  exit 1
fi

# ---------------------------------------------------------------------------
# 6. Limpeza opcional de imagens antigas
# ---------------------------------------------------------------------------
if [ "$DO_PRUNE" -eq 1 ]; then
  log "Removendo imagens Docker órfãs (--prune)..."
  docker image prune -f >/dev/null && ok "Imagens antigas removidas."
fi

# ---------------------------------------------------------------------------
# Resumo
# ---------------------------------------------------------------------------
echo
log "Status dos containers do Byakugan:"
docker ps --filter "name=byakugan" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
echo
ok "Atualização concluída com sucesso."
