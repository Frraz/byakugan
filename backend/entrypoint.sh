#!/usr/bin/env bash
# Entrypoint do backend Byakugan.
# Aplica migrações e coleta estáticos (apenas fora de DEBUG) antes de subir o
# processo definido em CMD (gunicorn em produção, runserver em dev).
set -euo pipefail

echo "[entrypoint] Aplicando migrações..."
python manage.py migrate --noinput

# collectstatic só faz sentido em produção (DEBUG desligado). O whitenoise
# serve os estáticos do Django admin/DRF a partir de STATIC_ROOT.
if [ "${DEBUG:-False}" != "True" ]; then
  echo "[entrypoint] Coletando arquivos estáticos..."
  python manage.py collectstatic --noinput
fi

echo "[entrypoint] Iniciando: $*"
exec "$@"
