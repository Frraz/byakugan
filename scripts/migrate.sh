#!/usr/bin/env bash
# Gera e aplica migrações do backend dentro do container.
set -euo pipefail

cd "$(dirname "$0")/.."

docker compose run --rm backend python manage.py makemigrations
docker compose run --rm backend python manage.py migrate
