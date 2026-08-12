#!/usr/bin/env bash
# Sobe todo o ambiente de desenvolvimento do Byakugan.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  echo "Criando .env a partir de .env.example..."
  cp .env.example .env
fi

docker compose up --build "$@"
