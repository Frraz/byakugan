#!/usr/bin/env bash
# Gera o build de produção do frontend (SPA) em frontend/dist usando Docker,
# sem exigir Node instalado no host. O nginx do host serve esse diretório.
#
# A API fica na mesma origem (nginx do host faz proxy de /api), então o build
# usa VITE_API_BASE_URL=/api por padrão.
set -euo pipefail

cd "$(dirname "$0")/.."

API_BASE="${VITE_API_BASE_URL:-/api}"

echo "[build-frontend] Gerando build com VITE_API_BASE_URL=${API_BASE} ..."
docker run --rm \
  -v "$PWD/frontend":/app \
  -w /app \
  -e "VITE_API_BASE_URL=${API_BASE}" \
  node:22-slim \
  sh -c "if [ -f package-lock.json ]; then npm ci; else npm install; fi && npm run build"

echo "[build-frontend] Concluído. Saída em: frontend/dist"
