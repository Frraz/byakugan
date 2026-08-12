"""Configurações de produção (hardening — ver docs/security.md).

Uso no servidor: DJANGO_SETTINGS_MODULE=config.settings.production
A aplicação roda atrás do nginx do HOST, que termina o TLS. Por isso confiamos
no header X-Forwarded-Proto para saber que a origem é HTTPS.
"""

from .base import *  # noqa: F401,F403
from .base import MIDDLEWARE, env

DEBUG = False

# Hosts e origens confiáveis vêm do ambiente (ex.: byakugan.ferzion.com.br).
ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=[])
CSRF_TRUSTED_ORIGINS = env.list("CSRF_TRUSTED_ORIGINS", default=[])

# --- WhiteNoise: serve os estáticos do Django admin/DRF via gunicorn ---
# Inserido logo após o SecurityMiddleware (ordem recomendada).
MIDDLEWARE.insert(
    MIDDLEWARE.index("django.middleware.security.SecurityMiddleware") + 1,
    "whitenoise.middleware.WhiteNoiseMiddleware",
)
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}

# --- HTTPS / HSTS obrigatórios em produção (RNF008) ---
# O nginx do host faz o TLS; o gunicorn recebe HTTP na rede loopback.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31_536_000  # 1 ano
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"

# Em produção, CORS é restrito às origens explicitamente configuradas.
# Como o SPA é servido na MESMA origem do backend (nginx do host), normalmente
# nem é necessário — deixe vazio salvo se houver front em outro domínio.
CORS_ALLOWED_ORIGINS = env.list("CORS_ALLOWED_ORIGINS", default=[])
