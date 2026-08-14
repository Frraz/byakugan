"""Configurações base do Byakugan, compartilhadas entre ambientes."""

from pathlib import Path

import environ

BASE_DIR = Path(__file__).resolve().parent.parent.parent

env = environ.Env()

SECRET_KEY = env("DJANGO_SECRET_KEY", default="unsafe-dev-key-change-me")
DEBUG = env.bool("DEBUG", default=False)
ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=["localhost", "127.0.0.1"])

# --- Aplicações ---
DJANGO_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

THIRD_PARTY_APPS = [
    "rest_framework",
    "rest_framework_simplejwt.token_blacklist",
    "django_filters",
    "corsheaders",
]

LOCAL_APPS = [
    "apps.core",
    "apps.accounts",
    "apps.assets",
    "apps.scans",
    "apps.reports",
    "apps.knowledge",
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

# --- Banco de dados (PostgreSQL) ---
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env("POSTGRES_DB", default="byakugan"),
        "USER": env("POSTGRES_USER", default="byakugan"),
        "PASSWORD": env("POSTGRES_PASSWORD", default="byakugan"),
        "HOST": env("POSTGRES_HOST", default="localhost"),
        "PORT": env("POSTGRES_PORT", default="5432"),
    }
}

# --- Autenticação / usuário customizado ---
AUTH_USER_MODEL = "accounts.User"

# Argon2 como algoritmo primário (ver docs/security.md)
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 10},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# --- DRF ---
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 20,
    "DEFAULT_FILTER_BACKENDS": (
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
        "rest_framework.filters.OrderingFilter",
    ),
    "DEFAULT_THROTTLE_CLASSES": (
        "rest_framework.throttling.UserRateThrottle",
        "rest_framework.throttling.AnonRateThrottle",
    ),
    "DEFAULT_THROTTLE_RATES": {"user": "1000/day", "anon": "60/hour"},
    "EXCEPTION_HANDLER": "apps.core.exceptions.audited_exception_handler",
}

# --- JWT (ver docs/security.md) ---
from datetime import timedelta  # noqa: E402

SIMPLE_JWT = {
    # Chave de assinatura própria — separada de DJANGO_SECRET_KEY (usado por
    # sessions/CSRF/outros signers do Django) para que rotacionar uma não
    # force a rotação da outra. Sem JWT_SECRET no ambiente, cai no
    # DJANGO_SECRET_KEY (comportamento padrão do simplejwt).
    "SIGNING_KEY": env("JWT_SECRET", default=SECRET_KEY),
    "ACCESS_TOKEN_LIFETIME": timedelta(
        minutes=env.int("JWT_ACCESS_TOKEN_LIFETIME_MINUTES", default=15)
    ),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=env.int("JWT_REFRESH_TOKEN_LIFETIME_DAYS", default=7)),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": True,
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
}

# --- Motor de varredura (kill-switch — ver docs/security.md) ---
BYAKUGAN_SCANNING_ENABLED = env.bool("BYAKUGAN_SCANNING_ENABLED", default=False)

# --- Motor de exploração (kill-switch dedicado — ver docs/exploitation-engine.md) ---
# Segundo kill-switch, INDEPENDENTE do de varredura: a exploração ativa
# (prova de impacto) é a operação mais invasiva do Byakugan e exige opt-in
# explícito. Mesmo com este switch ligado, a exploração só roda com
# ``options["exploit"]=True`` + ``intensity="aggressive"`` + escopo revalidado.
BYAKUGAN_EXPLOITATION_ENABLED = env.bool("BYAKUGAN_EXPLOITATION_ENABLED", default=False)

# --- Vulnerability Assessment (NVD — Fase 3) ---
# API key é opcional: sem ela, o NVD limita a ~5 requisições/30s por IP; com
# ela, o limite sobe para ~50/30s. NVD_REQUEST_DELAY_SECONDS espaça as
# requisições do CveLookupAdapter para respeitar esse limite (RNF009).
NVD_API_BASE_URL = env(
    "NVD_API_BASE_URL", default="https://services.nvd.nist.gov/rest/json/cves/2.0"
)
NVD_API_KEY = env("NVD_API_KEY", default="")
NVD_REQUEST_DELAY_SECONDS = env.float("NVD_REQUEST_DELAY_SECONDS", default=6.0)

# --- Celery ---
CELERY_BROKER_URL = env("CELERY_BROKER_URL", default="redis://localhost:6379/0")
CELERY_RESULT_BACKEND = env("CELERY_RESULT_BACKEND", default="redis://localhost:6379/1")
CELERY_TASK_TRACK_STARTED = True
# Execução síncrona (sem worker) — útil em testes; nunca ligar em produção.
CELERY_TASK_ALWAYS_EAGER = env.bool("CELERY_TASK_ALWAYS_EAGER", default=False)

# Limites de execução de scans.run_scan — evita que um worker fique preso
# indefinidamente num scan travado (motor ofensivo pode varrer múltiplos
# hosts × muitos adapters). SOFT dá chance de um encerramento limpo (exceção
# capturável) antes do HARD matar a task.
SCAN_TASK_TIME_LIMIT = env.int("SCAN_TASK_TIME_LIMIT", default=1800)
SCAN_TASK_SOFT_TIME_LIMIT = env.int("SCAN_TASK_SOFT_TIME_LIMIT", default=1700)

# --- CORS ---
CORS_ALLOWED_ORIGINS = env.list("CORS_ALLOWED_ORIGINS", default=["http://localhost:5173"])

# --- Internacionalização ---
LANGUAGE_CODE = "pt-br"
TIME_ZONE = "America/Sao_Paulo"
USE_I18N = True
USE_TZ = True

# --- Arquivos estáticos ---
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

# --- Arquivos gerados (relatórios) ---
# Não expostos via URL pública: o download passa sempre pela API autenticada e
# auditada (RN011), nunca por serving estático direto do nginx/whitenoise.
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- Logging estruturado (JSON) — ver docs/security.md ---
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "apps.core.logging.JsonFormatter",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
}
