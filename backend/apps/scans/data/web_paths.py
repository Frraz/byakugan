"""Paths sensíveis testados por ``web.exposure`` (Fase 4 — Web Active Testing).

Cada entrada mapeia um path para uma assinatura de conteúdo opcional —
quando presente, uma resposta ``200`` só é considerada exposição confirmada
se a assinatura também aparecer no corpo (reduz falso positivo de servidores
que devolvem ``200`` para qualquer path — "soft 404"). ``None`` significa
que o próprio ``200`` no path já é significativo (ex.: painel admin).
"""

from __future__ import annotations

SENSITIVE_PATHS: dict[str, str | None] = {
    "/.git/HEAD": "ref:",
    "/.git/config": "[core]",
    "/.svn/entries": None,
    "/.env": "=",
    "/.env.example": "=",
    "/.DS_Store": None,
    "/.htaccess": None,
    "/.htpasswd": None,
    "/backup.zip": None,
    "/backup.sql": None,
    "/backup.tar.gz": None,
    "/dump.sql": None,
    "/database.sql": None,
    "/wp-config.php.bak": None,
    "/config.php.bak": None,
    "/web.config.bak": None,
    "/admin": None,
    "/administrator": None,
    "/phpinfo.php": "phpinfo()",
    "/actuator": None,
    "/actuator/health": '"status"',
    "/actuator/env": None,
    "/server-status": "Apache Server Status",
    "/server-info": None,
    "/.well-known/security.txt": None,
    "/composer.json": '"require"',
    "/package.json": '"dependencies"',
    "/Dockerfile": "FROM ",
    "/docker-compose.yml": None,
    "/.aws/credentials": "aws_access_key_id",
    "/id_rsa": "PRIVATE KEY",
    "/debug": None,
    "/console": None,
    "/trace.axd": None,
    "/elmah.axd": None,
    "/telescope": None,
    "/_profiler": None,
}
