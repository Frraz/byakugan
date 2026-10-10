"""Motor de web application active testing (Fase 4).

Um único adapter (``adapters.WebScanAdapter``) orquestra o crawl e as
checagens deste pacote: ``crawler`` (descoberta de URLs/formulários/scripts),
``passive`` (headers/cookies/CORS), ``exposure`` (paths sensíveis + source
maps), ``methods`` (métodos HTTP perigosos), ``injection`` (detecção de
XSS/SQLi/traversal/redirect/SSTI/command injection/SSRF/host header/
NoSQLi/LDAP/CRLF), ``access_control`` (forced browsing/IDOR/CSRF via
``csrf``), ``auth_checks`` (enumeração de usuário/rate limit/JWT fraco),
``graphql_checks`` (introspecção GraphQL exposta) e ``cloud_exposure``
(referências a buckets S3/GCS/Azure — puramente passivo, nunca requisita o
bucket de terceiros). Todo probe é não-destrutivo: apenas GET/OPTIONS/TRACE,
marcadores inertes em vez de payloads executáveis, e nenhuma escrita no alvo.

Os submódulos são importados aqui explicitamente para que
``from . import web; web.passive.analyze_...(...)`` funcione em
``adapters.py`` sem depender da ordem de import de cada submódulo.
"""

from . import (
    access_control,
    auth_checks,
    cloud_exposure,
    crawler,
    csrf,
    exposure,
    graphql_checks,
    injection,
    integrity,
    methods,
    passive,
)

__all__ = [
    "access_control",
    "auth_checks",
    "cloud_exposure",
    "crawler",
    "csrf",
    "exposure",
    "graphql_checks",
    "injection",
    "integrity",
    "methods",
    "passive",
]
