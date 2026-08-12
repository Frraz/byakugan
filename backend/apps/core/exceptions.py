"""Exceções e tratamento de erros padronizados da API.

Centraliza o formato de erro (``{"detail": ...}``) e adiciona status codes
que o DRF não traz por padrão (ex.: 409 Conflict para RN002).
"""

from __future__ import annotations

from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.response import Response
from rest_framework.views import exception_handler


class Conflict(APIException):
    """Erro de conflito de estado (HTTP 409).

    Usado, por exemplo, quando já existe um scan em execução para o mesmo
    alvo (RN002).
    """

    status_code = status.HTTP_409_CONFLICT
    default_detail = "Conflito com o estado atual do recurso."
    default_code = "conflict"


class ScanningDisabled(APIException):
    """Varredura real desabilitada pelo kill-switch global (protótipo).

    Ver ``BYAKUGAN_SCANNING_ENABLED`` em docs/security.md.
    """

    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = (
        "Execução de varredura está desabilitada neste ambiente "
        "(BYAKUGAN_SCANNING_ENABLED=False)."
    )
    default_code = "scanning_disabled"


def audited_exception_handler(exc: Exception, context: dict) -> Response | None:
    """Handler de exceções do DRF.

    Delega ao handler padrão do DRF, garantindo o formato consistente de
    resposta. Serve como ponto único de extensão para tratamento de erros.
    """
    return exception_handler(exc, context)
