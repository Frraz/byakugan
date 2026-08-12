"""Motor de web application active testing (Fase 4).

Um único adapter (``adapters.WebScanAdapter``) orquestra o crawl e as
checagens deste pacote: ``crawler`` (descoberta de URLs/formulários),
``passive`` (headers/cookies/CORS), ``exposure`` (paths sensíveis),
``methods`` (métodos HTTP perigosos) e ``injection`` (detecção de
XSS/SQLi/traversal/redirect/SSTI/command injection). Todo probe é
não-destrutivo: apenas GET/OPTIONS/TRACE, marcadores inertes em vez de
payloads executáveis, e nenhuma escrita no alvo.

Os submódulos são importados aqui explicitamente para que
``from . import web; web.passive.analyze_...(...)`` funcione em
``adapters.py`` sem depender da ordem de import de cada submódulo.
"""

from . import crawler, exposure, injection, methods, passive

__all__ = ["crawler", "exposure", "injection", "methods", "passive"]
