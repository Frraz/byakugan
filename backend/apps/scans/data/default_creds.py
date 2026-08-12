"""Credenciais default/fracas amplamente documentadas — usadas só para DETECÇÃO.

Lista curta e curada, restrita a credenciais de fábrica/instalação
publicamente conhecidas (não uma wordlist de força bruta). Cada uma é
tentada **uma única vez** por ``adapters.DefaultCredsAdapter`` — sem
repetição, sem lockout intencional, sem elevação além da verificação
pontual "a credencial padrão ainda funciona?".
"""

from __future__ import annotations

#: (usuário, senha) tentados contra endpoints que desafiam HTTP Basic Auth.
HTTP_BASIC_CREDS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("root", "root"),
    ("root", "toor"),
]
