"""Configurações de desenvolvimento."""

from .base import *  # noqa: F401,F403
from .base import env

DEBUG = True

# Em dev, aceita qualquer host local por conveniência.
ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=["localhost", "127.0.0.1", "0.0.0.0", "backend"])
