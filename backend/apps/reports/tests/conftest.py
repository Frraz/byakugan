"""Fixtures locais dos testes de reports."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_media_root(settings, tmp_path):
    """Evita escrever relatórios de teste no ``media/`` real do projeto."""
    settings.MEDIA_ROOT = tmp_path
