"""Fixtures compartilhadas de teste (pytest)."""

from __future__ import annotations

import pytest
from rest_framework.test import APIClient

from apps.accounts.tests.factories import UserFactory


@pytest.fixture
def api_client() -> APIClient:
    """Cliente DRF não autenticado."""
    return APIClient()


@pytest.fixture
def admin_user(db):
    return UserFactory(role="admin")


@pytest.fixture
def analyst_user(db):
    return UserFactory(role="analyst")


@pytest.fixture
def viewer_user(db):
    return UserFactory(role="viewer")


@pytest.fixture
def admin_client(admin_user) -> APIClient:
    client = APIClient()
    client.force_authenticate(admin_user)
    return client


@pytest.fixture
def analyst_client(analyst_user) -> APIClient:
    client = APIClient()
    client.force_authenticate(analyst_user)
    return client


@pytest.fixture
def viewer_client(viewer_user) -> APIClient:
    client = APIClient()
    client.force_authenticate(viewer_user)
    return client
