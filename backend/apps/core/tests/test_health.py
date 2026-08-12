"""Testes de smoke do health check."""

from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient


def test_health_endpoint_returns_ok() -> None:
    """GET /api/health/ deve responder 200 com status 'ok'."""
    client = APIClient()
    response = client.get(reverse("core:health"))

    assert response.status_code == status.HTTP_200_OK
    assert response.data["status"] == "ok"
    assert response.data["service"] == "byakugan-api"
