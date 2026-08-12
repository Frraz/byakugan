"""Testes de autenticação e RBAC de usuários (RF001–RF003, RN006, RN011)."""

from __future__ import annotations

import pytest
from django.urls import reverse

from apps.accounts.tests.factories import DEFAULT_PASSWORD, UserFactory
from apps.core.models import AuditLog

pytestmark = pytest.mark.django_db


def test_login_returns_tokens_and_user(api_client):
    user = UserFactory(role="analyst")
    resp = api_client.post(
        reverse("accounts:login"),
        {"email": user.email, "password": DEFAULT_PASSWORD},
        format="json",
    )
    assert resp.status_code == 200
    assert "access" in resp.data and "refresh" in resp.data
    assert resp.data["user"]["email"] == user.email
    assert resp.data["user"]["role"] == "analyst"


def test_rn011_login_is_audited(api_client):
    user = UserFactory()
    api_client.post(
        reverse("accounts:login"),
        {"email": user.email, "password": DEFAULT_PASSWORD},
        format="json",
    )
    assert AuditLog.objects.filter(action="auth.login").exists()


def test_refresh_issues_new_access(api_client):
    user = UserFactory()
    login = api_client.post(
        reverse("accounts:login"),
        {"email": user.email, "password": DEFAULT_PASSWORD},
        format="json",
    )
    resp = api_client.post(
        reverse("accounts:refresh"), {"refresh": login.data["refresh"]}, format="json"
    )
    assert resp.status_code == 200
    assert "access" in resp.data


def test_logout_blacklists_refresh(api_client):
    user = UserFactory()
    login = api_client.post(
        reverse("accounts:login"),
        {"email": user.email, "password": DEFAULT_PASSWORD},
        format="json",
    )
    refresh = login.data["refresh"]
    api_client.force_authenticate(user)
    logout = api_client.post(reverse("accounts:logout"), {"refresh": refresh}, format="json")
    assert logout.status_code == 205

    api_client.force_authenticate(user=None)
    reuse = api_client.post(reverse("accounts:refresh"), {"refresh": refresh}, format="json")
    assert reuse.status_code == 401


def test_register_requires_admin(analyst_client):
    resp = analyst_client.post(
        reverse("accounts:register"),
        {"email": "new@byakugan.test", "password": DEFAULT_PASSWORD, "role": "viewer"},
        format="json",
    )
    assert resp.status_code == 403


def test_admin_can_register_user(admin_client):
    resp = admin_client.post(
        reverse("accounts:register"),
        {"email": "new@byakugan.test", "password": DEFAULT_PASSWORD, "role": "analyst"},
        format="json",
    )
    assert resp.status_code == 201
    assert resp.data["email"] == "new@byakugan.test"
    assert "password" not in resp.data


def test_register_rejects_weak_password(admin_client):
    resp = admin_client.post(
        reverse("accounts:register"),
        {"email": "weak@byakugan.test", "password": "123", "role": "viewer"},
        format="json",
    )
    assert resp.status_code == 400


def test_me_returns_current_user(analyst_client, analyst_user):
    resp = analyst_client.get(reverse("accounts:me"))
    assert resp.status_code == 200
    assert resp.data["email"] == analyst_user.email
