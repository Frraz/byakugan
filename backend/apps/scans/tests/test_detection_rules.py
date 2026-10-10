"""Testes das regras de detecção Sigma seedadas em ``ExploitationPlaybook``.

Validação empírica (mesma disciplina de ``docs/testing.md`): antes de
confiar que as ~20 regras Sigma escritas à mão são YAML bem-formado e
seguem o schema mínimo do Sigma, valida-se com o parser real (PyYAML) —
não só "parece certo".
"""

from __future__ import annotations

import uuid

import pytest
import yaml
from django.urls import reverse

from apps.scans.models import ExploitationPlaybook

pytestmark = pytest.mark.django_db

#: Mesma lista de 20 classes semeadas em
#: ``migrations/0016_seed_detection_rules.py`` — mantida aqui só para a
#: asserção de contagem; a fonte da verdade do conteúdo é a migration.
_SEEDED_KEYS = (
    "injection.sqli-error",
    "injection.sqli-boolean",
    "injection.command-injection",
    "injection.path-traversal",
    "injection.xss",
    "injection.ssrf",
    "injection.ssti",
    "injection.open-redirect",
    "injection.host-header",
    "injection.nosqli",
    "injection.ldap",
    "injection.crlf",
    "access-control.forced-browsing",
    "access-control.idor",
    "auth.user-enumeration",
    "auth.jwt-weak",
    "credential.default",
    "exposure.git",
    "integrity.java-deserialization",
    "integrity.php-object-injection",
)

#: Campos obrigatórios do schema Sigma mínimo (https://sigmahq.io/).
_REQUIRED_SIGMA_FIELDS = ("title", "id", "logsource", "detection", "level")


def _rules_with_content() -> list[ExploitationPlaybook]:
    return list(ExploitationPlaybook.objects.exclude(detection_rule=""))


def test_detection_rules_seeded_for_all_expected_classes():
    keys_with_rule = set(
        ExploitationPlaybook.objects.exclude(detection_rule="").values_list("key", flat=True)
    )
    assert set(_SEEDED_KEYS) <= keys_with_rule


def test_all_detection_rules_are_valid_yaml():
    rules = _rules_with_content()
    assert len(rules) >= len(_SEEDED_KEYS)
    for pb in rules:
        parsed = yaml.safe_load(pb.detection_rule)
        assert isinstance(parsed, dict), f"{pb.key}: YAML não decodificou para um dict"


def test_all_detection_rules_have_required_sigma_fields():
    for pb in _rules_with_content():
        parsed = yaml.safe_load(pb.detection_rule)
        for field in _REQUIRED_SIGMA_FIELDS:
            assert field in parsed, f"{pb.key}: campo Sigma obrigatório '{field}' ausente"
        assert parsed["level"] in {"informational", "low", "medium", "high", "critical"}


def test_all_detection_rules_have_a_condition_in_detection():
    for pb in _rules_with_content():
        parsed = yaml.safe_load(pb.detection_rule)
        assert "condition" in parsed["detection"], f"{pb.key}: detection sem 'condition'"


def test_detection_rule_ids_are_unique_valid_uuids():
    ids = []
    for pb in _rules_with_content():
        parsed = yaml.safe_load(pb.detection_rule)
        raw_id = parsed["id"]
        uuid.UUID(raw_id)  # levanta ValueError se não for um UUID válido
        ids.append(raw_id)
    assert len(ids) == len(set(ids)), "IDs de regra Sigma duplicados entre playbooks"


def test_playbook_without_log_based_signature_has_no_detection_rule():
    # CSRF não tem assinatura de log confiável (ausência de token não é um
    # padrão observável em log) — a honestidade do design exige que o campo
    # fique vazio em vez de forçar uma regra de baixa confiança.
    pb = ExploitationPlaybook.objects.get(key="access-control.csrf")
    assert pb.detection_rule == ""


# --- API ---------------------------------------------------------------


def test_playbook_api_includes_detection_rule_field(analyst_client):
    resp = analyst_client.get(reverse("scans:playbook-detail", args=["injection.sqli-error"]))
    assert resp.status_code == 200
    assert "detection_rule" in resp.data
    assert "title: SQL Injection" in resp.data["detection_rule"]


def test_playbook_api_detection_rule_blank_when_not_seeded(analyst_client):
    resp = analyst_client.get(reverse("scans:playbook-detail", args=["access-control.csrf"]))
    assert resp.status_code == 200
    assert resp.data["detection_rule"] == ""
