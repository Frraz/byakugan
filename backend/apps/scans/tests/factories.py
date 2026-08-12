"""Factories do domínio de scans para testes."""

from __future__ import annotations

import factory

from apps.accounts.tests.factories import UserFactory
from apps.scans.models import Scan, Target


class TargetFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Target

    name = factory.Sequence(lambda n: f"Alvo {n}")
    value = "scanme.example.test"
    kind = "domain"
    authorized_by = "CISO Teste"
    authorization_scope = "scanme.example.test"
    is_active = True
    created_by = factory.SubFactory(UserFactory, role="analyst")


class ScanFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Scan

    created_by = factory.SubFactory(UserFactory, role="analyst")
    target = "scanme.example.test"
    scan_type = Scan.ScanType.DISCOVERY
    status = Scan.Status.PENDING
    authorized_by = "CISO Teste"
    authorization_scope = "scanme.example.test"
