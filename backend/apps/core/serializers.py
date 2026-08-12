"""Serializers transversais do core."""

from __future__ import annotations

from rest_framework import serializers

from .models import AuditLog


class AuditLogSerializer(serializers.ModelSerializer):
    """Serialização somente-leitura da trilha de auditoria."""

    class Meta:
        model = AuditLog
        fields = ("id", "user", "action", "severity", "source", "metadata", "timestamp")
        read_only_fields = fields
