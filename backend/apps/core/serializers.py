"""Serializers transversais do core."""

from __future__ import annotations

from rest_framework import serializers

from .models import AuditLog


class AuditLogSerializer(serializers.ModelSerializer):
    """Serialização somente-leitura da trilha de auditoria.

    ``user`` é o FK cru (id); ``user_email`` é um campo adicional somente
    leitura para exibição (a trilha de auditoria existe para dizer *quem*
    fez o quê — um id opaco não serve a esse propósito na UI). Adição
    aditiva, não altera ``user`` nem nenhum outro campo existente.
    """

    user_email = serializers.SerializerMethodField()

    class Meta:
        model = AuditLog
        fields = ("id", "user", "user_email", "action", "severity", "source", "metadata", "timestamp")
        read_only_fields = fields

    def get_user_email(self, obj: AuditLog) -> str | None:
        return obj.user.email if obj.user_id else None
