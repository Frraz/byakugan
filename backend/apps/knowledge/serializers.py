"""Serializers da Knowledge Base: KnowledgeArticle (RF014, RN013)."""

from __future__ import annotations

from rest_framework import serializers

from .models import KnowledgeArticle


class KnowledgeArticleSerializer(serializers.ModelSerializer):
    """Artigo de conhecimento (descrição, impacto, remediação, referências)."""

    class Meta:
        model = KnowledgeArticle
        fields = (
            "id",
            "slug",
            "title",
            "category",
            "summary",
            "impact",
            "remediation_steps",
            "references",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id", "created_at", "updated_at")

    def validate_remediation_steps(self, value: list[str]) -> list[str]:
        """RN013: artigo sem passo de remediação é conteúdo sem contexto."""
        if not value:
            raise serializers.ValidationError("Informe ao menos um passo de remediação (RN013).")
        return value
