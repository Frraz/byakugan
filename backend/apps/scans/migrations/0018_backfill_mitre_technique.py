# Backfill de `mitre_technique` em todas as linhas existentes, a partir do
# `playbook_key` já gravado — mesmo estilo de 0007_finding_owasp_classification.py.

from django.db import migrations

from apps.scans.mitre import resolve_mitre


def backfill_mitre(apps, schema_editor):
    Finding = apps.get_model("scans", "Finding")
    for finding in Finding.objects.all().iterator():
        technique, _ = resolve_mitre(finding.playbook_key)
        if technique:
            finding.mitre_technique = technique
            finding.save(update_fields=["mitre_technique"])


def clear_mitre(apps, schema_editor):
    Finding = apps.get_model("scans", "Finding")
    Finding.objects.update(mitre_technique="")


class Migration(migrations.Migration):

    dependencies = [
        ("scans", "0017_add_mitre_technique_field"),
    ]

    operations = [migrations.RunPython(backfill_mitre, clear_mitre)]
