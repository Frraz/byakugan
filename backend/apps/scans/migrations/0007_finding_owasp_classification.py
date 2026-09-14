# Classificação OWASP Top 10 (2021 + 2025) + CWE de primeira classe no Finding.
#
# Adiciona os campos e faz backfill de todas as linhas existentes via a fonte
# única (apps/scans/owasp.resolve_owasp), a partir do playbook_key/category já
# gravado — mesmo estilo de migração de dados de 0006_seed_playbooks.py.

from django.db import migrations, models

from apps.scans.owasp import resolve_owasp


def backfill_owasp(apps, schema_editor):
    Finding = apps.get_model("scans", "Finding")
    for finding in Finding.objects.all().iterator():
        owasp_2021, owasp_2025, cwe = resolve_owasp(
            playbook_key=finding.playbook_key, category=finding.category
        )
        if owasp_2021 or owasp_2025 or cwe:
            finding.owasp_2021 = owasp_2021
            finding.owasp_2025 = owasp_2025
            finding.cwe = cwe
            finding.save(update_fields=["owasp_2021", "owasp_2025", "cwe"])


def clear_owasp(apps, schema_editor):
    Finding = apps.get_model("scans", "Finding")
    Finding.objects.update(owasp_2021="", owasp_2025="", cwe="")


class Migration(migrations.Migration):

    dependencies = [
        ("scans", "0006_seed_playbooks"),
    ]

    operations = [
        migrations.AddField(
            model_name="finding",
            name="owasp_2021",
            field=models.CharField(blank=True, db_index=True, default="", max_length=4),
        ),
        migrations.AddField(
            model_name="finding",
            name="owasp_2025",
            field=models.CharField(blank=True, db_index=True, default="", max_length=4),
        ),
        migrations.AddField(
            model_name="finding",
            name="cwe",
            field=models.CharField(blank=True, default="", max_length=16),
        ),
        # Novas categorias (Fase B): access-control (A01), auth (A07),
        # integrity (A08). Só muda o conjunto de choices — no-op no schema, mas
        # o full_clean() do Finding rejeita categorias fora das choices.
        migrations.AlterField(
            model_name="finding",
            name="category",
            field=models.CharField(
                choices=[
                    ("software", "Software (CVE)"),
                    ("service", "Serviço de rede"),
                    ("network", "Rede"),
                    ("credential", "Credencial"),
                    ("tls", "TLS"),
                    ("certificate", "Certificado"),
                    ("dns", "DNS"),
                    ("email-security", "Segurança de e-mail"),
                    ("subdomain", "Subdomínio"),
                    ("web-headers", "Headers HTTP"),
                    ("cookie", "Cookie"),
                    ("cors", "CORS"),
                    ("exposure", "Exposição"),
                    ("http-method", "Método HTTP"),
                    ("injection", "Injeção"),
                    ("access-control", "Controle de acesso"),
                    ("auth", "Autenticação"),
                    ("integrity", "Integridade de software/dados"),
                ],
                max_length=50,
            ),
        ),
        migrations.RunPython(backfill_owasp, clear_owasp),
    ]
