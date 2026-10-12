"""Servidor de QA isolado: SQLite temporário, dados sintéticos e motores desligados.

Execute com o Python do ambiente de desenvolvimento. Nunca usa o banco configurado
no .env, nunca liga os motores e nunca executa probes contra alvos.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))
os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings.dev"


def main() -> None:
    """Prepara dados locais e inicia uma API descartável na porta 8001."""
    from django.conf import settings

    with TemporaryDirectory(prefix="byakugan-redesign-lab-") as directory:
        root = Path(directory)
        settings.DATABASES = {
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": str(root / "lab.sqlite3"),
            }
        }
        settings.MEDIA_ROOT = root / "media"
        settings.BYAKUGAN_SCANNING_ENABLED = False
        settings.BYAKUGAN_EXPLOITATION_ENABLED = False
        settings.CELERY_TASK_ALWAYS_EAGER = True
        settings.CELERY_BROKER_URL = "memory://"
        settings.CELERY_RESULT_BACKEND = "cache+memory://"
        settings.ALLOWED_HOSTS = ["localhost", "127.0.0.1", "testserver"]
        settings.CORS_ALLOWED_ORIGINS = ["http://127.0.0.1:5173"]
        settings.REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"] = {
            "anon": "1000/min",
            "user": "10000/min",
            "login": "100/min",
            "scan": "100/min",
        }

        import django

        django.setup()
        from django.core.management import call_command
        from apps.accounts.models import User
        from apps.reports.models import Report
        from apps.reports.pdf import render_pdf
        from apps.reports.tests.factories import make_completed_scan_with_findings
        from apps.scans.models import Evidence, Target

        call_command("migrate", verbosity=0)
        password = secrets.token_urlsafe(24)
        user = User.objects.create_user(
            email="redesign-lab@example.test", password=password, role="admin"
        )
        target = Target.objects.create(
            name="Laboratório de redesign",
            value="web01.example.test",
            kind="domain",
            authorization_scope="web01.example.test",
            authorized_by=user.email,
            created_by=user,
        )
        scan = make_completed_scan_with_findings()
        scan.target_ref = target
        scan.created_by = user
        scan.authorized_by = user.email
        scan.authorization_scope = target.value
        scan.save()
        finding = scan.findings.first()
        finding.evidence = (
            "Amostra de laboratório: <script> & configuração HTTP.\n" * 80
        )
        finding.recommendation = "Validar a configuração e testar a correção.\n" * 25
        finding.save(update_fields=["evidence", "recommendation"])
        Evidence.objects.create(
            finding=finding,
            scan=scan,
            asset=finding.asset,
            status="blocked",
            impact_level="none",
            proof="Cenário de laboratório: motor desligado.",
            playbook_key="software.cve",
            steps_performed=[],
            chain=[],
            roe_profile="non-destructive",
        )
        credentials_path = Path("/tmp/byakugan-redesign-lab.json")
        credentials_path.write_text(
            json.dumps(
                {
                    "email": user.email,
                    "password": password,
                    "scan": str(scan.id),
                    "asset": str(finding.asset.id),
                }
            )
        )
        credentials_path.chmod(0o600)
        output = Path("/tmp/byakugan-redesign-pdfs")
        output.mkdir(exist_ok=True)
        for report_type in (Report.ReportType.EXECUTIVE, Report.ReportType.TECHNICAL):
            (output / f"{report_type}.pdf").write_bytes(render_pdf(scan, report_type))
        print(
            "API de laboratório: http://127.0.0.1:8001/api/ — motores desabilitados",
            flush=True,
        )
        print("PDFs de QA: /tmp/byakugan-redesign-pdfs/", flush=True)
        try:
            call_command("runserver", "127.0.0.1:8001", use_reloader=False, verbosity=0)
        finally:
            credentials_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
