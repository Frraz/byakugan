# Semeia os playbooks das 2 classes de detecção novas (Fase C3): CSP fraca
# (qualidade, não só presença) e documentação de API exposta (Swagger/OpenAPI).
# Mesmo padrão de 0012_seed_phase_c2_playbooks.py.

from django.db import migrations

OWASP_2021 = "https://owasp.org/Top10/"
OWASP_2025 = "https://owasp.org/Top10/2025/"

PLAYBOOKS = [
    {
        "key": "misconfig.weak-csp",
        "category": "web-headers",
        "vuln_class": "Content-Security-Policy fraca",
        "title": "Explorando uma CSP presente mas mal configurada",
        "summary": (
            "Uma Content-Security-Policy tecnicamente presente, mas com "
            "diretivas fracas (unsafe-inline, unsafe-eval, wildcard de "
            "origem, sem frame-ancestors), não oferece proteção real contra "
            "XSS/clickjacking — o payload de um XSS já encontrado em outro "
            "ponto do site passa a executar sem restrição."
        ),
        "prerequisites": "CSP presente com 'unsafe-inline'/'unsafe-eval'/wildcard, ou sem frame-ancestors.",
        "steps": [
            {
                "action": "Inspecionar a CSP recebida",
                "command": 'curl -skI "{url}" | grep -i content-security-policy',
                "expected": "Diretiva fraca identificada (ex.: script-src *, 'unsafe-inline').",
            },
            {
                "action": "Combinar com um XSS já encontrado no site para provar a falta de mitigação",
                "command": "injetar <script>alert(document.cookie)</script> no ponto de XSS já identificado",
                "expected": "Script executa normalmente — a CSP não bloqueou o payload.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. XSS sem mitigação da CSP",
                "impact": "session",
                "description": "A CSP fraca não impede a execução do payload de um XSS já presente.",
            },
            {
                "stage": "2. Clickjacking (se frame-ancestors ausente e X-Frame-Options também ausente)",
                "impact": "session",
                "description": "Página pode ser embutida em iframe de origem maliciosa.",
            },
        ],
        "max_impact": "session",
        "tools": ["curl", "Burp Suite", "CSP Evaluator (Google)"],
        "references": [
            OWASP_2021 + "A05_2021-Security_Misconfiguration/",
            OWASP_2025,
            "https://cwe.mitre.org/data/definitions/693.html",
            "https://csp-evaluator.withgoogle.com/",
        ],
    },
    {
        "key": "exposure.api-docs",
        "category": "exposure",
        "vuln_class": "Documentação de API exposta (Swagger/OpenAPI)",
        "title": "Mapeando a API a partir da documentação Swagger/OpenAPI exposta",
        "summary": (
            "Um arquivo swagger.json/openapi.json ou a interface Swagger UI "
            "acessível publicamente revela toda a superfície da API — todos "
            "os endpoints, parâmetros, modelos de dados e, com frequência, "
            "rotas administrativas/internas que nunca foram documentadas "
            "para o público."
        ),
        "prerequisites": "Endpoint de documentação de API (swagger.json/api-docs/swagger-ui) acessível sem autenticação.",
        "steps": [
            {
                "action": "Baixar a especificação completa",
                "command": 'curl -sk "{url}" -o openapi.json',
                "expected": "Especificação completa com todos os endpoints/parâmetros.",
            },
            {
                "action": "Carregar num cliente interativo e enumerar endpoints não documentados publicamente",
                "command": "Swagger UI / Postman apontando para o arquivo baixado",
                "expected": "Endpoints administrativos/internos visíveis na especificação.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Mapeamento completo da superfície de ataque da API",
                "impact": "info-disclosure",
                "description": "Todos os endpoints/parâmetros/modelos ficam visíveis, acelerando qualquer teste subsequente.",
            },
        ],
        "max_impact": "info-disclosure",
        "tools": ["curl", "Swagger UI", "Postman"],
        "references": [
            OWASP_2021 + "A05_2021-Security_Misconfiguration/",
            OWASP_2025,
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
    },
]


def seed_playbooks(apps, schema_editor):
    ExploitationPlaybook = apps.get_model("scans", "ExploitationPlaybook")
    for pb in PLAYBOOKS:
        ExploitationPlaybook.objects.update_or_create(
            key=pb["key"],
            defaults={k: v for k, v in pb.items() if k != "key"},
        )


def remove_playbooks(apps, schema_editor):
    ExploitationPlaybook = apps.get_model("scans", "ExploitationPlaybook")
    ExploitationPlaybook.objects.filter(key__in=[p["key"] for p in PLAYBOOKS]).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("scans", "0012_seed_phase_c2_playbooks"),
    ]

    operations = [migrations.RunPython(seed_playbooks, remove_playbooks)]
