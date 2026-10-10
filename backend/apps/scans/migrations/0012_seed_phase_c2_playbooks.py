# Semeia os playbooks das 3 classes de detecção novas (Fase C2): LDAP
# injection, CRLF Injection/HTTP Response Splitting e referência a cloud
# storage. Mesmo padrão de 0011_seed_expanded_coverage_playbooks.py.

from django.db import migrations

OWASP_2021 = "https://owasp.org/Top10/"
OWASP_2025 = "https://owasp.org/Top10/2025/"

PLAYBOOKS = [
    {
        "key": "injection.ldap",
        "category": "injection",
        "vuln_class": "LDAP Injection",
        "title": "Contornando um filtro LDAP com wildcard/fechamento de filtro",
        "summary": (
            "Quando um parâmetro é concatenado sem escape num filtro LDAP "
            "(ex.: autenticação contra um diretório Active Directory/OpenLDAP), "
            "injetar wildcards ou fechar o filtro antecipadamente pode "
            "contornar autenticação ou extrair dados do diretório."
        ),
        "prerequisites": "Parâmetro usado diretamente num filtro LDAP sem escape (RFC 4515).",
        "steps": [
            {
                "action": "Testar bypass de autenticação com wildcard",
                "command": 'curl -sk "{url}" --data-urlencode "{param}=*"',
                "expected": "Filtro '(uid=*)' casa qualquer usuário — possível bypass.",
            },
            {
                "action": "Fechar o filtro e injetar uma condição sempre-verdadeira",
                "command": 'curl -sk "{url}" --data-urlencode "{param})(|(uid=*"',
                "expected": "Resposta revela estrutura do filtro/dados do diretório.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Bypass de filtro de busca/autenticação",
                "impact": "auth-bypass",
                "description": "Wildcard ou fechamento de filtro contorna a condição esperada.",
            },
            {
                "stage": "2. Extração de dados do diretório",
                "impact": "db-read",
                "description": "Filtros booleanos permitem inferir atributos de entradas LDAP.",
            },
        ],
        "max_impact": "auth-bypass",
        "tools": ["curl", "Burp Suite", "ldapsearch"],
        "references": [
            OWASP_2021 + "A03_2021-Injection/",
            OWASP_2025,
            "https://cwe.mitre.org/data/definitions/90.html",
        ],
    },
    {
        "key": "injection.crlf",
        "category": "injection",
        "vuln_class": "CRLF Injection / HTTP Response Splitting",
        "title": "Injetando headers de resposta via CRLF",
        "summary": (
            "Quando um parâmetro é concatenado sem sanitizar CR/LF num header "
            "de resposta (ex.: Location de um redirect, Set-Cookie), um "
            "atacante pode injetar headers HTTP arbitrários — incluindo "
            "setar cookies, redirecionar via header forjado, ou em servidores "
            "antigos, dividir a resposta em duas (response splitting, "
            "possibilitando cache poisoning/XSS)."
        ),
        "prerequisites": "Parâmetro refletido num header de resposta sem sanitizar \\r\\n.",
        "steps": [
            {
                "action": "Injetar um header sintético via CRLF",
                "command": 'curl -skI "{url}" --data-urlencode "{param}=x\\r\\nX-Injected: 1"',
                "expected": "Header 'X-Injected: 1' aparece como header de resposta genuíno.",
            },
            {
                "action": "Escalar para Set-Cookie ou novo corpo (response splitting)",
                "command": 'curl -sk "{url}" --data-urlencode "{param}=x\\r\\nSet-Cookie: session=attacker-controlled"',
                "expected": "Cookie arbitrário setado no navegador da vítima.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Injeção de header arbitrário",
                "impact": "session",
                "description": "Set-Cookie forjado manipula a sessão da vítima.",
            },
            {
                "stage": "2. HTTP Response Splitting (servidores/proxies antigos)",
                "impact": "session",
                "description": "Dividir a resposta em duas permite refletir conteúdo controlado pelo atacante, incluindo envenenar cache.",
            },
        ],
        "max_impact": "session",
        "tools": ["curl", "Burp Suite"],
        "references": [
            OWASP_2021 + "A03_2021-Injection/",
            OWASP_2025,
            "https://cwe.mitre.org/data/definitions/93.html",
        ],
    },
    {
        "key": "exposure.cloud-storage-reference",
        "category": "exposure",
        "vuln_class": "Referência a cloud storage de terceiros",
        "title": "Verificando permissões de um bucket referenciado pelo site",
        "summary": (
            "O site referencia um bucket/container de cloud storage de "
            "terceiros (S3/GCS/Azure Blob). O Byakugan não testa esse host "
            "(fora do escopo autorizado do alvo), mas buckets mal "
            "configurados (listagem pública, escrita pública) são uma causa "
            "comum e grave de vazamento de dados — merece verificação manual."
        ),
        "prerequisites": "URL de bucket/container encontrada no código-fonte do site.",
        "steps": [
            {
                "action": "Verificar listagem pública do bucket (S3)",
                "command": "aws s3 ls s3://<bucket> --no-sign-request",
                "expected": "Listagem de objetos sem credenciais — bucket legível publicamente.",
            },
            {
                "action": "Verificar escrita pública (não executar sem autorização explícita para ESSE host)",
                "command": "aws s3 cp teste.txt s3://<bucket>/ --no-sign-request --dryrun",
                "expected": "Erro de permissão (esperado) ou sucesso (grave — escrita pública).",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Leitura pública de dados do bucket",
                "impact": "info-disclosure",
                "description": "Listagem/leitura de objetos sem autenticação.",
            },
        ],
        "max_impact": "info-disclosure",
        "tools": ["aws-cli", "gsutil", "az storage", "s3scanner"],
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
        ("scans", "0011_seed_expanded_coverage_playbooks"),
    ]

    operations = [migrations.RunPython(seed_playbooks, remove_playbooks)]
