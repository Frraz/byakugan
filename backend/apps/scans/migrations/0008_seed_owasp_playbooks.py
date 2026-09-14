# Semeia os playbooks das novas classes OWASP (Fase B/C) na aba Evidências.
#
# Migração de dados, mesmo padrão de 0006_seed_playbooks.py. `key` casa com
# `Finding.playbook_key` e com os `ExploitModule` (quando há um). `references`
# traz sempre a categoria OWASP 2021 E 2025 + o CWE — a classificação vira
# consultável no finding (owasp_2021/owasp_2025/cwe) e explicada no playbook.

from django.db import migrations

OWASP_2021 = "https://owasp.org/Top10/"
OWASP_2025 = "https://owasp.org/Top10/2025/"

PLAYBOOKS = [
    {
        "key": "access-control.forced-browsing",
        "category": "access-control",
        "vuln_class": "Broken Access Control (Forced Browsing)",
        "title": "Explorando acesso não-autenticado a área administrativa",
        "summary": (
            "Endpoints administrativos/de gestão que servem conteúdo sem exigir "
            "autenticação permitem que qualquer visitante use funcionalidade "
            "restrita — a falha de controle de acesso mais direta."
        ),
        "prerequisites": "Endpoint admin que responde 200 com conteúdo real (não redireciona para login).",
        "steps": [
            {
                "action": "Acessar o endpoint sem sessão",
                "command": 'curl -sk "{url}"',
                "expected": "HTTP 200 com painel/dados administrativos, sem pedir login.",
            },
            {
                "action": "Enumerar funcionalidade acessível (sem alterar)",
                "command": 'curl -sk "{url}" | grep -iE "user|config|delete|admin"',
                "expected": "Ações administrativas expostas — dimensiona o impacto.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Leitura de área restrita",
                "impact": "auth-bypass",
                "description": "Ver dados/funções que exigiriam autenticação.",
            },
            {
                "stage": "2. Ação administrativa",
                "impact": "auth-bypass",
                "description": "Executar operações de admin (gerir usuários, config).",
            },
        ],
        "max_impact": "auth-bypass",
        "tools": ["curl", "Burp Suite", "ffuf"],
        "references": [
            OWASP_2021 + "A01_2021-Broken_Access_Control/",
            OWASP_2025,
            "https://cwe.mitre.org/data/definitions/425.html",
        ],
    },
    {
        "key": "access-control.idor",
        "category": "access-control",
        "vuln_class": "Broken Access Control (IDOR)",
        "title": "Explorando Insecure Direct Object Reference (IDOR)",
        "summary": (
            "Quando o servidor entrega um objeto só pelo seu identificador, sem "
            "checar se ele pertence ao usuário autenticado, trocar o id dá acesso "
            "aos dados de outros usuários."
        ),
        "prerequisites": "Parâmetro de id numérico/sequencial cujo objeto muda ao variar o id.",
        "steps": [
            {
                "action": "Acessar o próprio objeto e um id vizinho",
                "command": 'curl -sk "{url}"  # depois troque {param}=N por N+1',
                "expected": "Objeto de outro id é servido sem checagem de propriedade.",
            },
            {
                "action": "Amostrar poucos ids para confirmar o padrão (não em massa)",
                "command": 'for i in 1 2 3; do curl -sk "{url}"; done  # variando {param}',
                "expected": "Vários registros de terceiros acessíveis — IDOR confirmado.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Leitura de dados de terceiros",
                "impact": "info-disclosure",
                "description": "Ler registros de outros usuários trocando o id.",
            },
            {
                "stage": "2. Alteração de dados de terceiros",
                "impact": "auth-bypass",
                "description": "Se o mesmo padrão valer para escrita — fora do RoE automatizado.",
            },
        ],
        "max_impact": "auth-bypass",
        "tools": ["Burp Suite (Autorize)", "curl", "ffuf"],
        "references": [
            OWASP_2021 + "A01_2021-Broken_Access_Control/",
            OWASP_2025,
            "https://cwe.mitre.org/data/definitions/639.html",
        ],
    },
    {
        "key": "auth.user-enumeration",
        "category": "auth",
        "vuln_class": "Authentication Failures (User Enumeration)",
        "title": "Explorando enumeração de usuários",
        "summary": (
            "Mensagens de erro que distinguem 'usuário inexistente' de 'senha "
            "incorreta' (ou tempos de resposta diferentes) permitem montar uma "
            "lista de contas válidas antes de força bruta/phishing direcionado."
        ),
        "prerequisites": "Login/registro/reset que revela se o usuário existe.",
        "steps": [
            {
                "action": "Comparar resposta para usuário existente vs. inexistente",
                "command": 'curl -sk "{url}" --data "username=admin&password=x" ; curl -sk "{url}" --data "username=byk-nao-existe&password=x"',
                "expected": "Mensagens/tempos diferentes revelam a existência da conta.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Lista de contas válidas",
                "impact": "info-disclosure",
                "description": "Enumerar usuários reais do sistema.",
            },
            {
                "stage": "2. Força bruta/credential stuffing direcionado",
                "impact": "auth-bypass",
                "description": "Focar ataques nas contas confirmadas — fora do RoE automatizado.",
            },
        ],
        "max_impact": "auth-bypass",
        "tools": ["curl", "Burp Suite (Intruder)", "ffuf"],
        "references": [
            OWASP_2021 + "A07_2021-Identification_and_Authentication_Failures/",
            OWASP_2025,
            "https://cwe.mitre.org/data/definitions/204.html",
        ],
    },
    {
        "key": "auth.no-rate-limit",
        "category": "auth",
        "vuln_class": "Authentication Failures (sem rate limiting)",
        "title": "Ausência de rate limiting no login",
        "summary": (
            "Sem limite de tentativas, bloqueio ou CAPTCHA, o login fica exposto a "
            "força bruta e credential stuffing em larga escala."
        ),
        "prerequisites": "Login que aceita tentativas ilimitadas sem barramento (429/lockout/CAPTCHA).",
        "steps": [
            {
                "action": "Medir se há barramento após várias tentativas (com autorização)",
                "command": 'for i in $(seq 1 20); do curl -sk -o /dev/null -w "%{http_code}\\n" "{url}" --data "username=admin&password=wrong$i"; done',
                "expected": "Nenhum 429/bloqueio — força bruta viável.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Força bruta de senha",
                "impact": "auth-bypass",
                "description": "Testar milhares de senhas por conta — fora do RoE automatizado.",
            },
        ],
        "max_impact": "auth-bypass",
        "tools": ["hydra", "Burp Suite (Intruder)", "ffuf"],
        "references": [
            OWASP_2021 + "A07_2021-Identification_and_Authentication_Failures/",
            OWASP_2025,
            "https://cwe.mitre.org/data/definitions/307.html",
        ],
    },
    {
        "key": "auth.weak-session",
        "category": "auth",
        "vuln_class": "Authentication Failures (sessão fraca)",
        "title": "Cookie de sessão sem proteção adequada",
        "summary": (
            "Cookies de sessão sem HttpOnly/Secure/SameSite ficam expostos a roubo "
            "via XSS, interceptação em trânsito e CSRF."
        ),
        "prerequisites": "Cookie de sessão sem uma ou mais flags (HttpOnly/Secure/SameSite).",
        "steps": [
            {
                "action": "Inspecionar as flags do cookie de sessão",
                "command": 'curl -skI "{url}" | grep -i set-cookie',
                "expected": "Faltam Secure/HttpOnly/SameSite no cookie de sessão.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Roubo de sessão",
                "impact": "session",
                "description": "Exfiltrar o cookie (sem HttpOnly) via XSS ou rede (sem Secure).",
            },
        ],
        "max_impact": "session",
        "tools": ["curl", "Burp Suite"],
        "references": [
            OWASP_2021 + "A07_2021-Identification_and_Authentication_Failures/",
            OWASP_2025,
            "https://cwe.mitre.org/data/definitions/614.html",
        ],
    },
    {
        "key": "integrity.missing-sri",
        "category": "integrity",
        "vuln_class": "Software/Data Integrity Failures (SRI ausente)",
        "title": "Recurso de terceiro sem Subresource Integrity",
        "summary": (
            "Scripts/estilos carregados de um CDN de terceiro sem hash SRI executam "
            "qualquer conteúdo que o CDN servir — se o CDN for comprometido, a "
            "aplicação executa código do atacante."
        ),
        "prerequisites": "<script>/<link> externo sem atributo integrity.",
        "steps": [
            {
                "action": "Localizar recursos externos sem integrity",
                "command": 'curl -sk "{url}" | grep -iE "<script|<link" | grep -v integrity',
                "expected": "Recursos de CDN sem hash SRI.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Execução via CDN comprometido",
                "impact": "session",
                "description": "Código do atacante roda no contexto da aplicação (supply chain).",
            },
        ],
        "max_impact": "session",
        "tools": ["curl", "SRI Hash Generator"],
        "references": [
            OWASP_2021 + "A08_2021-Software_and_Data_Integrity_Failures/",
            OWASP_2025,
            "https://cwe.mitre.org/data/definitions/353.html",
        ],
    },
    {
        "key": "integrity.vulnerable-js",
        "category": "integrity",
        "vuln_class": "Componentes desatualizados (front-end)",
        "title": "Biblioteca JS de front-end vulnerável",
        "summary": (
            "Uma biblioteca de front-end (jQuery, lodash, etc.) com versão abaixo "
            "da corrigida carrega vulnerabilidades públicas conhecidas (XSS, "
            "prototype pollution) direto no navegador do usuário."
        ),
        "prerequisites": "Biblioteca com versão inferior à menor versão segura conhecida.",
        "steps": [
            {
                "action": "Identificar bibliotecas e versões carregadas",
                "command": 'curl -sk "{url}" | grep -ioE "[a-z-]+[-.@][0-9]+\\.[0-9]+\\.[0-9]+"',
                "expected": "Nome+versão de libs desatualizadas.",
            },
            {
                "action": "Cruzar com advisories conhecidos",
                "command": "retire --js --path ./  # ou consultar Snyk/NVD",
                "expected": "CVEs/advisories aplicáveis à versão em uso.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Exploração da vulnerabilidade da lib",
                "impact": "session",
                "description": "Ex.: XSS via jQuery < 3.5.0, prototype pollution via lodash.",
            },
        ],
        "max_impact": "session",
        "tools": ["retire.js", "Snyk", "npm audit"],
        "references": [
            OWASP_2021 + "A06_2021-Vulnerable_and_Outdated_Components/",
            OWASP_2025,
            "https://cwe.mitre.org/data/definitions/1104.html",
        ],
    },
    {
        "key": "crypto.cleartext-credentials",
        "category": "credential",
        "vuln_class": "Cryptographic Failures (credenciais em texto claro)",
        "title": "Login transmitido sobre HTTP",
        "summary": (
            "Um formulário de login servido/submetido por HTTP envia as "
            "credenciais em texto claro, capturáveis por qualquer intermediário "
            "de rede (Wi-Fi, proxy, ISP)."
        ),
        "prerequisites": "Formulário com campo de senha em página HTTP (sem TLS).",
        "steps": [
            {
                "action": "Confirmar a ausência de TLS no login",
                "command": 'curl -skI "{url}"  # http:// sem redirect para https',
                "expected": "Página de login servida por HTTP.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Captura de credenciais em trânsito",
                "impact": "info-disclosure",
                "description": "Sniffing de rede recupera usuário/senha.",
            },
            {
                "stage": "2. Account takeover",
                "impact": "auth-bypass",
                "description": "Autenticar com as credenciais capturadas.",
            },
        ],
        "max_impact": "auth-bypass",
        "tools": ["Wireshark", "mitmproxy", "curl"],
        "references": [
            OWASP_2021 + "A02_2021-Cryptographic_Failures/",
            OWASP_2025,
            "https://cwe.mitre.org/data/definitions/319.html",
        ],
    },
    {
        "key": "crypto.mixed-content",
        "category": "tls",
        "vuln_class": "Cryptographic Failures (conteúdo misto)",
        "title": "Conteúdo misto em página HTTPS",
        "summary": (
            "Uma página HTTPS que carrega sub-recursos por HTTP quebra as "
            "garantias do TLS para esses recursos, permitindo interceptação/"
            "alteração em trânsito."
        ),
        "prerequisites": "Página HTTPS com src/href http:// inseguro.",
        "steps": [
            {
                "action": "Localizar sub-recursos inseguros",
                "command": 'curl -sk "{url}" | grep -iE "src=.http://|href=.http://"',
                "expected": "Recursos http:// numa página https.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Interceptação/alteração de recurso",
                "impact": "session",
                "description": "MITM injeta script no recurso HTTP carregado pela página HTTPS.",
            },
        ],
        "max_impact": "session",
        "tools": ["mitmproxy", "curl", "DevTools"],
        "references": [
            OWASP_2021 + "A02_2021-Cryptographic_Failures/",
            OWASP_2025,
            "https://cwe.mitre.org/data/definitions/319.html",
        ],
    },
    {
        "key": "misconfig.debug-mode",
        "category": "exposure",
        "vuln_class": "Security Misconfiguration (debug exposto)",
        "title": "Modo debug / stack trace em produção",
        "summary": (
            "Páginas de erro detalhadas (Django DEBUG, Werkzeug, Whoops...) revelam "
            "caminhos internos, versões, trechos de código e às vezes segredos, "
            "além de facilitar a exploração."
        ),
        "prerequisites": "Resposta de erro com stack trace/console de debug.",
        "steps": [
            {
                "action": "Disparar um erro e observar a página",
                "command": 'curl -sk "{url}"',
                "expected": "Stack trace/debugger com detalhes internos.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Vazamento de informação interna",
                "impact": "info-disclosure",
                "description": "Caminhos, versões, config e segredos no traceback.",
            },
            {
                "stage": "2. RCE via console de debug",
                "impact": "rce",
                "description": "Werkzeug debugger interativo permite execução de código.",
            },
        ],
        "max_impact": "rce",
        "tools": ["curl", "Burp Suite"],
        "references": [
            OWASP_2021 + "A05_2021-Security_Misconfiguration/",
            OWASP_2025,
            "https://cwe.mitre.org/data/definitions/489.html",
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
        ("scans", "0007_finding_owasp_classification"),
    ]

    operations = [migrations.RunPython(seed_playbooks, remove_playbooks)]
