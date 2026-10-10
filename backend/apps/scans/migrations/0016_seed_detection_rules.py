# Semeia o campo `detection_rule` (Sigma YAML) nos playbooks das 20 classes
# mais comuns/impactantes — o lado "blue team" do playbook (ver
# models.ExploitationPlaybook.detection_rule e docs/exploitation-engine.md).
#
# Cada regra é um template Sigma (https://sigmahq.io/) — formato aberto
# suportado por Splunk, Elastic, Microsoft Sentinel e Chronicle — pronto para
# um SOC adaptar e implantar contra os próprios logs. São detecções
# BASEADAS NO REQUEST (padrões de payload em query string/cookie/header),
# porque é isso que aparece em log de servidor web — nunca a prova de
# exploração em si (isso só o Byakugan observa, no corpo da resposta).
# Honestidade técnica: quando uma classe não tem uma assinatura de log
# confiável (ex. CSRF — ausência de token não é um padrão de log; CSP fraca —
# falha de config, não de payload), ela simplesmente não ganha regra aqui,
# em vez de forçar uma detecção de baixa confiança.

from django.db import migrations

RULES: dict[str, str] = {
    "injection.sqli-error": """\
title: SQL Injection - Database Error Signature in HTTP Response
id: 515ce3e4-84c1-4ad7-b855-b4ca531c9fe8
status: stable
description: |
  Detecta uma assinatura de erro de banco de dados (MySQL/PostgreSQL/Oracle/
  MSSQL/SQLite) no corpo da resposta HTTP — indício de SQL injection
  baseada em erro. Requer log de servidor/WAF que capture o corpo da
  resposta (nem todo access log padrão faz isso).
author: Byakugan
date: 2026/10/10
logsource:
  category: webserver
detection:
  keywords:
    - 'SQL syntax'
    - 'mysqli_'
    - 'PostgreSQL ERROR'
    - 'ORA-00933'
    - 'Unclosed quotation mark after the character string'
    - 'SQLSTATE['
  condition: keywords
falsepositives:
  - Página de documentação/erro que menciona essas strings legitimamente (raro em produção)
level: high
tags:
  - attack.initial_access
  - attack.t1190
""",
    "injection.sqli-boolean": """\
title: Possible Boolean-Based SQL Injection Probing
id: d71aba4a-e68f-4663-a03c-c0aa3c7b2c0f
status: stable
description: |
  Detecta parâmetros de URL contendo condições booleanas clássicas de SQLi
  (ex.: ' AND '1'='1 / ' AND '1'='2) usadas para inferir resultados sem
  erro visível no corpo da resposta.
author: Byakugan
date: 2026/10/10
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - "' AND '1'='1"
      - "' AND '1'='2"
      - "' OR '1'='1"
      - "%27%20AND%20%271%27%3D%27"
  condition: selection
falsepositives:
  - Teste de QA interno reutilizando payloads de SQLi conhecidos
level: high
tags:
  - attack.initial_access
  - attack.t1190
""",
    "injection.command-injection": """\
title: OS Command Injection Attempt in HTTP Request
id: cffa67b6-0168-4994-bad4-d2c20948a6cf
status: stable
description: Detecta separadores de shell seguidos de comandos de reconhecimento comuns na query string.
author: Byakugan
date: 2026/10/10
logsource:
  category: webserver
detection:
  keywords:
    - ';id'
    - '|id'
    - '`id`'
    - '$(id)'
    - ';whoami'
    - ';cat%20/etc/passwd'
    - ';cat+/etc/passwd'
  condition: keywords
falsepositives:
  - Query strings legítimas que casualmente contêm ';id' (raro)
level: critical
tags:
  - attack.execution
  - attack.t1059
""",
    "injection.path-traversal": """\
title: Path Traversal / Local File Inclusion Attempt
id: 37ab7a3b-1072-4b85-acb5-d402b8975c3a
status: stable
description: Detecta sequências de travessia de diretório visando arquivos sensíveis conhecidos (/etc/passwd, win.ini).
author: Byakugan
date: 2026/10/10
logsource:
  category: webserver
detection:
  keywords:
    - '../../../../etc/passwd'
    - '..%2f..%2f..%2fetc%2fpasswd'
    - '....//....//....//etc/passwd'
    - '..\\\\..\\\\..\\\\windows\\\\win.ini'
  condition: keywords
falsepositives:
  - Nenhum falso positivo plausível conhecido
level: high
tags:
  - attack.initial_access
  - attack.t1190
""",
    "injection.xss": """\
title: Reflected XSS Payload in Request Parameters
id: 51474e71-db8d-4570-97d5-67e4ef12514a
status: stable
description: Detecta marcadores clássicos de payload XSS (tags/handlers de evento) na query string.
author: Byakugan
date: 2026/10/10
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - '<script'
      - 'onerror='
      - 'onload='
      - 'javascript:'
      - '<svg/onload'
      - '<img%20src=x%20onerror='
  condition: selection
falsepositives:
  - Scanners de segurança autorizados (incluindo o próprio Byakugan)
level: medium
tags:
  - attack.initial_access
  - attack.t1190
""",
    "injection.ssrf": """\
title: SSRF Probe Targeting Cloud Metadata or Internal Schemes
id: cf4d6df8-e18b-4c6d-8564-cb433789fb9a
status: stable
description: Detecta tentativas de fazer o servidor requisitar o endpoint de metadata de nuvem ou esquemas de URL não-HTTP arriscados.
author: Byakugan
date: 2026/10/10
logsource:
  category: webserver
detection:
  keywords:
    - '169.254.169.254'
    - 'metadata.google.internal'
    - 'metadata.azure.com'
    - 'file:///'
    - 'gopher://'
    - 'dict://'
  condition: keywords
falsepositives:
  - Integrações internas legítimas que de fato precisam acessar o metadata service (raro vindo de parâmetro de usuário)
level: high
tags:
  - attack.initial_access
  - attack.t1190
""",
    "injection.ssti": """\
title: Server-Side Template Injection Payload
id: 8ee1cee4-9360-4ac4-af51-df19ea82c699
status: stable
description: Detecta expressões de avaliação de template (sintaxe Jinja2/Twig/FreeMarker/EL) em parâmetros de requisição.
author: Byakugan
date: 2026/10/10
logsource:
  category: webserver
detection:
  keywords:
    - '{{7*7}}'
    - '${7*7}'
    - '{{config'
    - '{{request'
    - '#{7*7}'
  condition: keywords
falsepositives:
  - Nenhum falso positivo plausível conhecido
level: critical
tags:
  - attack.initial_access
  - attack.t1190
""",
    "injection.open-redirect": """\
title: Open Redirect Parameter Pointing to External Host
id: ef6bb1ad-0e32-4e4f-b7ee-bbad3a5fd728
status: experimental
description: |
  Detecta parâmetros comuns de redirecionamento (redirect/url/next/return)
  apontando para um host absoluto — heurística, exige ajuste à allowlist de
  domínios legítimos do ambiente para reduzir falso positivo.
author: Byakugan
date: 2026/10/10
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - 'redirect=http'
      - 'url=http'
      - 'next=http'
      - 'return=http'
      - '=//evil'
  condition: selection
falsepositives:
  - Redirecionamento legítimo para parceiros/subdomínios próprios via parâmetro absoluto
level: medium
tags:
  - attack.initial_access
""",
    "injection.host-header": """\
title: Unexpected Host Header Value (Possible Host Header Injection)
id: 6089b512-ef60-4d2c-adeb-af0ffcdd788b
status: experimental
description: |
  Alerta quando o header Host não corresponde a nenhum vhost legítimo
  conhecido do ambiente. **Personalize** `filter_allowlist` com os hostnames
  reais antes de usar — sem isso, a regra não é utilizável (todo ambiente
  tem hostnames próprios diferentes).
author: Byakugan
date: 2026/10/10
logsource:
  category: webserver
detection:
  selection:
    cs-host|exists: true
  filter_allowlist:
    cs-host:
      - '<substitua pelos hostnames legítimos, ex.: app.empresa.com>'
  condition: selection and not filter_allowlist
falsepositives:
  - Healthchecks internos usando IP/localhost como Host
  - CDNs/load balancers que reescrevem o Host legitimamente
level: medium
tags:
  - attack.initial_access
""",
    "injection.nosqli": """\
title: MongoDB Query Operator Injection in Request Parameters
id: ea45e830-8a6d-49c3-bdbb-1aef8cbfa944
status: stable
description: Detecta operadores de consulta MongoDB ($ne/$gt/$regex/$where) expressos como chave de query string.
author: Byakugan
date: 2026/10/10
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - '[$ne]'
      - '[$gt]'
      - '[$regex]'
      - '[$where]'
  condition: selection
falsepositives:
  - API legítima que aceita filtros de operador MongoDB vindos do cliente por design (raro e deveria ser revisado)
level: high
tags:
  - attack.initial_access
  - attack.t1190
""",
    "injection.ldap": """\
title: LDAP Filter Injection Attempt
id: 95b094f6-008b-4e34-b5ea-eeaac0a84e0f
status: stable
description: Detecta fechamento de filtro LDAP e operadores lógicos típicos de injeção (wildcard/OR encadeado).
author: Byakugan
date: 2026/10/10
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - ')(uid='
      - ')(|('
      - '*)(&'
  condition: selection
falsepositives:
  - Nenhum falso positivo plausível conhecido
level: high
tags:
  - attack.initial_access
  - attack.t1190
""",
    "injection.crlf": """\
title: CRLF Sequence in Request Parameters (HTTP Response Splitting Attempt)
id: 61532207-1d1c-4b86-8463-12fc533ea6db
status: stable
description: Detecta sequências CRLF codificadas em parâmetros — tentativa de injetar um header de resposta HTTP arbitrário.
author: Byakugan
date: 2026/10/10
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - '%0d%0a'
      - '%0D%0A'
  condition: selection
falsepositives:
  - Nenhum falso positivo plausível conhecido
level: high
tags:
  - attack.initial_access
""",
    "access-control.forced-browsing": """\
title: Admin Panel Path Requested Without Session Cookie
id: 57f8efa0-7b62-4632-a5d4-4413d8cc5a3c
status: experimental
description: |
  Detecta requisição a um path administrativo comum sem cookie de sessão
  presente — indício de tentativa de acesso direto sem autenticação.
  **Ajuste** o nome do cookie de sessão (`cs-cookie`) ao framework do alvo.
author: Byakugan
date: 2026/10/10
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem|contains:
      - '/admin'
      - '/wp-admin'
      - '/manage'
      - '/phpmyadmin'
  filter_authenticated:
    cs-cookie|contains: 'sessionid='
  condition: selection and not filter_authenticated
falsepositives:
  - Primeira requisição de um usuário legítimo antes do redirect de login (normalmente responde 302, não 200 — correlacionar com o status da resposta)
level: medium
tags:
  - attack.initial_access
  - attack.t1190
""",
    "access-control.idor": """\
title: Sequential Numeric ID Enumeration (Possible IDOR Probing)
id: caf48511-612b-4914-b7ea-9051b02460cd
status: experimental
description: |
  Detecta um volume anormal de requisições variando um parâmetro de id
  numérico a partir do mesmo IP num curto intervalo — heurística de
  enumeração, não confirma IDOR por si só (precisa correlacionar com
  respostas 200 de conteúdo distinto).
author: Byakugan
date: 2026/10/10
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|re: '(id|user_id|account)=\\d+'
  timeframe: 1m
  condition: selection | count(cs-uri-query) by c-ip > 20
falsepositives:
  - Paginação legítima de listagens grandes
  - Crawlers/bots autorizados
level: medium
tags:
  - attack.collection
""",
    "auth.user-enumeration": """\
title: Username Enumeration via Repeated Login Failures (Varying Usernames)
id: bfd2f6fb-3c96-4bd5-a85f-073660dc3b0e
status: experimental
description: |
  Detecta um mesmo IP tentando login com muitos usernames distintos em
  pouco tempo — indício de enumeração de contas (manual ou automatizada).
author: Byakugan
date: 2026/10/10
logsource:
  category: authentication
detection:
  selection:
    EventID: 'login_failed'
  timeframe: 5m
  condition: selection | count(distinct username) by src_ip > 15
falsepositives:
  - Usuário legítimo testando múltiplas contas corporativas da mesma máquina
level: medium
tags:
  - attack.credential_access
  - attack.t1589
""",
    "auth.jwt-weak": """\
title: JWT with alg=none Observed in Request
id: 9649a8b8-379f-4ca9-8348-65324e347db9
status: stable
description: |
  Detecta um JWT cujo header Base64url decodifica para {"alg":"none"} (nas
  3 variações mais comuns de ordenação de campo) sendo enviado como
  credencial — um token sem assinatura não deveria nunca ser aceito.
  **Limitação**: a correspondência depende do encoder exato; variações de
  espaçamento/ordem de campo não listadas aqui evadem esta regra específica
  (decodificação real do token é mais confiável que grep de log).
author: Byakugan
date: 2026/10/10
logsource:
  category: webserver
detection:
  selection:
    Authorization|contains:
      - 'Bearer eyJhbGciOiJub25lIn0'
      - 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0'
      - 'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0'
  condition: selection
falsepositives:
  - Nenhum falso positivo plausível conhecido — alg=none nunca deveria aparecer em produção
level: critical
tags:
  - attack.initial_access
  - attack.t1548
""",
    "credential.default": """\
title: Successful Authentication with Known Default Credentials
id: 6748186d-e5e4-43ce-8789-078786b80eda
status: experimental
description: |
  Detecta login bem-sucedido usando combinações usuário/senha padrão de
  fábrica comuns. **Ajuste** `EventID`/nomes de campo ao log do seu IdP/app.
author: Byakugan
date: 2026/10/10
logsource:
  category: authentication
detection:
  selection:
    EventID: 'login_success'
    username:
      - 'admin'
      - 'root'
    password:
      - 'admin'
      - 'password'
      - '123456'
  condition: selection
falsepositives:
  - Ambiente de laboratório/homologação com credenciais de exemplo conhecidas (deveria, ainda assim, ser trocado)
level: critical
tags:
  - attack.initial_access
  - attack.t1078
""",
    "exposure.git": """\
title: Request for Exposed Version Control or Secrets File
id: 5661c933-bc90-4b66-8919-14e8373af945
status: stable
description: Detecta requisição a arquivos de metadados do Git ou de segredos (.env) que nunca deveriam estar publicamente acessíveis.
author: Byakugan
date: 2026/10/10
logsource:
  category: webserver
detection:
  selection:
    cs-uri-stem|contains:
      - '/.git/'
      - '/.env'
      - '/.svn/'
      - '/.htpasswd'
  condition: selection
falsepositives:
  - Nenhum falso positivo plausível conhecido — esses paths não deveriam existir publicamente
level: high
tags:
  - attack.reconnaissance
  - attack.t1596
""",
    "integrity.java-deserialization": """\
title: Java Serialized Object Signature in Request
id: 606e448c-c6ea-4766-b02e-539c38fd43b8
status: stable
description: |
  Detecta a assinatura Base64 do stream de serialização Java (AC ED 00 05 →
  'rO0AB') em cookie ou query string — precursor de RCE via gadget chain
  (ysoserial) se o backend desserializar esse valor.
author: Byakugan
date: 2026/10/10
logsource:
  category: webserver
detection:
  sel_query:
    cs-uri-query|contains: 'rO0AB'
  sel_cookie:
    Cookie|contains: 'rO0AB'
  condition: sel_query or sel_cookie
falsepositives:
  - Nenhum falso positivo plausível conhecido
level: critical
tags:
  - attack.execution
  - attack.t1190
""",
    "integrity.php-object-injection": """\
title: PHP Serialized Object Signature in Request
id: e7e59ba8-ae4b-464e-a2f6-f6368f0f7e8a
status: experimental
description: |
  Detecta a assinatura estrutural do serialize() nativo do PHP
  (O:<n>:"Classe":...) em query string — precursor de PHP Object Injection
  se o backend passar esse valor a unserialize() sem validação.
  Requer backend com suporte a `|re` (a maioria dos conversores Sigma modernos tem).
author: Byakugan
date: 2026/10/10
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|re: 'O:[0-9]+:"[A-Za-z_]'
  condition: selection
falsepositives:
  - Nenhum falso positivo plausível conhecido
level: high
tags:
  - attack.execution
  - attack.t1190
""",
}


def seed_detection_rules(apps, schema_editor):
    ExploitationPlaybook = apps.get_model("scans", "ExploitationPlaybook")
    for key, rule in RULES.items():
        ExploitationPlaybook.objects.filter(key=key).update(detection_rule=rule)


def unseed_detection_rules(apps, schema_editor):
    ExploitationPlaybook = apps.get_model("scans", "ExploitationPlaybook")
    ExploitationPlaybook.objects.filter(key__in=list(RULES)).update(detection_rule="")


class Migration(migrations.Migration):

    dependencies = [
        ("scans", "0015_add_detection_rule_field"),
    ]

    operations = [migrations.RunPython(seed_detection_rules, unseed_detection_rules)]
