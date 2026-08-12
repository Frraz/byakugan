# Semeia o conteúdo inicial da Knowledge Base (Fase 6).
#
# Migração de dados (não apenas de schema) — a forma correta e reproduzível
# de versionar conteúdo de referência: roda em qualquer ambiente (dev, CI,
# produção) junto com `migrate`, sem depender de um management command manual.

from django.db import migrations

ARTICLES = [
    {
        "slug": "outdated-software",
        "category": "software",
        "title": "Software desatualizado e vulnerabilidades conhecidas (CVE)",
        "summary": (
            "Serviços expostos rodando versões desatualizadas ficam vulneráveis a "
            "falhas já documentadas publicamente (CVE), muitas vezes com exploits "
            "disponíveis publicamente."
        ),
        "impact": (
            "Um invasor pode explorar CVEs conhecidos para obter execução remota de "
            "código, escalonamento de privilégios ou acesso não autorizado a dados, "
            "sem precisar descobrir uma falha nova — a informação já está documentada."
        ),
        "remediation_steps": [
            "Atualize o software para a versão mais recente estável que corrige o CVE identificado.",
            "Caso a atualização imediata não seja possível, aplique o patch de segurança específico fornecido pelo fabricante.",
            "Se não houver correção disponível, considere isolar o serviço da rede ou desativá-lo temporariamente.",
            "Assine o boletim de segurança do fabricante para ser notificado de novas vulnerabilidades.",
            "Estabeleça um processo recorrente de patch management para evitar o acúmulo de débito de atualização.",
        ],
        "references": [
            "https://nvd.nist.gov/",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        ],
    },
    {
        "slug": "weak-tls",
        "category": "tls",
        "title": "Protocolos TLS obsoletos ou configuração fraca",
        "summary": (
            "Versões antigas do TLS (1.0/1.1) e cifras fracas permitem ataques de "
            "downgrade e interceptação de tráfego cifrado."
        ),
        "impact": (
            "Comunicação sensível (credenciais, tokens, dados pessoais) pode ser "
            "interceptada ou manipulada por um atacante posicionado na rede (MITM), "
            "mesmo que o tráfego pareça criptografado."
        ),
        "remediation_steps": [
            "Desabilite TLS 1.0 e TLS 1.1 no servidor web/proxy.",
            "Exija TLS 1.2 como mínimo, preferencialmente TLS 1.3.",
            "Desabilite cipher suites fracas (RC4, DES, 3DES, exportáveis).",
            "Habilite HSTS (HTTP Strict Transport Security) para forçar HTTPS.",
            "Revalide a configuração com ferramentas como Qualys SSL Labs ou testssl.sh.",
        ],
        "references": ["https://ssl-config.mozilla.org/", "https://testssl.sh/"],
    },
    {
        "slug": "web-misconfiguration",
        "category": "web",
        "title": "Exposição e configuração insegura de aplicações web",
        "summary": (
            "Cabeçalhos de segurança ausentes, painéis administrativos expostos e "
            "mensagens de erro detalhadas revelam informações que facilitam ataques "
            "direcionados."
        ),
        "impact": (
            "Facilita reconhecimento por atacantes (fingerprinting de stack), ataques "
            "de clickjacking/XSS por falta de cabeçalhos de proteção, e acesso não "
            "autorizado a painéis administrativos."
        ),
        "remediation_steps": [
            "Configure cabeçalhos de segurança: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options.",
            "Restrinja o acesso a painéis administrativos por IP/VPN ou autenticação adicional (MFA).",
            "Desative mensagens de erro detalhadas (stack traces) em produção.",
            "Remova banners de versão desnecessários (Server, X-Powered-By).",
            "Realize varreduras periódicas de configuração com ferramentas como Mozilla Observatory.",
        ],
        "references": [
            "https://owasp.org/www-project-secure-headers/",
            "https://observatory.mozilla.org/",
        ],
    },
    {
        "slug": "exposed-service",
        "category": "network",
        "title": "Serviços de rede desnecessariamente expostos",
        "summary": (
            "Portas e serviços administrativos (SSH, RDP, bancos de dados) acessíveis "
            "diretamente da internet ampliam a superfície de ataque."
        ),
        "impact": (
            "Serviços expostos são alvo constante de varreduras automatizadas e "
            "ataques de força bruta; credenciais fracas ou vulnerabilidades no "
            "próprio serviço podem levar ao comprometimento total do host."
        ),
        "remediation_steps": [
            "Restrinja o acesso ao serviço via firewall/security group a IPs/redes confiáveis.",
            "Coloque serviços administrativos atrás de VPN ou bastion host.",
            "Desative serviços que não são realmente necessários.",
            "Habilite autenticação forte (chaves SSH, MFA) e desative senhas fracas/padrão.",
            "Monitore tentativas de acesso e configure rate limiting/fail2ban.",
        ],
        "references": ["https://www.cisa.gov/topics/cyber-threats-and-advisories"],
    },
    {
        "slug": "outdated-cms",
        "category": "cms",
        "title": "CMS e plugins desatualizados",
        "summary": (
            "CMSs (WordPress, Joomla, Drupal) e seus plugins/temas são alvos "
            "frequentes de exploração em massa quando desatualizados."
        ),
        "impact": (
            "Vulnerabilidades em plugins/temas são frequentemente exploradas em "
            "campanhas automatizadas em larga escala, podendo levar a desfiguração "
            "do site, injeção de malware ou uso do servidor para outros ataques."
        ),
        "remediation_steps": [
            "Atualize o CMS, tema e todos os plugins para as versões mais recentes.",
            "Remova plugins/temas não utilizados.",
            "Restrinja o acesso ao painel administrativo (/wp-admin, /administrator).",
            "Habilite atualizações automáticas de segurança quando disponível.",
            "Utilize um WAF (Web Application Firewall) para mitigar exploits conhecidos enquanto o patch não é aplicado.",
        ],
        "references": ["https://wpscan.com/", "https://owasp.org/www-project-top-ten/"],
    },
    {
        "slug": "general-remediation",
        "category": "general",
        "title": "Boas práticas gerais de remediação de vulnerabilidades",
        "summary": (
            "Diretrizes gerais aplicáveis quando não há uma categoria mais "
            "específica identificada para o finding."
        ),
        "impact": (
            "Qualquer vulnerabilidade não tratada aumenta a superfície de ataque do "
            "ambiente e o risco de comprometimento."
        ),
        "remediation_steps": [
            "Avalie a severidade e o CVSS do finding para priorizar a correção.",
            "Consulte a documentação oficial do fabricante/projeto para a correção recomendada.",
            "Aplique o princípio do menor privilégio e segmente o acesso ao ativo afetado.",
            "Revalide a correção com um novo scan após aplicar a mitigação.",
        ],
        "references": [],
    },
]


def seed_articles(apps, schema_editor):
    KnowledgeArticle = apps.get_model("knowledge", "KnowledgeArticle")
    for article in ARTICLES:
        KnowledgeArticle.objects.update_or_create(
            slug=article["slug"],
            defaults={k: v for k, v in article.items() if k != "slug"},
        )


def remove_seeded_articles(apps, schema_editor):
    KnowledgeArticle = apps.get_model("knowledge", "KnowledgeArticle")
    KnowledgeArticle.objects.filter(slug__in=[a["slug"] for a in ARTICLES]).delete()


class Migration(migrations.Migration):

    dependencies = [("knowledge", "0001_initial")]

    operations = [migrations.RunPython(seed_articles, remove_seeded_articles)]
