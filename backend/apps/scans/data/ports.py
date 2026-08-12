"""Perfis de porta TCP por intensidade de scan (ver ``profiles.py``).

``adapters.DEFAULT_PORTS`` (16 portas) continua sendo o perfil ``top16``. Os
perfis aqui ampliam a cobertura de exposição para intensidade ``normal``
(``TOP_100``) e ``aggressive`` (``TOP_1000``) — trade-off deliberado entre
profundidade e tempo/ruído de varredura, não uma lista "oficial" de
frequência real de uso (ao contrário do nmap-services). Portas sem nome de
serviço reconhecido ficam como ``"unknown"``: o número da porta já basta
para detectar exposição — o rótulo é só uma dica para o operador, refinada
pelo banner grab (``banners.py``) quando disponível.
"""

from __future__ import annotations

#: ~110 portas de serviços comumente expostos: acesso remoto, web, e-mail,
#: bancos de dados, mensageria, containers/orquestração e observabilidade.
TOP_100: dict[int, str] = {
    7: "echo",
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    69: "tftp",
    80: "http",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmptrap",
    179: "bgp",
    194: "irc",
    389: "ldap",
    427: "svrloc",
    443: "https",
    445: "smb",
    465: "smtps",
    500: "isakmp",
    514: "syslog",
    515: "printer",
    520: "rip",
    548: "afp",
    554: "rtsp",
    587: "submission",
    631: "ipp",
    636: "ldaps",
    646: "ldp",
    873: "rsync",
    902: "vmware-auth",
    989: "ftps-data",
    990: "ftps",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1194: "openvpn",
    1433: "mssql",
    1434: "mssql-monitor",
    1521: "oracle",
    1723: "pptp",
    1883: "mqtt",
    1900: "upnp",
    2049: "nfs",
    2082: "cpanel",
    2083: "cpanel-ssl",
    2181: "zookeeper",
    2222: "ssh-alt",
    2375: "docker",
    2376: "docker-tls",
    2483: "oracle-alt",
    2484: "oracle-alt-ssl",
    3000: "dev-http",
    3128: "squid-proxy",
    3268: "ldap-gc",
    3306: "mysql",
    3389: "rdp",
    3690: "svn",
    4369: "epmd",
    4443: "https-alt",
    4789: "vxlan",
    4840: "opcua",
    5000: "dev-http-alt",
    5060: "sip",
    5061: "sips",
    5222: "xmpp",
    5432: "postgresql",
    5601: "kibana",
    5671: "amqps",
    5672: "amqp",
    5900: "vnc",
    5984: "couchdb",
    5985: "winrm-http",
    5986: "winrm-https",
    6000: "x11",
    6379: "redis",
    6443: "kubernetes-api",
    6667: "irc",
    7000: "cassandra-thrift",
    7077: "spark",
    7199: "cassandra-jmx",
    7474: "neo4j-http",
    7687: "neo4j-bolt",
    8000: "http-alt2",
    8080: "http-alt",
    8081: "http-alt3",
    8161: "activemq",
    8443: "https-alt2",
    8500: "consul",
    8888: "http-alt4",
    9000: "php-fpm",
    9042: "cassandra",
    9090: "prometheus",
    9092: "kafka",
    9100: "printer-jetdirect",
    9200: "elasticsearch",
    9300: "elasticsearch-transport",
    9418: "git",
    9999: "abyss",
    10000: "webmin",
    11211: "memcached",
    15672: "rabbitmq-mgmt",
    27017: "mongodb",
    27018: "mongodb-shard",
    27019: "mongodb-config",
    50000: "db2",
}

#: Portas "bem conhecidas" adicionais (fora de TOP_100) e outras de alto
#: valor para detecção de exposição — usadas só na ampliação para TOP_1000.
_ADDITIONAL_HIGH_VALUE_PORTS: dict[int, str] = {
    3001: "dev-http-alt2",
    4200: "angular-dev",
    5001: "dev-http-alt3",
    5555: "android-debug-bridge",
    6660: "irc-alt",
    6666: "irc-alt2",
    6669: "irc-alt3",
    6697: "irc-ssl",
    7001: "cassandra-jmx-alt",
    8008: "http-alt5",
    8069: "odoo",
    8086: "influxdb",
    8888: "jupyter",
    9042: "cassandra",
    9160: "cassandra-thrift-alt",
    9990: "wildfly-mgmt",
    16379: "redis-cluster",
    18080: "http-alt6",
    28017: "mongodb-http",
    50070: "hadoop-namenode",
    61616: "activemq-openwire",
}


def _build_top_1000() -> dict[int, str]:
    """Combina TOP_100, a faixa "bem conhecida" (1–1024) e portas altas de valor.

    Portas na faixa 1–1024 sem nome específico em TOP_100 entram como
    "unknown" — ainda vale a pena testar (muitos serviços custom rodam ali),
    o rótulo só não tem uma dica melhor sem banner grab.
    """
    ports: dict[int, str] = {port: "unknown" for port in range(1, 1025)}
    ports.update(TOP_100)
    ports.update(_ADDITIONAL_HIGH_VALUE_PORTS)
    return dict(sorted(ports.items()))


#: Faixa "bem conhecida" completa (1–1024) + portas altas de alto valor —
#: perfil de intensidade ``aggressive``. Não é literalmente 1000 portas (é
#: mais abrangente que isso na faixa baixa) — o nome é o rótulo do perfil,
#: não uma contagem exata.
TOP_1000: dict[int, str] = _build_top_1000()
