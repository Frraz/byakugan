# Scanning Engine

> Núcleo responsável por executar análises **ofensivas de pentest autorizado** (descoberta, fingerprinting, testes ativos não-destrutivos), normalizar resultados e alimentar o motor de correlação. Todo trabalho pesado roda de forma **assíncrona** (Celery), em pure-Python (sem `nmap`/`nuclei`/`sqlmap`; container non-root, sem `NET_RAW`).

## ⚠️ Política de Autorização de Alvos

**Nenhum scan é executado sem autorização registrada.** Antes de enfileirar, o sistema exige:
- `authorized_by` — quem autorizou (nome/papel).
- `authorization_scope` — o escopo permitido (domínios, IPs, sub-redes).

O alvo do scan é validado contra o escopo. Varredura fora do escopo ou sem autorização é bloqueada e auditada. O Byakugan **não** deve ser usado contra terceiros sem permissão explícita — isso é ilegal.

### Enforcement de escopo (implementação)
Antes de enfileirar, o serviço `create_scan` valida o formato do alvo (RN001) e verifica se o alvo está **contido no `authorization_scope`** (`apps/scans/authorization.py`). Fora do escopo → `403` + registro de auditoria (`scan.out_of_scope`). Um alvo cadastrado (`Target`) já carrega sua autorização; scans que o referenciam a herdam.

**Expiração de autorização (RN015)**: `Target.authorization_expires_at`, quando definido, é **reavaliado a cada tentativa de scan** — não apenas no cadastro. Um alvo com autorização vencida bloqueia a criação de novos scans (`403` + auditoria `scan.authorization_expired`), mesmo que o `Target` continue ativo no cadastro.

**Fail-closed na expansão de alvo (RN017)**: quando o alvo é um CIDR ou uma lista, `apps/scans/targets.py:expand_target` gera os hosts individuais e **revalida cada um deles** contra `authorization_scope` antes de qualquer probe — um CIDR autorizado apenas parcialmente nunca vaza para os hosts fora do escopo. A expansão é limitada por `options["max_hosts"]` (padrão 256, teto absoluto 1024 — `profiles.HARD_CAPS`), evitando um scan acidentalmente gigantesco.

### Kill-switch global (protótipo)
O Byakugan é um protótipo de uso restrito. A execução real de varredura é controlada pela env **`BYAKUGAN_SCANNING_ENABLED`** (default **desligado**). Com o switch desligado, o scan é registrado mas **não executa varredura real** — falha de forma controlada com motivo auditado (`scan.blocked`). Isso evita varredura acidental fora de um laboratório autorizado.

### Testes ativos: detecção, nunca exploração (RN016)
Todo check ativo (credenciais default, injeção, testes web) segue os mesmos princípios:
- **Apenas detecta e prova** a vulnerabilidade — nunca explora, altera, apaga ou indisponibiliza dados/serviços do alvo.
- Requisições **idempotentes**: GET/OPTIONS/TRACE; nunca PUT/DELETE ou escrita ativa.
- **Marcadores inertes e únicos** em vez de payloads vivos (ex.: XSS usa `<b>`, nunca `<script>` — pensado inclusive para o caso de XSS armazenado, onde um payload executável salvo poderia atingir usuários reais depois).
- Testes **time-based** (SQLi/command injection por `sleep`) fazem **uma única requisição curta e limitada**, e só rodam com `intensity="aggressive"`.
- Credenciais default são testadas **uma vez por serviço**, só em `intensity="aggressive"`, com revalidação de escopo extra antes de qualquer tentativa.

## Arquitetura

```
Scan Request → Validação → Expansão de alvo → Fila (Celery) → Workers → Adapters → Parsers → DB → Correlation Engine
```

## Fluxo de execução

### 1. Criação
O usuário cria um scan informando alvo (host único, domínio, IP, CIDR ou lista), tipo (`discovery`/`fingerprint`/`vulnerability`/`full`) e autorização. Opcionalmente informa `options` (perfil de intensidade — ver abaixo).

### 2. Validação
Valida formato do alvo (RN001), duplicidade (RN002 → `409`), permissões (RBAC), autorização (RN007) e sua expiração (RN015).

### 3. Enfileiramento
O scan é enviado ao Celery (`scans.run_scan`, com `time_limit`/`soft_time_limit`/`max_retries=2`/`acks_late=True` — nunca prende um worker indefinidamente). Máquina de estados (RN010):

```
pending → running → completed
                 ↘ failed
                 ↘ cancelled
```

### 4. Execução

O orquestrador (`apps/scans/tasks.py:run_scan`) **expande o alvo** em uma lista de hosts (`targets.expand_target` — CIDR/lista → hosts individuais, cada um revalidado contra o escopo) e, **para cada host**, roda os adapters do `scan_type` em duas fases:

1. **Fase profile** (`discovery`/`fingerprint`) — descobre hosts, portas, DNS, subdomínios, tecnologias, TLS/certificado — persiste primeiro.
2. **Fase vulnerability** — lê o profile já persistido (do próprio scan, não apenas de execuções anteriores) e produz findings: correlação de CVE, credenciais default, testes ativos web.

Essa ordem duas-fases **por host** garante que, mesmo num scan `full` sobre múltiplos hosts, cada adapter de vulnerabilidade sempre veja o profile mais recente do host que está processando. `Scan.progress` (0–100) e `Scan.phase` (ex.: `"tls @ 192.168.0.10"`) são atualizados após cada adapter, consultáveis via polling. Cancelamento é **cooperativo**: `ScanContext.check_cancelled()` é checado entre lotes de probe, e `POST /scans/{id}/cancel/` também tenta revogar a task Celery (`celery_app.control.revoke`).

O **Correlation Module** (Risk Assessment) não roda como parte da execução do scan — é computado **sob demanda** a cada leitura, sempre a partir dos `Finding` mais recentes. Ver seção própria abaixo.

## Perfis de intensidade (`Scan.options`)

`scan_type` continua sendo o seletor grosso do pipeline; a **profundidade** de cada execução vem de `options`, normalizado por `apps/scans/profiles.py:normalize_options` a partir da entrada do usuário — nunca confiando em valores não clampados:

| Campo | Descrição | Teto absoluto (`HARD_CAPS`) |
| --- | --- | --- |
| `intensity` | `safe` \| `normal` (padrão) \| `aggressive` — perfil base dos demais campos | — |
| `port_set` | `top16` \| `top100` \| `top1000` — portas TCP varridas (`data/ports.py`) | — |
| `wordlist_size` | Tamanho da wordlist de subdomínios | 5000 |
| `max_hosts` | Máximo de hosts expandidos de um CIDR/lista (RN017) | 1024 |
| `max_pages` | Máximo de páginas rastreadas pelo crawler web | 200 |
| `max_workers` | Concorrência máxima (ex.: resolução de subdomínios) | 64 |
| `rate_delay` | Atraso (s) entre requisições — rate limiting por alvo | — |
| `enabled_checks` | Lista de `adapter.name` a habilitar; `null` = todos do `scan_type` | — |

`aggressive` habilita os checks mais invasivos (credenciais default, injeção time-based) — **sempre não-destrutivos**, mas com maior chance de gerar ruído/carga no alvo; `safe` reduz portas/wordlist e desliga esses checks.

## Scanner Adapters

Cada capacidade de varredura é encapsulada num **adapter** que implementa uma interface comum — permite adicionar capacidades sem tocar no orquestrador, e trocar/mockar adapters por seam de rede fino (`_fetch`/`_probe`/`_query_nvd`/...) mantendo toda a lógica de decisão em módulos puros e testáveis sem rede real.

```python
class ScannerAdapter(ABC):
    name: str
    scan_type: str  # discovery | fingerprint | vulnerability

    @abstractmethod
    def run(self, target: str, context: ScanContext) -> list[RawResult]:
        """Executa a varredura e retorna resultados brutos para o parser."""
```

| Adapter (`name`) | `scan_type` | Base | Produz |
| --- | --- | --- | --- |
| `dns` (`DnsAdapter`) | discovery | `dnspython` | Registros A/AAAA/MX/NS/TXT do domínio |
| `port-discovery` (`PortDiscoveryAdapter`) | discovery | `socket` + banner grab | Portas TCP abertas; produto/versão via `banners.py` quando o serviço bannerriza |
| `udp-probe` (`UdpProbeAdapter`) | discovery | `socket` UDP | Serviços UDP leves (DNS/NTP/SNMP/NetBIOS/mDNS — `data/udp_probes.py`) |
| `subdomain-enum` (`SubdomainAdapter`) | discovery | `dnspython` + crt.sh (CT logs) | Subdomínios via wordlist e Certificate Transparency; cada candidato revalidado contra o escopo antes de resolver |
| `zone-transfer` (`ZoneTransferAdapter`) | discovery | `dnspython` (`dns.query.xfr`) | Finding `category=dns` (severity `high`) se AXFR for aceito; hosts/registros vazados |
| `email-security` (`EmailSecurityAdapter`) | discovery | `dnspython` + `dns_analysis.py` | Finding `category=email-security` — SPF/DMARC ausentes ou fracos, DKIM |
| `http-fingerprint` (`HttpFingerprintAdapter`) | fingerprint | `requests` + assinaturas (`signatures.py`) | Servidor web, linguagem, framework, CMS, frontend (`assets.Technology`) |
| `tls` (`TlsAdapter`) | fingerprint | `ssl` (stdlib) + `cryptography` | Versão/cipher TLS negociados (`Technology`) **e** findings `category=tls`/`certificate` (`tls_analysis.py`) |
| `cve-lookup` (`CveLookupAdapter`) | vulnerability | API NVD CVE 2.0 (`cve.py`) | Findings `category=software` — correlação de CVE por CPE (fallback keyword) |
| `default-creds` (`DefaultCredsAdapter`) | vulnerability | `ftplib`/`requests`/sockets | Finding `category=credential` — só em `intensity=aggressive` |
| `web-scan` (`WebScanAdapter`) | vulnerability | `requests` + `web/*.py` | Findings `web-headers`/`cookie`/`cors`/`exposure`/`http-method`/`injection` |

`ADAPTERS_BY_SCAN_TYPE` mapeia `discovery`→6 adapters, `fingerprint`→2, `vulnerability`→3, `full`→todos os 11. `options["enabled_checks"]` filtra esse conjunto por `adapter.name` quando informado.

> **TLS & certificados**: `TlsAdapter` força cada versão TLS individualmente (`minimum_version`/`maximum_version`) para enumerar os protocolos aceitos e decodifica o certificado via `cryptography.x509`. `tls_analysis.py` (puro) aplica 8 regras: protocolo obsoleto, cipher fraco, certificado expirado/ainda-não-válido/expirando em <30 dias, self-signed, SAN ausente, hostname mismatch (com suporte a wildcard de 1 label), chave RSA/DSA fraca (<2048 bits) e assinatura com hash fraco (sha1/md5).
>
> **DNS & subdomínios**: `SubdomainAdapter` combina wordlist curada (`data/subdomains.py`) com Certificate Transparency (crt.sh); `ZoneTransferAdapter` tenta AXFR nos NS do domínio (read-only — não altera a zona) e reporta como finding de alta severidade quando aceito; `EmailSecurityAdapter` analisa SPF (`+all`/`?all` fracos), DMARC (`p=none`) e presença de DKIM. Registros DNS não-host (MX/NS/TXT/SOA/SRV) são persistidos em `assets.DnsRecord`.
>
> **Testes ativos web**: `WebScanAdapter` orquestra, por porta HTTP(S) comum (80/8080/443/8443): headers de segurança e cookies (`web/passive.py`), CORS, exposição de paths sensíveis com **baseline diffing** contra um path aleatório-inexistente (`web/exposure.py`, evita falso positivo em servidor "soft 404"), métodos HTTP (`OPTIONS`/`TRACE` — nunca PUT/DELETE ativos, `web/methods.py`), crawl BFS same-origin (`web/crawler.py`) e detecção de injeção (`web/injection.py`: XSS refletido, SQLi error/boolean-based, path traversal, open redirect, SSTI, command injection, e SQLi/cmdi time-based só em `aggressive`) — até `MAX_INJECTION_POINTS=15` pontos únicos por origem.
>
> **Credenciais default**: `DefaultCredsAdapter` só roda em `intensity=aggressive`, com revalidação de escopo extra, e só testa portas **já confirmadas abertas** pela fase de discovery do mesmo scan (nunca abre conexão às cegas): FTP anônimo, Redis sem auth, Elasticsearch aberto, HTTP Basic com credenciais default (só se o endpoint já desafiar com 401) e Spring Boot Actuator exposto.
>
> **Vulnerability Assessment (CVE)**: o `CveLookupAdapter` **não varre a rede** — lê o technology profile já persistido do ativo (`Service.product`/`version` e `Technology.name`/`version`) e consulta a API NVD CVE 2.0. Tenta primeiro `virtualMatchString` no formato CPE 2.3 (`cve.py:build_cpe_match` — `cpe:2.3:a:*:<produto>:<versão>:*`, vendor coringa por não haver dicionário produto→vendor mantido), que casa contra o dicionário oficial de produtos da NVD e reduz falso-positivo; se não encontrar nada, cai para `keywordSearch="<produto> <versão>"` (busca livre). A métrica CVSS mais recente disponível é escolhida (v3.1 > v3.0 > v2 — `cve.py:_best_metric`) e a severidade é derivada do `baseSeverity` da NVD ou, na ausência dele, dos limiares padrão de CVSS (RN004). Respeita rate limit via `NVD_REQUEST_DELAY_SECONDS` (padrão 6s sem `NVD_API_KEY`) e nunca deriva técnicas de exploração — apenas correlação informativa de versão × CVE.
>
> **Protocolo não é produto (correção de falso positivo)**: só entram como candidato a lookup de CVE as tecnologias de categorias que identificam um produto de software real (`PRODUCT_TECHNOLOGY_CATEGORIES` em `adapters.py`: `os`/`web-server`/`framework`/`language`/`frontend`/`cms`/`database`). A categoria `tls` fica **de fora de propósito** — é o protocolo negociado (`Technology(category="tls", name="TLS", version="TLSv1.3")`), não uma implementação identificável. Antes desta exclusão, essa entrada virava candidata: o CPE match falhava (não existe fornecedor "tls" no dicionário da NVD) e caía no fallback `keywordSearch="TLS TLSv1.3"`, uma busca livre que casa qualquer CVE cujo texto apenas **mencione** TLS 1.3 como pré-requisito — ex.: CVEs específicas de wolfSSL 4.0.0, Apache 2.4.37/38+mod_ssl, F5 BIG-IP ou OpenSSL 3.0.0–3.0.2 com configuração de cipher específica, nenhuma delas confirmável só por saber que o alvo negocia TLS 1.3. `CveLookupAdapter._collect_products` filtra por essa allowlist antes de qualquer chamada à NVD — os achados de protocolo/certificado do próprio `TlsAdapter` (`tls_analysis.py`, category `tls`/`certificate`) continuam existindo normalmente, só não alimentam mais o lookup de CVE por produto.
>
> **Pipeline em duas fases**: como o `CveLookupAdapter`/`DefaultCredsAdapter`/`WebScanAdapter` dependem de dados que os adapters de discovery/fingerprint descobrem, `tasks.run_scan` executa e **persiste** primeiro os adapters de profile (por host) e só então roda os de vulnerabilidade — mesmo dentro de um único scan `full`.

## Suporte IPv4/IPv6

O motor é dual-stack por design — alvos IPv6 (literais ou hosts IPv6-only) são varridos como qualquer alvo IPv4:

- **Validação e escopo** (`validators.py`/`authorization.py`/`targets.py`) já usam o módulo `ipaddress` da stdlib de forma agnóstica a versão — `ip_address`/`ip_network` reconhecem v4 e v6 automaticamente, inclusive na expansão de CIDR (`expand_target`, RN017) e no matching de escopo (RN007).
- **Resolução de host** (`adapters._resolve_ip`): usa `socket.getaddrinfo` (não `socket.gethostbyname`, que é IPv4-only e nunca enxergava registros `AAAA`). IPs literais passam direto, sem round-trip de DNS; quando um host resolve para as duas famílias, IPv4 é preferido (compatibilidade com o inventário existente); IPv6 é usado quando é a única opção.
- **Probes de socket puro** (`PortDiscoveryAdapter`/`UdpProbeAdapter`): a família do socket (`AF_INET`/`AF_INET6`) é escolhida dinamicamente a partir da versão do IP resolvido (`adapters._address_family`) — antes era travada em `AF_INET`, rejeitando qualquer conexão a um IP v6.
- **URLs HTTP** (`HttpFingerprintAdapter`, `WebScanAdapter`, `DefaultCredsAdapter`): um IPv6 literal usado como alvo precisa de colchetes em URL (RFC 3986: `http://[2001:db8::1]:8080/`, nunca `http://2001:db8::1:8080/`, ambíguo). `adapters._url_host` cuida disso antes de qualquer `f"http://{host}:{port}"`.
- **TLS** (`TlsAdapter`) e **DNS** (`dnspython`, usado por `DnsAdapter`/`SubdomainAdapter`/`ZoneTransferAdapter`/`EmailSecurityAdapter`) já eram dual-stack — `socket.create_connection` e dnspython resolvem a família correta sozinhos a partir do endereço.
- **Banco**: `Asset.ip` é `GenericIPAddressField` sem restrição de protocolo — aceita v4 e v6 nativamente.

### Docker (dev e produção)

A rede bridge padrão do Compose é **IPv4-only** — sem isso, o `celery`/`web` nunca conseguem abrir uma conexão IPv6 de saída, mesmo com o código acima correto. `docker-compose.yml`/`docker-compose.prod.yml` declaram uma rede dual-stack (`enable_ipv6: true` + sub-rede IPv6 ULA). Isso sozinho **não é suficiente** para o container alcançar a internet IPv6 real — também é preciso, no host:

1. Docker Engine ≥ 27 com `"ip6tables": true` em `/etc/docker/daemon.json` (reinicie o daemon depois de editar) — habilita o NAT66 automático para a rede bridge.
2. O próprio host ter conectividade IPv6 de saída (nem todo VPS tem — confirme com `curl -6 https://ifconfig.co` **no host**, fora de qualquer container, antes de assumir que vai funcionar dentro dele).

Verificação de ponta a ponta (depois de 1 e 2):
```bash
docker compose exec celery python -c "import socket; print(socket.getaddrinfo('ipv6.google.com', 443))"
```
Se isso resolver e não levantar `OSError`, o container tem saída IPv6 funcional.

## Estrutura de Findings

Campos obrigatórios (RN008/RN019 — nenhum finding sem contexto, validado no próprio modelo):
`id`, `asset`, `category`, `title`, `severity`, `cvss`, `description`, `evidence`, `recommendation`, `dedup_key`.

Severidade: `critical` · `high` · `medium` · `low` · `info`.

Categoria (`FindingCategory`, 15 valores): `software` · `service` · `network` · `credential` · `tls` · `certificate` · `dns` · `email-security` · `subdomain` · `web-headers` · `cookie` · `cors` · `exposure` · `http-method` · `injection`.

## Performance
- Meta: até **100 ativos simultâneos**.
- Processamento assíncrono e **escalabilidade horizontal** de workers.
- Rate limiting (`options["rate_delay"]`) e concorrência limitada por alvo (`options["max_workers"]`) — profissional e evita virar DoS acidental.

## Histórico
Nenhum scan é sobrescrito (RN003). Todos os resultados permanecem disponíveis para auditoria.

## Correlation Engine (Risk Score)

Transforma findings em risco de negócio: agrupa por ativo/ambiente, prioriza automaticamente e agrupa por criticidade e categoria. Implementado em `apps/scans/correlation.py` (regras puras, sem I/O) e exposto via `GET /api/risk/overview/` (`apps/scans/views.py:RiskOverviewView`).

**Decisão de design**: o risco **não é persistido** — é recomputado a cada requisição a partir dos `Finding` já salvos. Como `Finding` é imutável por scan (RN003/RN005), qualquer leitura de risco já reflete exatamente o estado atual sem precisar de invalidação de cache ou de um job de recálculo assíncrono.

### Fórmula do `risk_score` (0–100)

Para um conjunto de findings (de um ativo ou do ambiente inteiro):

```
peso(finding) = finding.cvss se disponível, senão um score-equivalente por severidade:
                critical → 9.5 · high → 8.0 · medium → 5.5 · low → 2.0 · info → 0.0

risk_score = min(100, soma dos pesos dos findings NÃO triados como resolvidos)
```

A soma cresce com a **quantidade e a gravidade** dos findings, mas satura em 100 — um único finding crítico não deveria (e não deve) levar o score ao máximo; são necessários vários findings graves acumulados. `risk_level` classifica o score na mesma banda usada para CVSS, só que ×10 (`cve.severity_bucket`, escalado):

| risk_score | risk_level |
| --- | --- |
| ≥ 90 | `critical` |
| ≥ 70 | `high` |
| ≥ 40 | `medium` |
| > 0 | `low` |
| 0 | `info` |

### Dedup & triagem (RN018)

Reexecutar o mesmo scan sobre o mesmo alvo cria **novos** registros de `Finding` para o "mesmo" achado (RN003 — imutabilidade nunca é violada), o que inflaria o `risk_score` aditivo a cada rodada. Para resolver isso sem quebrar a imutabilidade:

- `Finding.dedup_key` (`parsers.compute_dedup_key`) é um hash estável de `asset + category + título normalizado` — todo `Finding` que representa o "mesmo achado lógico" em execuções distintas compartilha o mesmo `dedup_key`, mesmo sendo linhas diferentes.
- `FindingTriage` é uma camada **mutável separada**, chaveada por `dedup_key` (único), com `status` ∈ `open` \| `fixed` \| `false-positive` \| `accepted-risk`, nota e autor. Triar um achado (`POST /api/findings/{id}/triage/`, analyst/admin, RN011) afeta **todos** os `Finding` passados e futuros com aquele `dedup_key` — sem jamais reescrever o histórico.
- `compute_risk`/`compute_asset_risk`/`compute_heatmap` aceitam `excluded_dedup_keys` (resolvido pela view, que consulta `FindingTriage` — `correlation.py` continua livre de I/O) e excluem da soma os achados triados como `fixed`/`false-positive`/`accepted-risk`. O `risk_score` passa a refletir **risco aberto e único**, não a contagem bruta de execuções.

### Saídas

- **Priorização automática**: `top_assets` — risk assessment por ativo, ordenado por `risk_score` decrescente.
- **Agrupamento por criticidade**: `summary.severity` — contagem de findings do ambiente por severidade.
- **Heatmap**: `heatmap` — contagem de findings por `(category, severity)`, com `category_label` (rótulo PT-BR pronto para a UI, `correlation.CATEGORY_LABELS`).
