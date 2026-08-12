# Scanning Engine

> Núcleo responsável por executar análises, normalizar resultados e alimentar o motor de correlação. Todo trabalho pesado roda de forma **assíncrona** (Celery).

## ⚠️ Política de Autorização de Alvos

**Nenhum scan é executado sem autorização registrada.** Antes de enfileirar, o sistema exige:
- `authorized_by` — quem autorizou (nome/papel).
- `authorization_scope` — o escopo permitido (domínios, IPs, sub-redes).

O alvo do scan é validado contra o escopo. Varredura fora do escopo ou sem autorização é bloqueada e auditada. O Byakugan **não** deve ser usado contra terceiros sem permissão explícita — isso é ilegal.

### Enforcement de escopo (implementação)
Antes de enfileirar, o serviço `create_scan` valida o formato do alvo (RN001) e verifica se o alvo está **contido no `authorization_scope`** (`apps/scans/authorization.py`). Fora do escopo → `400`/`403` + registro de auditoria. Um alvo cadastrado (`Target`) já carrega sua autorização; scans que o referenciam a herdam.

### Kill-switch global (protótipo)
O Byakugan é um protótipo de uso restrito. A execução real de varredura é controlada pela env **`BYAKUGAN_SCANNING_ENABLED`** (default **desligado**). Com o switch desligado, o scan é registrado mas **não executa varredura real** — falha de forma controlada com motivo auditado. Isso evita varredura acidental fora de um laboratório autorizado.

## Arquitetura

```
Scan Request → Validação → Fila (Celery) → Workers → Adapters → Parsers → DB → Correlation Engine
```

## Fluxo de execução

### 1. Criação
O usuário cria um scan informando alvo (host único, domínio ou lista de IPs), tipo e autorização.

### 2. Validação
Valida formato do alvo (RN001), duplicidade (RN002 → `409`), permissões (RBAC) e autorização (RN007).

### 3. Enfileiramento
O scan é enviado ao Celery. Máquina de estados (RN010):

```
pending → running → completed
                 ↘ failed
                 ↘ cancelled
```

### 4. Execução
Workers executam módulos independentes via **scanner adapters**:

- **Discovery Module** → hosts, DNS, subdomínios, serviços → *Asset Inventory*.
- **Fingerprint Module** → OS, frameworks, servidores, tecnologias → *Technology Profile*.
- **Vulnerability Module** → busca CVE, CVSS, correlação de versões → *Findings*.
- **Correlation Module** → agrupa, deduplica, prioriza → *Risk Assessment*.

## Scanner Adapters (integração real progressiva)

Cada capacidade de varredura é encapsulada num **adapter** que implementa uma interface comum. Isso permite:
- Começar com integrações reais simples e ir adicionando outras sem tocar no orquestrador.
- Trocar/mockar adapters por configuração (útil para testes e demonstrações sem alvos reais).

Interface (esqueleto — ver `backend/apps/scans/adapters.py`):

```python
class ScannerAdapter(ABC):
    name: str
    scan_type: str  # discovery | fingerprint | vulnerability

    @abstractmethod
    def run(self, target: str, context: ScanContext) -> list[RawResult]:
        """Executa a varredura e retorna resultados brutos para o parser."""
```

Adapters previstos (evolução progressiva):
| Adapter | Base | Fase |
| --- | --- | --- |
| `PortDiscoveryAdapter` | socket/`python-nmap` | 1 ✅ |
| `DnsAdapter` | `dnspython` | 1 ✅ |
| `HttpFingerprintAdapter` | `requests` + assinaturas (`signatures.py`) | 2 ✅ |
| `TlsAdapter` | `ssl` (stdlib) — versão/cipher negociado | 2 ✅ |
| `CveLookupAdapter` | API NVD CVE 2.0 (`cve.py`) | 3 ✅ |

> **Fingerprinting (Fase 2)**: o `HttpFingerprintAdapter` faz GET às portas HTTP(S) comuns e deriva servidor web, linguagem, framework, CMS e frontend a partir de headers (`Server`, `X-Powered-By`, cookies) e assinaturas no HTML. O `TlsAdapter` negocia TLS (stdlib `ssl`) e reporta a versão do protocolo (protocolos obsoletos ficam registrados na evidência). Ambos produzem `RawResult(kind="technology")`, normalizados em `assets.Technology` — o *technology profile* do ambiente.

> **Vulnerability Assessment (Fase 3)**: o `CveLookupAdapter` **não varre a rede** — lê o technology profile já persistido do ativo (`Service.product`/`version` e `Technology.name`/`version`) e consulta a API NVD CVE 2.0 por palavra-chave (`keywordSearch="<produto> <versão>"`) para cada par produto/versão único, limitado a `NVD_MAX_RESULTS` CVEs por produto. A métrica CVSS mais recente disponível é escolhida (v3.1 > v3.0 > v2 — `cve.py:_best_metric`) e a severidade é derivada do `baseSeverity` da NVD ou, na ausência dele, dos limiares padrão de CVSS (RN004). Respeita rate limit via `NVD_REQUEST_DELAY_SECONDS` (padrão 6s sem `NVD_API_KEY`) e nunca deriva técnicas de exploração — apenas correlação informativa de versão × CVE, com uma recomendação genérica de atualização.
>
> **Pipeline em duas fases**: como o `CveLookupAdapter` depende de dados que os demais adapters descobrem, `tasks.run_scan` executa e **persiste** primeiro os adapters de discovery/fingerprint (`scan_type != "vulnerability"`) e só então roda os adapters de vulnerabilidade — mesmo dentro de um único scan `full`. Isso garante que o CVE lookup sempre veja o profile mais recente do próprio scan, não apenas de execuções anteriores.

> Boas práticas: timeouts, rate limiting por alvo, concorrência controlada e respeito a `robots`/janela autorizada. Nunca embutir técnicas cujo propósito primário seja evasão maliciosa.

## Estrutura de Findings

Campos obrigatórios (RN008 — nenhum finding sem contexto):
`id`, `asset`, `category`, `title`, `severity`, `cvss`, `description`, `evidence`, `recommendation`.

Severidade: `critical` · `high` · `medium` · `low` · `info`.

## Performance
- Meta: até **100 ativos simultâneos**.
- Processamento assíncrono e **escalabilidade horizontal** de workers.

## Histórico
Nenhum scan é sobrescrito (RN003). Todos os resultados permanecem disponíveis para auditoria.
