# Reporting

> Relatórios são rastreáveis ao scan de origem (RN005) e imutáveis após gerados (RN003). Formatos: PDF, CSV, JSON.

## Tipos de relatório

### Relatório Executivo
Público: gestores. Linguagem de negócio, foco em risco e ação.

Conteúdo:
- Resumo do escopo (ativos analisados, período, alvo autorizado).
- **Risk Score geral** e classificação (ex.: Alto).
- Distribuição de severidade:
  ```
  Ativos analisados: 150
  Críticas: 5   Altas: 18   Médias: 32   Baixas: 45
  Risco Geral: Alto
  ```
- Top riscos priorizados e recomendação de ação.
- Heatmap por categoria (infra, aplicações, banco, cloud).

### Relatório Técnico
Público: analistas. Detalhe e evidência.

Conteúdo:
- Inventário de ativos e serviços.
- Lista completa de findings com: título, severidade, CVSS, descrição, **evidência**, **recomendação**, referências (CVE/links).
- Logs relevantes e metadados do scan.
- Passos de remediação (integração com Knowledge Base).

## Estrutura de dados do relatório (payload base)

```json
{
  "scan_id": "...",
  "generated_at": "2026-08-12T12:00:00Z",
  "target": "empresa.com",
  "summary": {
    "assets": 150,
    "severity": { "critical": 5, "high": 18, "medium": 32, "low": 45, "info": 10 },
    "risk_score": 82,
    "risk_level": "high"
  },
  "findings": [
    {
      "asset": "web-01 (192.168.0.10)",
      "title": "TLS 1.0 habilitado",
      "severity": "medium",
      "cvss": 5.9,
      "evidence": "Handshake aceitou TLS 1.0 na porta 443",
      "recommendation": "Desabilitar TLS 1.0 e 1.1; exigir TLS 1.2+"
    }
  ]
}
```

## Geração
- **PDF**: template renderizado (ex.: WeasyPrint/ReportLab) a partir do payload.
- **CSV**: uma linha por finding (para importação em planilhas/SIEM).
- **JSON**: payload completo (integração com outras ferramentas).

## Regras
- Rastreabilidade obrigatória ao `scan` (RN005).
- Relatórios não são editados após criação; nova versão = novo relatório.
- Exportação é auditada (RN011).
- Só é possível gerar relatório de um scan com status `completed` (RN012) — evita relatório com dados parciais.

## Implementação (Fase 5)

`apps/reports` — `payload.py` monta o payload acima reaproveitando o Correlation Engine (`apps.scans.correlation`) para `risk_score`/`risk_level`/`heatmap`, garantindo que o número mostrado no relatório seja **exatamente** o mesmo do dashboard. `rendering.py` gera os três formatos: JSON (payload completo), CSV (uma linha por finding, via `csv.DictWriter`) e PDF (via `reportlab` — puro Python, sem dependência de sistema como Pango/Cairo). `services.generate_report` grava o artefato em `MEDIA_ROOT/reports/<uuid>.<ext>` e cria o registro `Report`; nunca é servido por URL estática — só via `GET /api/reports/{id}/download/` (autenticado + auditado).

**Diferenças por `report_type`**: o executivo inclui `top_risks` (ativos priorizados) e `heatmap`; o técnico inclui `assets` (inventário), `findings` (lista completa) e, desde a Fase 6, `knowledge_articles` — os artigos da Knowledge Base relacionados às categorias dos findings do scan (um artigo por categoria distinta, sem repetição — ver `apps.reports.payload.build_related_knowledge`). O CSV ignora `report_type` e `knowledge_articles` — é sempre a lista de findings.

**Não implementado ainda**: logs brutos do scan no relatório técnico (hoje traz metadados — tipo, status, autorização, timestamps — mas não logs linha a linha).
