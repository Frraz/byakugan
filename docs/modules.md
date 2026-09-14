# Especificação de Módulos

> Cada módulo corresponde a um app Django (`backend/apps/<módulo>`) e/ou área do frontend. Entradas → processamento → saídas.

## Accounts (Autenticação & Usuários)
- **Responsabilidade:** identidade, JWT, RBAC.
- **Entrada:** credenciais.
- **Saída:** tokens, perfil, permissões.
- **Depende de:** —.

## Core
- **Responsabilidade:** `BaseModel`, health check, logging estruturado, utilidades transversais, auditoria.
- **Saída:** infraestrutura compartilhada usada por todos os módulos.

## Assets (Asset Discovery)
- **Responsabilidade:** inventário de ativos e serviços descobertos.
- **Entrada:** resultados do Discovery Module.
- **Saída:** `assets`, `services`.
- **Depende de:** Scans (adapters).

## Scans (Scanning Engine + Exploitation Engine)
- **Responsabilidade:** criar, validar, enfileirar e orquestrar scans; scanner adapters (detecção); classificação e cobertura OWASP; e o motor de exploração (prova de impacto).
- **Entrada:** requisição de scan (alvo + autorização).
- **Saída:** estados do scan, resultados brutos → parsers; findings classificados no OWASP 2021/2025 + CWE; `Evidence` de exploração.
- **Depende de:** Celery/Redis, Assets.
- **Submódulos-chave:**
  - `adapters.py` + `web/` — detecção não-destrutiva (RN016), 11 adapters, 18 categorias.
  - `owasp.py` / `owasp_coverage.py` — taxonomia fonte única (RN024) + matriz de cobertura por scan.
  - `exploit/` — motor de exploração: contrato `ExploitModule` por `playbook_key` (`registry.py`), orquestração com gating (`runner.py`) e piso de não-dano central no seam de rede (`base.py`) — RN021–RN023.
  - `correlation.py` — risk score, priorização, heatmap; `parsers.py` — normalização/persistência + enriquecimento OWASP.

## Vulnerabilities (Vulnerability Assessment)
- **Responsabilidade:** catálogo de vulnerabilidades e findings por ativo.
- **Entrada:** technology profile + base CVE (NVD).
- **Saída:** `findings`, `vulnerabilities`.
- **Depende de:** Assets, Scans.

## Correlation (Correlation Engine)
- **Responsabilidade:** risk score, priorização, agrupamento, heatmaps.
- **Entrada:** findings.
- **Saída:** risk assessment por ativo/ambiente.
- **Depende de:** Vulnerabilities.

## Reporting
- **Responsabilidade:** relatórios executivo/técnico (PDF/CSV/JSON) com rastreabilidade.
- **Entrada:** scan + findings + risco.
- **Saída:** `reports` (artefatos).
- **Depende de:** Scans, Correlation.

## Knowledge Base
- **Responsabilidade:** conteúdo explicativo e de remediação por vulnerabilidade.
- **Saída:** descrição, impacto, referências, mitigações.

## AI Assistant
- **Responsabilidade:** explicar/resumir/recomendar sobre dados coletados.
- **Entrada:** findings, KB, histórico.
- **Saída:** respostas estruturadas (ver `ai-assistant.md`).
- **Depende de:** Vulnerabilities, Correlation, Knowledge Base.

## Dashboard
- **Responsabilidade:** visão executiva e técnica consolidada.
- **Entrada:** assets, findings, risco.
- **Saída:** KPIs, tabelas, heatmaps (frontend).

## Mapa de dependências (alto nível)
```
Core ← (todos)
Accounts ← (todos, via auth)
Scans → Assets
Scans(Detecção) → Findings → OWASP (classificação 2021/2025 + CWE)
Findings → Exploitation → Evidence (gated, RoE)
Findings → Correlation → Risk + Cobertura OWASP → Reporting
Findings, Correlation, Evidence, KnowledgeBase → AI Assistant (planejado)
Assets, Findings, Correlation, Cobertura OWASP → Dashboard
```
