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

## Scans (Scanning Engine)
- **Responsabilidade:** criar, validar, enfileirar e orquestrar scans; scanner adapters.
- **Entrada:** requisição de scan (alvo + autorização).
- **Saída:** estados do scan, resultados brutos → parsers.
- **Depende de:** Celery/Redis, Assets, Vulnerabilities.

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
Scans → Assets, Vulnerabilities
Vulnerabilities → Correlation → Reporting
Vulnerabilities, Correlation, KnowledgeBase → AI Assistant
Assets, Vulnerabilities, Correlation → Dashboard
```
