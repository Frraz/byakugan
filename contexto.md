Observação, esse arquivo conteé informações importantes sobre o contexto do projeto. Certifique-se de ler atentamente para compreender todos os detalhes relevantes.

Aqui vou colar trechos de uma conversa minha com o cha GPT, onde eu estava planejando o projeto. Não use tudo como regra absoluta, pois algumas ideias podem ter mudado ao longo do tempo. No entanto, esses trechos fornecem uma visão geral do raciocínio por trás das decisões tomadas.

Com base nisso tudo vamos fazer o melhor projeto de Cybersecurity possível, levando em consideração as melhores práticas, ferramentas e metodologias disponíveis. O objetivo é criar um ambiente seguro e resiliente, capaz de proteger dados sensíveis e mitigar riscos de ameaças cibernéticas.

Conversa:
################################################################################################################################################################################################
Prompt inicial:
Me ajude a planejar um sistema chamado byakugan. É para um projeto da minha faculdade de segurança cibernética (FIAP) onde eu terei que desenvolver uma ferramenta de análise/exporação de servidores e serviços web. essa ferramenta deverá funcionar como um canivete suiço e fazer uma análise completa do alvo ou dos alvos. deverá ser como se fosse um compilado de burp suite, hyndra, John the Ripper , nmap, metasploit zmanp, Wireshark, Nessus, OpenVAS. Burp Suite, OWASP ZAP, Metasploit , Hashcat  , **sqlmap**  **Armitage**  e etc.


essa ferramenta chamada Byakugan deve te vários tipos de análies, desde o mais simples e até mesmo o mais avançado, e trazer todos os resultados, resumos, resulatados inteiros e etc em uma interface amigável.

o objetivo aqui é criar uma ferramenta que descomplique todas as demais ferramentas e reuna tudo em um só lugar para facilitar o trabalhos dos soc na identificação de vunerabilidades da empresa, também essa ferramenta deverá de alguma forma instruir ou pelo menos dá algum norte para a correção de tais vunerabilidaes.


################################################################################################################################################################################################
Primeira resposta:
A ideia do Byakugan é muito boa para um projeto acadêmico de Segurança Cibernética, principalmente se você posicionar a ferramenta como uma plataforma de Security Assessment, Asset Discovery e Vulnerability Management, e não como uma ferramenta de exploração ofensiva automática.

Isso é importante porque, em ambientes corporativos reais, o maior valor normalmente não está em "explorar tudo", mas sim em:

Descobrir ativos.
Identificar vulnerabilidades.
Correlacionar riscos.
Priorizar correções.
Gerar evidências.
Auxiliar equipes SOC, Blue Team e GRC.
Visão Geral do Projeto
Nome

Byakugan

Inspirado no anime Naruto.

O Byakugan enxerga tudo ao redor.

A ferramenta teria a mesma proposta:

"Ver tudo o que existe dentro de uma infraestrutura e revelar riscos ocultos."

Objetivo Principal

Criar uma plataforma centralizada que permita:

Descoberta de ativos
Inventário de serviços
Mapeamento de rede
Identificação de vulnerabilidades
Análise de aplicações web
Correlação de riscos
Relatórios executivos
Relatórios técnicos
Recomendações de correção

Tudo em uma única interface.

Público-Alvo
Analistas SOC
Blue Team
Pentesters autorizados
Consultorias de Segurança
Equipes DevSecOps
Equipes de Infraestrutura
Estudantes
Filosofia do Produto

Em vez de competir diretamente com:

Nmap
Burp Suite
OWASP ZAP
Metasploit
OpenVAS
Wireshark

o Byakugan seria um:

Security Orchestration Layer

Uma camada de orquestração que integra ferramentas existentes.

Isso reduz:

Complexidade
Curva de aprendizado
Tempo de análise
Arquitetura Geral
Frontend
│
├── Dashboard
├── Assets
├── Vulnerabilities
├── Scans
├── Reports
└── Knowledge Base

Backend API
│
├── Asset Engine
├── Scan Engine
├── Correlation Engine
├── Risk Engine
├── Reporting Engine
└── AI Assistant

Workers
│
├── Network Worker
├── Web Worker
├── DNS Worker
├── SSL Worker
├── OSINT Worker
└── Vulnerability Worker

Database
│
├── Assets
├── Findings
├── Vulnerabilities
├── Reports
└── Historical Data
Módulo 1 — Asset Discovery

Primeira etapa.

Descobrir tudo.

Descoberta de Hosts

Identificar:

IPs
Hosts
Sub-redes
Gateways

Resultado:

192.168.0.10
192.168.0.15
192.168.0.20
Descoberta DNS

Mapear:

Domínios
Subdomínios
DNS Records

Exemplo:

empresa.com

A
MX
TXT
SPF
DKIM
Descoberta de Serviços

Identificar:

22 SSH
80 HTTP
443 HTTPS
3306 MySQL
5432 PostgreSQL
Módulo 2 — Fingerprinting

Identificar tecnologias.

Sistema Operacional

Exemplo:

Ubuntu 24.04
Windows Server 2025
Debian 13
Frameworks

Identificar:

Django
Laravel
Spring
ASP.NET
React
Angular
Vue
Servidores Web

Identificar:

Apache
Nginx
IIS
Caddy
Módulo 3 — Web Application Assessment

Análise de aplicações web.

Headers

Verificar:

CSP
HSTS
X-Frame-Options
X-Content-Type
Cookies

Verificar:

HttpOnly
Secure
SameSite
SSL/TLS

Analisar:

Certificados
Cifras
Protocolos
Expiração
Autenticação

Detectar:

MFA
SSO
OAuth
OpenID Connect
Módulo 4 — Vulnerability Correlation

Este é o coração do sistema.

Base CVE

Relacionar:

Software
Versão
CVE

Exemplo:

Apache 2.4.48

CVE-2024-XXXXX
CVSS 9.8
CVSS

Calcular:

Crítico
Alto
Médio
Baixo
Priorização

Combinar:

CVSS
Exposição
Ativo crítico
Módulo 5 — Risk Engine

Transformar dados técnicos em risco.

Exemplo:

10 vulnerabilidades críticas

Risco Geral: Alto
Heatmap
Infraestrutura
Aplicações
Banco de Dados
Cloud
Módulo 6 — Knowledge Base

Cada vulnerabilidade possui:

Explicação
Impacto
Evidências
Referências
Correções

Exemplo:

Vulnerabilidade:
TLS 1.0 habilitado

Impacto:
Criptografia obsoleta

Correção:
Desabilitar TLS 1.0 e TLS 1.1
Módulo 7 — Relatórios
Executivo

Para gestores.

Exemplo:

Ativos analisados: 150

Críticas: 5
Altas: 18
Médias: 32
Baixas: 45

Risco Geral: Alto
Técnico

Para analistas.

Contendo:

Evidências
Logs
Screenshots
Detalhes técnicos
Módulo 8 — Dashboard

Tela principal.

Assets..................245
Critical.................7
High....................22
Medium..................55

Risk Score.............82/100
Módulo 9 — IA Integrada

Uma funcionalidade muito interessante para a FIAP.

A IA poderia:

Explicar vulnerabilidades

Exemplo:

Explique CVE-2025-XXXX
Gerar correções

Exemplo:

Como corrigir Apache 2.4.48?
Gerar relatórios

Transformar findings técnicos em linguagem executiva.

Stack Recomendada (2026)

Como você já vem estudando Python e React, eu seguiria:

Frontend
React
TypeScript
Vite
Tailwind
Shadcn/UI
Backend
Python
Django
Django REST Framework
Workers
Celery
Redis
Banco
PostgreSQL
Busca
Elasticsearch ou OpenSearch
Mensageria
RabbitMQ
Containers
Docker
Docker Compose
Diferencial para a banca da FIAP

Em vez de apresentar o Byakugan como:

"Uma ferramenta que faz pentest."

Apresente como:

"Uma plataforma inteligente de descoberta de ativos, análise de exposição, gestão de vulnerabilidades e apoio à remediação para equipes SOC."

Isso deixa o projeto mais alinhado com segurança defensiva, governança e gestão de riscos, além de ser tecnicamente mais viável para um projeto acadêmico.

Uma evolução interessante seria dividir o desenvolvimento em fases:

Asset Discovery
Fingerprinting
Vulnerability Assessment
Correlation Engine
Reporting Engine
IA para explicação e remediação
Dashboards executivos e SOC

Assim você consegue entregar um MVP sólido e ainda mostrar uma visão de produto que poderia evoluir para algo próximo de plataformas comerciais como Tenable Nessus, Qualys VMDR e Rapid7 InsightVM, mas com foco em simplicidade e experiência de uso.


################################################################################################################################################################################################
Segundo prompt:

agora com base nisso, me ajude a montar os seguintes arquivos:





| `CLAUDE.md` | Instruções gerais do projeto, convenções e regras permanentes. |
| ----------- | -------------------------------------------------------------- |

| `README.md` | Visão geral do sistema, como instalar, executar e contribuir. |
| ----------- | ------------------------------------------------------------- |

| `docs/architecture.md` | Arquitetura, módulos, tecnologias e fluxo da aplicação. |
| ---------------------- | ------------------------------------------------------- |

| `docs/requirements.md` | Requisitos funcionais e não funcionais. |
| ---------------------- | --------------------------------------- |

| `docs/database.md` | Modelo de dados, tabelas, relacionamentos e migrações. |
| ------------------ | ------------------------------------------------------ |

| `docs/api.md` | Endpoints, contratos, autenticação e exemplos. |
| ------------- | ---------------------------------------------- |

| `docs/rules.md` | Regras de negócio detalhadas. |
| --------------- | ----------------------------- |

| `docs/tasks.md` | Lista de funcionalidades, backlog e progresso. |
| --------------- | ---------------------------------------------- |

| `docs/ui.md` | Padrões de interface, componentes e identidade visual. |
| ------------ | ------------------------------------------------------ |

| `docs/testing.md` | Estratégia de testes, cobertura e padrões. |
| ----------------- | ------------------------------------------ |

| `.env.example` | Variáveis de ambiente necessárias. |
| -------------- | ---------------------------------- |





gere eles da melhor maneira possível para que o claude code consigma me ajudar a desenvolver compleamente esse projeto para a faculdade


################################################################################################################################################################################################
Reposta:
Para que o Claude Code consiga atuar como um verdadeiro arquiteto e copiloto do projeto, esses arquivos precisam funcionar como a fonte única da verdade (Single Source of Truth).

Minha recomendação é estruturar o projeto como se fosse um produto SaaS real, mesmo sendo acadêmico. Isso ajuda muito na organização e impressiona a banca da FIAP.

CLAUDE.md

Use este arquivo como o "cérebro" do projeto.

CLAUDE.md
Projeto

Nome: Byakugan

Byakugan é uma plataforma centralizada de descoberta de ativos, análise de exposição, gerenciamento de vulnerabilidades e geração de relatórios de segurança.

O objetivo é simplificar o trabalho de equipes SOC, Blue Team, DevSecOps e Analistas de Segurança por meio de uma interface única que consolida múltiplas análises de infraestrutura e aplicações web.

Objetivos do Sistema

O sistema deve:

Descobrir ativos de rede
Identificar tecnologias utilizadas
Avaliar exposição de serviços
Detectar vulnerabilidades conhecidas
Correlacionar riscos
Gerar relatórios executivos e técnicos
Auxiliar na remediação de vulnerabilidades
Manter histórico de análises
Princípios Arquiteturais
Clean Architecture
Domain Driven Design (DDD)
SOLID
API First
Security By Design
Observability First
Modular Monolith inicialmente
Preparado para Microservices futuramente
Stack Oficial
Frontend
React
TypeScript
Vite
TailwindCSS
Shadcn/UI
React Query
Zustand
Backend
Python 3.13+
Django
Django REST Framework
Celery
Redis
Banco de Dados
PostgreSQL
Busca
OpenSearch
Infraestrutura
Docker
Docker Compose
Convenções
Backend
Seguir PEP8
Type Hints obrigatórios
Docstrings obrigatórias
Services para lógica de negócio
Serializers apenas para validação
Views finas
Frontend
Componentes reutilizáveis
Hooks customizados
Separação entre UI e lógica
Não utilizar lógica de negócio em componentes
Segurança

Nunca:

Armazenar senhas em texto puro
Expor segredos em código
Desabilitar autenticação
Desabilitar logs de auditoria

Sempre:

Utilizar RBAC
Validar entradas
Registrar auditoria
Utilizar HTTPS
Estrutura de Pastas

backend/
frontend/
docs/
infra/
scripts/
tests/

Padrões de Commit

feat:
fix:
refactor:
test:
docs:
chore:

Exemplo:

feat(asset-discovery): add host scanner

Prioridade de Desenvolvimento
Autenticação
Asset Discovery
Fingerprinting
Vulnerability Assessment
Correlation Engine
Reporting
Dashboard
IA Assistente
Regra Fundamental

Toda funcionalidade deve possuir:

requisito
regra de negócio
endpoint
testes
documentação
README.md
Byakugan
Visão Geral

Byakugan é uma plataforma de Security Assessment desenvolvida para centralizar descoberta de ativos, identificação de vulnerabilidades, correlação de riscos e geração de relatórios.

O sistema foi criado como projeto acadêmico do curso de Segurança Cibernética da FIAP.

Principais Funcionalidades
Asset Discovery
Service Discovery
Fingerprinting
Vulnerability Assessment
Risk Correlation
Reporting
Dashboard Executivo
Dashboard Técnico
Assistente IA
Tecnologias
Frontend
React
TypeScript
Tailwind
Shadcn/UI
Backend
Django
DRF
Celery
Redis
Banco
PostgreSQL
Instalação
Backend
cd backend

python -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt
Banco
docker compose up postgres -d
Redis
docker compose up redis -d
Migrações
python manage.py migrate
Executar
python manage.py runserver
Frontend
cd frontend

npm install

npm run dev
Testes
pytest
Estrutura

backend/
frontend/
docs/
infra/
tests/

Licença

MIT

docs/architecture.md

Estrutura:

# Arquitetura

## Visão Geral

Frontend React
↓
API Django
↓
Services
↓
Workers Celery
↓
PostgreSQL

---

## Módulos

### Authentication

JWT
RBAC

### Asset Discovery

Hosts
DNS
Subdomínios

### Fingerprinting

OS
Frameworks
Tecnologias

### Vulnerability Assessment

CVE Engine
CVSS Engine

### Correlation Engine

Risk Score
Priorização

### Reporting

PDF
CSV
JSON

### Audit

Logs
Eventos

---

## Fluxo

Usuário
→ Cria Scan
→ Scan é enviado ao Celery
→ Worker executa análise
→ Resultados persistidos
→ Correlation Engine processa
→ Dashboard atualizado
docs/requirements.md

Estrutura:

# Requisitos

## Funcionais

RF001 - Login

RF002 - Cadastro de usuários

RF003 - RBAC

RF004 - Criar scan

RF005 - Executar scan

RF006 - Consultar scans

RF007 - Consultar ativos

RF008 - Consultar vulnerabilidades

RF009 - Gerar relatório

RF010 - Exportar relatório

RF011 - Histórico de análises

RF012 - Dashboard executivo

RF013 - Dashboard técnico

RF014 - Base de conhecimento

RF015 - Recomendações de correção

---

## Não Funcionais

RNF001 - API REST

RNF002 - Docker

RNF003 - PostgreSQL

RNF004 - Tempo de resposta < 500ms

RNF005 - Cobertura de testes > 80%

RNF006 - Logs estruturados

RNF007 - Auditoria completa

RNF008 - HTTPS obrigatório
docs/database.md

Defina:

# Database

## Users

id
email
password_hash
role

---

## Assets

id
ip
hostname
domain
status

---

## Scans

id
asset_id
status
started_at
finished_at

---

## Services

id
asset_id
port
protocol
service_name

---

## Vulnerabilities

id
asset_id
cve
severity
cvss_score

---

## Findings

id
scan_id
title
description
evidence

---

## Reports

id
scan_id
file_path
created_at

---

## AuditLogs

id
user_id
action
timestamp
docs/api.md

Defina todos os endpoints.

Exemplo:

POST /api/auth/login

POST /api/auth/register

GET /api/assets

POST /api/assets

GET /api/scans

POST /api/scans

GET /api/scans/{id}

GET /api/vulnerabilities

GET /api/reports

POST /api/reports

Além disso:

Request
Response
Status Codes
Exemplos JSON
docs/rules.md
# Regras de Negócio

RN001

Todo scan deve possuir um alvo válido.

RN002

Um scan não pode ser executado duas vezes simultaneamente.

RN003

Resultados históricos nunca podem ser apagados.

RN004

Toda vulnerabilidade deve possuir classificação CVSS.

RN005

Todo relatório deve manter rastreabilidade com o scan que o originou.

RN006

Apenas administradores podem excluir registros.
docs/tasks.md
# Backlog

## MVP

[ ] Login

[ ] RBAC

[ ] Asset Discovery

[ ] Scan Engine

[ ] Dashboard

[ ] Relatórios

---

## V1

[ ] CVE Engine

[ ] Risk Engine

[ ] Knowledge Base

[ ] Exportação PDF

---

## V2

[ ] OpenSearch

[ ] IA Assistente

[ ] Correlação Avançada

[ ] Multi Tenant

---

## V3

[ ] Integração SIEM

[ ] Integração SOAR

[ ] Agendamento Automático
docs/ui.md
# UI

## Cores

Primary:
#2563EB

Success:
#16A34A

Warning:
#F59E0B

Danger:
#DC2626

---

## Tipografia

Inter

---

## Layout

Sidebar fixa

Topbar

Dashboard

Cards

Tabelas

Filtros

---

## Componentes

Button
Input
Card
Modal
Table
Badge
Toast
docs/testing.md
# Testes

## Backend

Pytest

Meta:
80% cobertura

---

## Frontend

Vitest

React Testing Library

---

## E2E

Playwright

---

## Estratégia

Unitários

Integração

E2E

Smoke Tests
.env.example

DJANGO_SECRET_KEY=

DEBUG=False

ALLOWED_HOSTS=

POSTGRES_DB=byakugan

POSTGRES_USER=postgres

POSTGRES_PASSWORD=postgres

POSTGRES_HOST=postgres

POSTGRES_PORT=5432

REDIS_HOST=redis

REDIS_PORT=6379

JWT_SECRET=

OPENSEARCH_HOST=

OPENSEARCH_PORT=

AI_PROVIDER=openai

AI_API_KEY=

Se você quiser realmente acelerar o desenvolvimento com Claude Code, eu adicionaria ainda mais 4 arquivos estratégicos:

docs/roadmap.md → planejamento completo até a versão 1.0.
docs/security.md → arquitetura de segurança do próprio Byakugan.
docs/scanning-engine.md → especificação detalhada do motor de análise.
docs/ai-assistant.md → como a IA irá correlacionar vulnerabilidades e sugerir remediações.

Esses quatro documentos costumam ser os que mais ajudam um agente de código a manter consistência durante meses de desenvolvimento.


###############################################################################################################################################################################################
proximo promt:
faça isso, me ajude a criar mais esses arquivos:



`docs/roadmap.md` → planejamento completo até a versão 1.0.



1. `docs/security.md` → arquitetura de segurança do próprio Byakugan.
2. `docs/scanning-engine.md` → especificação detalhada do motor de análise.
3. `docs/ai-assistant.md` → como a IA irá correlacionar vulnerabilidades e sugerir remediações.


###############################################################################################################################################################################################
ultima resposta da conversa:
Esses arquivos são justamente o que transforma o Byakugan de um "trabalho da faculdade" em um projeto com especificação de produto real.

Minha sugestão é que eles sejam escritos pensando em três públicos ao mesmo tempo:

Você (desenvolvedor).
Claude Code (agente de desenvolvimento).
Banca da FIAP (documentação técnica).
docs/roadmap.md
Roadmap
Visão

O Byakugan será desenvolvido incrementalmente, iniciando com um MVP funcional de descoberta de ativos e evoluindo para uma plataforma completa de gestão de vulnerabilidades, correlação de riscos e apoio à remediação.

Fase 0 — Fundação

Objetivo:

Criar a infraestrutura base do projeto.

Entregas
Estrutura de monorepo
Docker Compose
PostgreSQL
Redis
Backend Django
Frontend React
Autenticação JWT
RBAC
Auditoria básica
CI/CD inicial

Status:

Planejado
Fase 1 — Asset Discovery

Objetivo:

Identificar ativos presentes no ambiente.

Funcionalidades
Cadastro de alvos
Descoberta de hosts
Descoberta de serviços
Inventário de ativos
Histórico de descobertas
Resultado Esperado

Usuário consegue visualizar:

Hosts
Portas
Protocolos
Serviços

Status:

MVP
Fase 2 — Fingerprinting

Objetivo:

Identificar tecnologias utilizadas.

Funcionalidades
Sistema operacional
Servidores web
Frameworks
Bancos de dados
Tecnologias frontend
Resultado Esperado

Mapa tecnológico completo do ambiente.

Status:

MVP
Fase 3 — Vulnerability Assessment

Objetivo:

Relacionar ativos a vulnerabilidades conhecidas.

Funcionalidades
Base CVE
Busca por versões vulneráveis
Classificação CVSS
Evidências técnicas
Resultado Esperado

Lista de vulnerabilidades por ativo.

Status:

MVP
Fase 4 — Correlation Engine

Objetivo:

Transformar vulnerabilidades em risco de negócio.

Funcionalidades
Risk Score
Priorização automática
Agrupamento por criticidade
Heatmaps

Status:

V1
Fase 5 — Reporting

Objetivo:

Gerar relatórios profissionais.

Funcionalidades
PDF Executivo
PDF Técnico
Exportação CSV
Exportação JSON
Histórico de relatórios

Status:

V1
Fase 6 — Knowledge Base

Objetivo:

Explicar vulnerabilidades e correções.

Funcionalidades
Descrição da vulnerabilidade
Impacto
Referências
Mitigações
Passo a passo de correção

Status:

V1
Fase 7 — AI Assistant

Objetivo:

Criar um analista virtual de segurança.

Funcionalidades
Explicação de findings
Sugestão de correções
Resumos executivos
Consultas em linguagem natural

Status:

V1
Fase 8 — Enterprise Features

Objetivo:

Preparar o sistema para ambientes corporativos.

Funcionalidades
Multi-tenant
SSO
Integração SIEM
Integração SOAR
Agendamento avançado

Status:

Pós 1.0
Critério para Versão 1.0

A versão 1.0 será considerada concluída quando:

Asset Discovery estiver funcional
Fingerprinting estiver funcional
Vulnerability Assessment estiver funcional
Reporting estiver funcional
AI Assistant estiver funcional
Cobertura de testes acima de 80%
Documentação completa
docs/security.md
Segurança do Byakugan
Objetivo

Garantir que o próprio Byakugan siga princípios modernos de segurança.

Security By Design

Todo componente deve ser desenvolvido considerando:

Confidencialidade
Integridade
Disponibilidade
Auditabilidade
Autenticação

Método:

JWT

Tokens:

Access Token
Refresh Token

Expiração:

Access Token: 15 minutos

Refresh Token: 7 dias

Controle de Acesso

Modelo:

RBAC

Perfis:

Administrator

Acesso total.

Security Analyst

Pode criar scans e consultar resultados.

Viewer

Somente leitura.

Proteção de Senhas

Obrigatório:

Argon2
Salt automático
Nunca armazenar senha em texto puro
Comunicação

Obrigatório:

HTTPS
TLS 1.3

Proibido:

HTTP em produção
Auditoria

Todos os eventos devem ser registrados.

Exemplos:

Login
Logout
Criação de Scan
Execução de Scan
Exclusão de Registro
Logs

Formato:

JSON estruturado

Campos:

timestamp
user
action
severity
source
Segredos

Nunca armazenar:

Senhas
Chaves API
Tokens

em código-fonte.

Utilizar:

.env
Secret Manager futuramente
Segurança da API

Obrigatório:

Rate Limiting
Validação de entrada
Sanitização
CSRF Protection
CORS configurado
Banco de Dados

Obrigatório:

Backups automáticos
Criptografia em trânsito
Menor privilégio possível
Hardening

Produção deve utilizar:

Containers não privilegiados
Usuário não-root
Headers de segurança
CSP
HSTS
Dependências

Obrigatório:

Verificação de vulnerabilidades
Atualizações regulares
SCA (Software Composition Analysis)
Conformidade

Referências:

OWASP Top 10
OWASP ASVS
NIST CSF
CIS Controls
docs/scanning-engine.md
Scanning Engine
Objetivo

O Scanning Engine é o núcleo responsável por executar análises, consolidar resultados e alimentar o mecanismo de correlação de riscos.

Arquitetura

Scan Request
↓
Scheduler
↓
Queue
↓
Workers
↓
Parsers
↓
Database
↓
Correlation Engine

Fluxo de Execução
1. Criação do Scan

Usuário cria um scan.

Exemplo:

Host único
Domínio
Lista de IPs
2. Validação

O sistema valida:

Formato
Duplicidade
Permissões
3. Enfileiramento

O scan é enviado ao Celery.

Estados:

Pending
Running
Completed
Failed
Cancelled
4. Execução

Workers executam módulos independentes.

Discovery Module

Responsável por:

Hosts
DNS
Subdomínios
Serviços

Saída:

Asset Inventory

Fingerprint Module

Responsável por:

Sistema operacional
Frameworks
Servidores
Tecnologias

Saída:

Technology Profile

Vulnerability Module

Responsável por:

Busca CVE
CVSS
Correlação de versões

Saída:

Findings

Correlation Module

Responsável por:

Agrupar vulnerabilidades
Eliminar duplicidades
Priorizar riscos

Saída:

Risk Assessment

Estrutura de Findings

Campos obrigatórios:

id
asset
category
title
severity
cvss
description
evidence
recommendation
Severidade

Critical
High
Medium
Low
Info

Regras

Todo finding deve:

possuir evidência
possuir descrição
possuir recomendação

Nenhum finding pode ser salvo sem contexto.

Performance

Meta:

até 100 ativos simultâneos
processamento assíncrono
escalabilidade horizontal
Histórico

Nenhum scan poderá ser sobrescrito.

Todos os resultados devem permanecer disponíveis para auditoria.

docs/ai-assistant.md
AI Assistant
Objetivo

O AI Assistant atua como um analista virtual de segurança integrado ao Byakugan.

Seu objetivo é transformar resultados técnicos em informações acionáveis para analistas e gestores.

Princípios

A IA nunca executa ações automaticamente.

A IA apenas:

Analisa
Explica
Resume
Recomenda

A decisão final sempre pertence ao usuário.

Fontes de Dados

A IA poderá utilizar:

Findings
Vulnerabilities
CVEs
Knowledge Base
Relatórios anteriores
Histórico do ambiente
Capacidades
Explicação de Vulnerabilidades

Exemplo:

Pergunta:

"O que significa essa vulnerabilidade?"

Resposta:

descrição
impacto
risco
Sugestão de Correção

Exemplo:

Entrada:

Apache vulnerável

Saída:

atualização recomendada
mitigação temporária
impacto da correção
Resumo Executivo

Transformar linguagem técnica em linguagem de negócio.

Exemplo:

"Existem 3 vulnerabilidades críticas que podem impactar sistemas expostos à internet."

Priorização

A IA deve considerar:

CVSS
Exposição
Criticidade do ativo
Histórico
Correlation Engine IA

A IA deverá identificar:

vulnerabilidades relacionadas
causas comuns
padrões recorrentes
riscos sistêmicos
Prompt Base

Objetivo:

Analisar findings de segurança e gerar recomendações objetivas.

Regras:

Não inventar informações
Não assumir exploração bem-sucedida
Explicar em linguagem clara
Sempre citar evidências
Limitações

A IA não pode:

Executar ações
Alterar sistemas
Excluir dados
Tomar decisões pelo usuário
Futuro

Versão futura:

Chat com contexto completo
Consultas em linguagem natural
Geração automática de relatórios
Assistente SOC
Assistente DevSecOps
Critérios de Qualidade

Toda resposta da IA deve conter:

Resumo
Evidência
Impacto
Recomendação
Nível de confiança

Formato:

Resumo:
...

Evidência:
...

Impacto:
...

Recomendação:
...

Confiança:
Alta | Média | Baixa

Com esses quatro documentos, o Byakugan já passa a ter uma documentação próxima do que equipes profissionais utilizam para orientar desenvolvimento contínuo. O próximo passo que mais agregaria valor seria criar também:

docs/modules.md → especificação detalhada de cada módulo do sistema.
docs/domain-model.md → entidades, agregados e bounded contexts (DDD).
docs/reporting.md → modelos completos dos relatórios executivo e técnico.
docs/deployment.md → Docker, CI/CD, ambientes e infraestrutura.

Esses documentos costumam reduzir drasticamente ambiguidades quando você começar a implementar o projeto com Claude Code.
