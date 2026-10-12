# Redesign — entrega e evidências

Atualizado em **11/10/2026**. Plano de referência: [PLANO_REDESIGN_BYAKUGAN.md](../PLANO_REDESIGN_BYAKUGAN.md).

A referência antiga “Fase E (QA)” estava em `frontend/src/index.css`. O plano
canônico usa fases **0–6**; a retomada correspondeu à Fase 6, com revisão das
entregas anteriores. O baseline de código foi o commit `8b2b982`; não havia um
registro completo de screenshots anterior à retomada. As capturas desta entrega
formam o baseline reproduzível para próximas alterações.

Capturas de referência com fixtures de teste (não são resultados de um ambiente real):
[desktop escuro](redesign/overview-dark-1440x900.png),
[desktop claro](redesign/overview-light-1440x900.png),
[mobile escuro](redesign/overview-dark-360x800.png),
[mobile claro](redesign/overview-light-360x800.png).

## Situação por fase

| Fase | Entrega final | Evidência |
|---|---|---|
| 0 — Auditoria | Rotas, endpoints, tokens, componentes e lacunas confrontados com o plano; permissões permissivas e estados incorretos identificados | Inventário abaixo, histórico Git e este documento |
| 1 — Sistema visual | Tokens claro/escuro ajustados após medição; marca vetorial preservada; componentes, foco, severidade textual e catálogo interno | `index.css`, `components/ui/`, `/design-system` somente em desenvolvimento |
| 2 — Login e shell | Login validado, mostrar senha, retorno à rota solicitada, refresh concorrente, limpeza de cache entre sessões, sidebar compacta/mobile, busca e RBAC | Testes de API/RBAC, Playwright e integração real |
| 3 — Operação | Alvos com escopo/validade, formatos IPv4/IPv6/CIDR, seleção paginada, scans com gates reais, progresso acessível, cancelamento e confirmação de prova de impacto | Cenários de autorização expirada, andamento e permissões |
| 4 — Investigação | Dashboard com totais globais/erros honestos, inventário navegável, findings/triagem, evidências filtradas por ocorrência, OWASP e conteúdo longo | Matriz visual de rotas, abas e testes backend |
| 5 — Relatórios | Seleção paginada e contextual ao scan, estados completos, preview/download, PDF com fontes embutidas e evidências extensas, taxonomia MITRE também no JSON/CSV | Integração com API real, testes PDF e inspeção dos arquivos |
| 6 — QA | Responsividade nos seis tamanhos, dois temas, axe, teclado/foco, estados vazio/erro, regressão e documentação | Comandos e resultados abaixo |

As fases do redesign estão entregues no escopo da API atual. Os limites de
validação e as evoluções funcionais independentes estão explicitados ao final;
esta entrega não encerra o roadmap V2/V3 do produto.

## Inventário de rotas e contratos

| Rota | Fontes de dados reais |
|---|---|
| `/login`, `/account`, `/users/new` | `/auth/login/`, `/auth/refresh/`, `/auth/logout/`, `/auth/me/`, `/auth/register/` (admin) |
| `/` | `/risk/overview/`, `/scans/stats/`, `/scans/`, `/assets/`, `/targets/` |
| `/targets` | `/targets/` e detalhe; criação/edição admin/analyst, exclusão admin |
| `/assets`, `/assets/:id` | `/assets/`, detalhe com serviços/tecnologias/DNS, `/findings/?asset=` |
| `/scans`, `/scans/:id` | `/scans/`, detalhe/findings/services/owasp-coverage/cancel/exploit, `/evidence/?scan=` |
| `/vulnerabilities` | `/findings/grouped/`, triagem, evidências e playbooks existentes |
| `/evidence` | `/evidence/`, `/playbooks/`; status reais, sem equiparar bloqueado/tentado a provado |
| `/reports` | `/reports/`, `/reports/:id/download/`; geração síncrona existente |
| `/knowledge-base` | `/knowledge-base/`, `/findings/` relacionados; escrita admin/analyst |
| `/audit-log` | `/audit-logs/` somente admin; histórico sem controles de alteração |
| `/design-system` | Amostras explicitamente demonstrativas, só em desenvolvimento |

Busca Ctrl/Cmd K consulta **alvos, scans e artigos** pelas APIs existentes; não
promete uma busca sobre todo o domínio. Filtros/paginação nas listas ficam na URL.
Não existem métricas ou registros sintéticos no código da aplicação; fixtures
estão restritas a `e2e/` e ao laboratório descartável.

## Verificação

- **Backend: 768 testes aprovados**, incluindo regressão PDF, API, payload,
  CSV/JSON, taxonomia, permissões e motores com seams simulados. SQLite em memória,
  Python 3.14 no ambiente temporário `/tmp/byakugan-venv`; não substitui CI PostgreSQL/Python 3.13.
- **Frontend: 41 testes aprovados**, cobrindo refresh simultâneo JSON/binário,
  sessão antiga, RBAC, filtros com reset de página, formatos e ciclo de relatórios.
- **TypeScript, build Vite, ESLint, ruff e black** verificados. Páginas carregam sob
  demanda; o build não emite mais o aviso de chunk acima de 500 kB.
- **Playwright: 22 cenários aprovados** entre matriz e integração real com Django
  isolado, incluindo inventário, abas, catálogo, retorno de foco, autorização
  expirada, criação bloqueada pelo kill-switch e troca para uma conta viewer.
  Na rodada com dois workers, o teste desktop claro excedeu 60 s durante o axe;
  passou novamente com um worker. A integração passou após corrigir o próprio
  teste para aguardar o término do login antes de navegar. O padrão é um worker.
- Matriz: 1440×900, 1280×800, 1024×768, 768×1024, 390×844, 360×800, claro/escuro;
  rotas autenticadas, 404, vazio/erro, diálogos e conteúdo técnico longo.
- axe nas rotas desktop e nos formulários/abas revisados, tags WCAG 2 A/AA,
  2.1 AA e 2.2 AA. Teclado verifica Escape, retorno de foco, validação com foco
  no primeiro campo, busca e navegação de volta. Layout 720×450 verifica reflow
  equivalente a uma viewport 1440×900 a 200%; não aciona o controle de zoom do navegador.
- PDFs executivo/técnico de laboratório inspecionados com renderização em imagem,
  extração de texto e verificação de fontes embutidas. Testes de estresse cobrem
  evidência com 120 linhas, markup literal, acentos, palavra extensa e inventário
  com célula maior que uma página. Evidência completa continua selecionável.

O teste de CVSS agrupado passou a comparar valores decimais exatos (`Decimal`),
evitando a comparação incorreta entre decimal do DRF e float binário no SQLite.
Não houve mudança na fórmula ou na precisão de CVSS.

## Reprodução

No frontend:

```bash
npm ci
npm run build
npm run lint
npm test
npx playwright install chromium
npm run test:e2e
```

Screenshots, traces de falhas e HTML ficam em `frontend/test-results/` e
`frontend/playwright-report/` (ignorados pelo Git). Para um Chromium já instalado,
`PLAYWRIGHT_CHROMIUM_EXECUTABLE` pode apontar para seu executável.

Para integração com API real, em outro terminal:

```bash
python scripts/redesign_lab.py
# No diretório frontend:
BYAKUGAN_LIVE_LAB=1 npm run test:e2e -- --grep 'real API'
```

O laboratório cria SQLite e mídia temporários, conta com senha aleatória guardada
em arquivo local com modo 0600 e dados de teste identificados. Ambos os motores
ficam **desativados**; nenhuma varredura real é executada. Interromper o servidor
remove as credenciais temporárias. PDFs de QA ficam em `/tmp/byakugan-redesign-pdfs/`.
Não usar o laboratório para publicar uma instância ou armazenar dados reais.

## Limites e evoluções independentes

- A API não publica o estado dos kill-switches: a UI informa a validação no servidor
  e apresenta bloqueios reais; não inventa um indicador “motor habilitado”.
- Gestão completa de usuários (listar/editar/desativar), edição de perfil e geração
  assíncrona de relatórios exigem contratos/trabalho de backend; seguem no backlog.
- O inventário representa observações registradas. Não há endpoint de histórico
  completo de presença por scan para criar uma linha do tempo confiável.
- axe e Chromium não certificam WCAG nem substituem avaliação com leitor de tela,
  dispositivos físicos, teclado virtual, Safari/Firefox ou impressão física.
- PDFs têm texto selecionável e marcadores, mas não possuem tagging PDF/UA.
- `npm audit fix` compatível foi aplicado. Permanecem **16 avisos** na árvore:
  tooling Vitest/tinypool, Tailwind e transitivos, além de React Router. Resolver
  todos exige migrações de versões principais e/ou correções upstream; não foi
  aplicado `--force`. Isso deve ser tratado como manutenção de dependências,
  separadamente do aceite visual, antes de uma atualização de produção.
