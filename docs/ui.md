# UI — Identidade Visual e Componentes

> Identidade oficial do Byakugan: **"Forensic Instrument"** (ver `PLANO_REDESIGN_BYAKUGAN.md` para o racional completo do redesign). Dark-first na aplicação; os PDFs usam uma composição editorial clara, distinta do tema escuro.

## Conceito de marca
O Byakugan é uma **plataforma de Security Assessment / pentest profissional autorizado**. A marca deve transmitir: precisão, controle, inteligência, maturidade, tecnologia discreta. **Não** cyberpunk, **não** gamer, **não** genérica — uma bancada de trabalho de precisão, não um filme de hackers.

## Princípios
- **Dark-first, não dark-only.** O tema escuro é o padrão da área operacional; o claro é uma adaptação editorial equivalente (não uma inversão mecânica de cores).
- Dados antes da decoração: cada gráfico, cor e animação precisa ajudar a entender risco, progresso ou próximo passo.
- Severidade sempre comunicada por **cor + texto** (nunca só cor — acessibilidade).
- Estética: superfícies planas com contraste de borda, elevação por contraste (não por sombra/glow), geometria limpa. **Sem** glassmorphism indiscriminado, **sem** neon, **sem** gradientes decorativos de fundo.
- Consistência: tokens semânticos centralizados (Tailwind CSS variables; shadcn/ui como base comportamental).

## Paleta de cores

### Marca e superfícies (tema escuro, padrão)
| Uso | Token | Hex |
| --- | --- | --- |
| Fundo base | `background` | `#0B0D10` |
| Sidebar/topbar | `sidebar` | `#0E1115` |
| Superfície (cards, tabelas) | `surface` / `card` | `#13171C` |
| Superfície elevada (popover, menus, drawers) | `surface-raised` / `popover` | `#191F26` |
| Superfície discreta (campos, código) | `surface-subtle` / `muted` | `#101317` |
| Borda | `border` | `#293039` |
| Borda forte | `border-strong` | `#3A444F` |
| Texto principal | `foreground` | `#F0F1EE` |
| Texto secundário | `muted-foreground` | `#B0B7BF` |
| Texto de metadado | `dim` | `#858E99` |
| Acento de marca (latão mineral) | `primary` | `#D4AE73` |

O acento de marca é usado com parcimônia (ação primária, item de navegação ativo, estado "running") — não colore links, bordas ou ícones indiscriminadamente. `accent` (hover neutro de menus/dropdowns) é um cinza-azulado discreto, não uma segunda cor de marca.

### Severidade (findings) — tema escuro
| Severidade | Token | Hex |
| --- | --- | --- |
| Critical | `destructive` | `#F06B73` |
| High | `sev-high` | `#F29A63` |
| Medium | `warning` | `#E3C66F` |
| Low | `sev-low` | `#80B7D4` |
| Info | `sev-info` | `#A7B0BC` |
| Sucesso | `success` | `#75C6A3` |

`sev-low` é um token dedicado — nunca reaproveita `primary`/`brand`, mesmo sendo também uma tonalidade azulada (severidade e marca são semânticas distintas).

Tema claro (`:root`) usa tokens equivalentes com valores escurecidos para contraste AA em fundo branco (ver `frontend/src/index.css`); suportado via `darkMode: ["class"]`, mas o dark é o padrão real da aplicação.

## Tipografia
- Interface: **Inter Variable** (`@fontsource-variable/inter`), fallback `system-ui, sans-serif`.
- Dados técnicos (IPs, portas, hashes, IDs, CVEs, código): mono (`ui-monospace, SFMono-Regular, Consolas, monospace`).
- Wordmark "BYAKUGAN": `foreground`, tracking moderado; subtítulo "SECURITY ASSESSMENT" em `muted-foreground`, tracking mais largo, sem usar a cor de marca no subtítulo (reservada para o símbolo).

## Logo
- Símbolo (`Mark`, `frontend/src/components/brand/Logo.tsx`): vetor puro — dois arcos assimétricos + um ponto focal. Não é um olho literal, não tem referência a anime; lê-se como um instrumento de foco/precisão. Funciona em 16–32px (sidebar compacta, favicon) e em tamanhos grandes (login, capa de relatório PDF).
- No PDF, a mesma marca é desenhada nativamente via primitivas do ReportLab (`apps/reports/pdf.py:_draw_mark`), não como imagem raster — garante consistência exata de forma entre app e documento sem depender de um arquivo de imagem.
- Variações: horizontal (símbolo + wordmark, `Logo`), símbolo puro (`Mark` — favicon, topbar mobile, cabeçalho de PDF).

## Layout
- **Sidebar fixa** à esquerda, dois grupos:
  - Operação: Dashboard · Alvos · Scans · Vulnerabilidades · Evidências · Relatórios · Base de conhecimento.
  - Administração (visível por papel): Auditoria.
  - Item ativo: fundo sutil (`bg-primary/10`) + marcador de borda esquerda em `primary`.
  - **Assets** não tem aba própria — o inventário do ativo é acessível por *drill-down* a partir do detalhe da vulnerabilidade (`/assets/:id`).
- **Topbar** com busca/tema, usuário, papel (RBAC) e logout.
- Área de conteúdo: **KPI tiles** no topo quando aplicável, tabelas com filtros abaixo.
- **Ações primárias sempre visíveis** ("Novo alvo", "Novo scan"): no deployment privado o frontend concede escrita a qualquer usuário autenticado (`usePermissions`), então os botões não "somem"; o backend segue como fonte real de permissão. O mesmo vale para `isAdmin` (ex.: item "Auditoria" na navegação) — a página correspondente trata um eventual 403 do backend como estado de acesso negado, não como erro genérico.

## Componentes base
Button (default/outline/secondary/ghost/destructive/link) · Input · Select · Textarea · Card/GlassPanel · Dialog/Sheet/AlertDialog (ConfirmDialog) · Table (paginação/ordenação) · Badge (severidade/status/categoria, com texto + cor, nunca só cor) · StatCard (KPI) · CopyButton (blocos de evidência/código) · Toast (sonner) · Tabs · Tooltip · Skeleton/TableSkeleton (loading) · EmptyState · ErrorBanner.

## Design system (implementação)
A UI é construída sobre **shadcn/ui** (primitivos Radix, estilo *new-york*), com **lucide-react** (ícones), **sonner** (toasts) e **recharts** (gráficos). Os tokens de cor são **CSS variables em HSL** (`src/index.css`): o tema claro vive em `:root` e o escuro (padrão) em `.dark`; o Tailwind (`darkMode: ["class"]`) mapeia tanto os nomes semânticos do shadcn (`background`, `card`, `primary`…) quanto os aliases próprios da marca (`sidebar`, `surface`, `surface-raised`, `surface-subtle`, `sev-*`, `dim`). Componentes próprios do Byakugan (glass-panel, stat-card, severity/status/category badge, confirm-dialog, copy-button, data-pagination) ficam em `src/components/ui/` sobre os primitivos. Toda listagem tem paginação server-side (PAGE_SIZE 20), busca/filtros, skeleton com forma de tabela e estado vazio; ações destrutivas usam `ConfirmDialog` (com confirmação digitada quando em cascata) e feedback via toast. Navegação mobile via `Sheet` (hambúrguer). O polling de scans é adaptativo (só enquanto há scan ativo, evitando estourar o throttle da API).

## Padrões de dados
- **Tabelas** para listas (scans, findings, alvos, auditoria) com filtros e ordenação server-side.
- **KPI tiles** no topo dos dashboards (Ativos, Critical, High, Medium, Risk Score).
- **Heatmap** para risco por categoria; **matriz OWASP** (testada/encontrada/provada, 2021+2025) por scan.
- **Estados vazios** e **loading (skeleton)** explícitos em toda listagem; filtro aplicado vs. "sem dados" sempre diferenciados.

## Telas-chave (fluxos principais)
- **Novo alvo** (`TargetFormDialog`): enxuto — só **Nome** e **Valor** (host/domínio/IPv4/IPv6/CIDR). "Autorizado por" foi removido (auto-preenchido); "Escopo autorizado" é opcional, com ícone **(i)** explicando o que é e como usar (default = o próprio alvo). A listagem distingue autorização válida, **expirando em até 7 dias** (aviso amarelo) e expirada (vermelho) — não só "válida"/"expirada".
- **Novo scan** (`ScanFormDialog`): fluxo em seções numeradas — tipo de scan (cards com descrição), alvo (cadastrado ou inline, com aviso de validade da autorização do alvo selecionado), intensidade (cards), **exploração** (toggle de prova de impacto, habilitado só em `aggressive`, com aviso de RoE), ajustes finos (portas/wordlist/checks) e um resumo do que vai rodar.
- **Detalhe do scan**: abas Findings · Serviços · Evidências · **Cobertura OWASP** · Autorização. Cancelamento explica que é cooperativo (fase em andamento pode levar instantes para parar; resultados parciais são preservados).
- **Vulnerabilidades**: **visão consolidada** — uma linha por vulnerabilidade lógica (RN025), com badge de "N alvos afetados". O painel de detalhe (`VulnerabilityGroupSheet`) separa **como foi detectada** (evidência, com copiar), **como pode ser explorada** (playbook + exploração comprovada) e **onde foi encontrada** (todos os alvos/ativos, com triagem por ocorrência) + OWASP/CWE + remediação inline.
- **Evidências**: lista **todos** os status de exploração (comprovado/tentado/bloqueado/falha) com filtro; empty states explicam o estado real (motor desligado, nenhum finding explorável, alvo fora do escopo). Blocos de prova/evidência têm botão de copiar.
- **Base de conhecimento**: listagem por categoria + busca; detalhe com resumo, impacto, remediação passo a passo, referências e findings relacionados (cross-scan, por categoria); edição com preview ao vivo do conteúdo formatado.
- **Auditoria** (admin): trilha somente-leitura — nenhum controle de editar/apagar em nenhum lugar da UI; filtro por busca/severidade; detalhe mostra ator, timestamp e metadata JSON com copiar.

## PDFs (ReportLab)
Composição editorial clara (fundo branco), deliberadamente distinta do tema escuro da aplicação — mesma identidade de marca (`apps/reports/pdf.py`): acento em latão (`BRASS`/`BRASS_LIGHT`), faixa quase-preta (`INK_DARK`) só na capa e cabeçalhos de tabela, cores de severidade escurecidas para contraste em fundo claro. Narrativa de Ataque só aparece quando há `Evidence` `proven` (nunca especulativa); cobertura OWASP (2021+2025) idêntica à da aplicação, com "cobertura limitada" sempre marcada como limitação, nunca em verde.

## Acessibilidade
- Contraste mínimo WCAG 2.2 AA nos fluxos críticos.
- Navegação por teclado em modais, tabelas e formulários; foco visível (`focus-visible:ring`) inclusive nos itens de navegação da sidebar.
- `aria-label` em ícones e botões sem texto (ex.: `CopyButton`, ações de tabela).
- `prefers-reduced-motion` respeitado globalmente (`src/index.css`).
