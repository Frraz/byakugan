# UI — Identidade Visual e Componentes

> Identidade oficial do Byakugan. Os assets de marca estão na raiz do projeto:
> `Byakugan logo.png`, `Byakugan identidade visual.png`. Tagline: **"See Everything. Detect Everything."**

## Conceito de marca
O Byakugan é uma **plataforma de cyber intelligence** — o "olho que tudo vê" reimaginado como sistema de inteligência de segurança. A marca deve transmitir: inteligente, observador, preciso, confiável, futurista, estratégico, técnico, poderoso. **Não** agressivo, **não** militar, **não** "hacker". Referências: CrowdStrike Falcon, Tenable, Datadog, SentinelOne, Grafana.

## Princípios
- **Dark theme first.** O tema escuro (Cyber Navy) é o padrão; o claro é adaptação.
- Clareza acima de tudo: dados de segurança densos precisam de hierarquia visual forte.
- Severidade sempre comunicada por **cor + texto + ícone** (nunca só cor — acessibilidade).
- Estética: **glassmorphism** sutil, **soft neon glow**, geometria limpa, "command center".
- Consistência: componentes reutilizáveis (Tailwind; Shadcn/UI opcional).

## Paleta de cores

### Marca
| Uso | Token | Hex |
| --- | --- | --- |
| Fundo base (Cyber Navy) | `navy` / `background` | `#0B1220` |
| Superfície (cards) | `surface` | `#111A2E` |
| Primária / destaque (Electric Blue) | `primary` | `#00D4FF` |
| Acento (Byakugan Lavender) | `accent` | `#C8B6FF` |
| Sucesso | `success` | `#22C55E` |
| Atenção | `warning` | `#F59E0B` |
| Crítico / perigo | `danger` | `#EF4444` |
| Texto principal | `foreground` | `#E6EDF6` |
| Texto secundário | `muted` | `#8A97AD` |

### Severidade (findings)
| Severidade | Cor | Hex |
| --- | --- | --- |
| Critical | danger | `#EF4444` |
| High | orange | `#F97316` |
| Medium | warning | `#F59E0B` |
| Low | primary | `#00D4FF` |
| Info | slate | `#64748B` |

Suporte a **dark mode** (padrão) e **light mode** via tokens semânticos (`darkMode: "class"`).

## Tipografia
- Família: **Inter** (fallback: system-ui, sans-serif); wordmark em geométrica com *tracking* largo, caixa alta.
- Hierarquia: **H1** (título de página, bold), **H2** (subtítulo/seção), **H3** (título de bloco), **Body** (14/16), **Caption** (12, para data points).
- Wordmark "BYAKUGAN": branco/prata; subtítulo "CYBERSECURITY PLATFORM" em Electric Blue, *letter-spacing* amplo.

## Logo
- Símbolo: olho amendoado, íris pálida com glow lavanda, radar/circuitos internos (`src/components/brand/Logo.tsx`, vetor SVG — escala e monocromático).
- Variações: horizontal (ícone + wordmark), ícone puro (favicon/app), monocromático.

## Layout
- **Sidebar fixa** à esquerda (navegação: **Dashboard · Alvos · Scans · Vulnerabilidades · Evidências · Relatórios**). Ícones no mesmo *design language* do olho/circuito.
  - **Assets** e **Knowledge Base** **não** têm mais aba própria (simplificação — deployment privado). O inventário do ativo continua acessível por *drill-down* a partir do detalhe da vulnerabilidade (`/assets/:id`), e os passos de remediação (Knowledge Base) aparecem **inline** no detalhe do finding — os dados seguem existindo no backend, só não como navegação de topo.
- **Topbar** com usuário, papel (RBAC) e alternância de tema.
- Área de conteúdo: **KPI tiles** no topo, tabelas com filtros abaixo. Fundo Cyber Navy com painéis glass.
- **Ações primárias sempre visíveis** ("Novo alvo", "Novo scan"): no deployment privado o frontend concede escrita a qualquer usuário autenticado (`usePermissions`), então os botões não "somem"; o backend segue como fonte real de permissão.

## Componentes base
Button (filled/neon-outline) · Input · Select · Card/GlassPanel · Modal/Dialog · Table (paginação/ordenação) · Badge (severidade/status, pill com indicador) · StatCard (KPI) · Toast · Tabs · Tooltip · Skeleton (loading).

## Design system (implementação)
A UI é construída sobre **shadcn/ui** (primitivos Radix, estilo *new-york*), com **lucide-react** (ícones), **sonner** (toasts) e **recharts** (gráficos). Os tokens de cor são **CSS variables em HSL** (`src/index.css`): o tema claro vive em `:root` e o escuro (padrão, Cyber Navy) em `.dark`; o Tailwind (`darkMode: ["class"]`) mapeia tanto os nomes semânticos do shadcn (`background`, `card`, `primary`…) quanto os aliases legados da marca (`navy`, `surface`, `sev-high`…). Componentes próprios do Byakugan (glass-panel, stat-card, severity/status badge, confirm-dialog, data-pagination) ficam em `src/components/ui/` sobre os primitivos. A fonte **Inter** é carregada via `@fontsource-variable/inter`. Toda listagem tem paginação server-side (PAGE_SIZE 20), busca/filtros, skeleton com forma de tabela e estado vazio; ações destrutivas usam `ConfirmDialog` (com confirmação digitada quando em cascata) e feedback via toast. Navegação mobile via `Sheet` (hambúrguer). O polling de scans é adaptativo (só enquanto há scan ativo, evitando estourar o throttle da API).

## Padrões de dados
- **Tabelas** para listas (scans, findings) com filtros e ordenação server-side; barra de severidade colorida à direita.
- **KPI tiles** no topo dos dashboards (Ativos, Critical, High, Medium, Risk Score).
- **Heatmap** para risco por categoria (infra, aplicações, banco, cloud).
- **Estados vazios** e **loading (skeleton)** explícitos em toda listagem.

## Telas-chave (fluxos principais)
- **Novo alvo** (`TargetFormDialog`): enxuto — só **Nome** e **Valor** (host/domínio/IPv4/IPv6/CIDR). "Autorizado por" foi removido (auto-preenchido); "Escopo autorizado" é opcional, com ícone **(i)** explicando o que é e como usar (default = o próprio alvo).
- **Novo scan** (`ScanFormDialog`): fluxo em seções numeradas — tipo de scan (cards com descrição), alvo (cadastrado ou inline), intensidade (cards), **exploração** (toggle de prova de impacto, habilitado só em `aggressive`, com aviso de RoE), ajustes finos (portas/wordlist/checks) e um resumo do que vai rodar.
- **Vulnerabilidades**: **visão consolidada** — uma linha por vulnerabilidade lógica (RN025), com badge de "N alvos afetados". O painel de detalhe (`VulnerabilityGroupSheet`) separa **como foi detectada** (evidência), **como pode ser explorada** (playbook + exploração comprovada) e **onde foi encontrada** (todos os alvos/ativos, com triagem por ocorrência) + OWASP/CWE + remediação inline.
- **Evidências**: lista **todos** os status de exploração (comprovado/tentado/bloqueado/falha) com filtro; empty states explicam o estado real (motor desligado, nenhum finding explorável, alvo fora do escopo).

## Acessibilidade
- Contraste mínimo WCAG AA (atenção ao Electric Blue sobre Navy — usar sobre superfícies escuras, nunca texto pequeno em glow puro).
- Navegação por teclado em modais, tabelas e formulários.
- `aria-label` em ícones e badges de severidade.
