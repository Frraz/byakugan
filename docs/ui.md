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
- **Sidebar fixa** à esquerda (navegação por módulo: Dashboard, Assets, Scans, Targets, Vulnerabilities, Reports, Knowledge Base). Ícones no mesmo *design language* do olho/circuito.
- **Topbar** com busca global, usuário, papel (RBAC) e alternância de tema.
- Área de conteúdo: **KPI tiles** no topo, tabelas com filtros abaixo. Fundo Cyber Navy com painéis glass.

## Componentes base
Button (filled/neon-outline) · Input · Select · Card/GlassPanel · Modal/Dialog · Table (paginação/ordenação) · Badge (severidade/status, pill com indicador) · StatCard (KPI) · Toast · Tabs · Tooltip · Skeleton (loading).

## Padrões de dados
- **Tabelas** para listas (assets, scans, findings) com filtros e ordenação server-side; barra de severidade colorida à direita.
- **KPI tiles** no topo dos dashboards (Assets, Critical, High, Medium, Risk Score).
- **Heatmap** para risco por categoria (infra, aplicações, banco, cloud).
- **Estados vazios** e **loading (skeleton)** explícitos em toda listagem.

## Acessibilidade
- Contraste mínimo WCAG AA (atenção ao Electric Blue sobre Navy — usar sobre superfícies escuras, nunca texto pequeno em glow puro).
- Navegação por teclado em modais, tabelas e formulários.
- `aria-label` em ícones e badges de severidade.
