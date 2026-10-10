# Byakugan — Plano Mestre de Redesign de UI/UX

**Versão:** 1.0  
**Objetivo:** redefinir a experiência visual e funcional do Byakugan, da autenticação aos relatórios PDF, preservando a lógica de negócio e os controles de segurança existentes.

---

## 1. Resumo executivo

O Byakugan deve deixar de parecer um painel técnico montado a partir de componentes prontos e passar a transmitir a qualidade de uma ferramenta profissional de operações de segurança: precisa, confiável, discreta, rápida de ler e consistente em cada estado.

A proposta não é adicionar efeitos para parecer tecnológica. É construir uma linguagem própria através de hierarquia editorial, dados bem organizados, tipografia, precisão de espaçamento, estados claros e visualizações que ajudem o analista a decidir o que fazer em seguida.

### Direção recomendada: **Forensic Instrument**

Uma interface de análise forense e operações ofensivas, inspirada na clareza dos melhores produtos de software profissional, em ferramentas de análise técnica e em publicações editoriais de alto padrão. A sensação desejada é de uma bancada de trabalho de precisão — não de um filme de hackers, jogo ou template SaaS.

Princípios centrais:

- **Dark-first, sem ser dark-only:** a área operacional usa tema escuro refinado; os PDFs usam uma linguagem editorial clara, adequada à impressão e à leitura prolongada.
- **Dados antes da decoração:** cada gráfico, métrica, cor e animação precisa ajudar a compreender risco, progresso ou próximo passo.
- **Densidade controlada:** exibir informação suficiente para especialistas sem transformar cada tela em uma parede de dados.
- **Segurança visível:** escopo autorizado, expiração, estado dos kill-switches e diferença entre detecção e prova de impacto precisam estar evidentes antes de ações sensíveis.
- **Sistema, não coleção de telas:** as páginas compartilham os mesmos tokens, espaçamentos, padrões de interação e estados.
- **Verdade operacional:** nunca apresentar dados fictícios, progresso inventado, cobertura total ou exploração comprovada sem evidência.

### O que o redesign cobre

Login e sessões; estrutura global de navegação; dashboard; alvos e autorização; inventário de ativos; criação, acompanhamento e histórico de scans; vulnerabilidades consolidadas; detalhes de findings; evidências e playbooks; matriz de cobertura OWASP; cadeias de risco; base de conhecimento; relatórios na aplicação; PDFs executivo e técnico; exportações CSV/JSON; auditoria e permissões; estados responsivos; acessibilidade; testes visuais e funcionais.

### Limite técnico

O README descreve React, TypeScript, Vite, Tailwind CSS, shadcn/ui, Radix, lucide-react, Sonner, Recharts, React Query, Zustand e React Router no frontend; Django REST Framework no backend; Celery para scans assíncronos; e ReportLab para PDFs. O plano aproveita essa stack. Não propõe reescrever backend, contratos da API, autenticação JWT, permissões RBAC, regras de autorização ou motores de scan como parte do redesign visual. Se um requisito visual depender de dado que a API não fornece, isso deve ser identificado explicitamente e tratado como dependência, nunca simulado no frontend.

---

## 2. Identidade visual e posicionamento

### 2.1 Personalidade

O produto deve transmitir cinco atributos:

1. **Precisão:** números alinhados, tabelas bem construídas, nomenclatura técnica consistente e ausência de ruído visual.
2. **Controle:** ações irreversíveis e operações sensíveis têm contexto, revisão e confirmação proporcionais ao risco.
3. **Inteligência:** correlações, caminhos de risco e evidências são apresentados em ordem útil, não apenas como listas extensas.
4. **Maturidade:** pouco ornamento, estados completos, contraste adequado, conteúdo bem escrito e comportamento previsível.
5. **Tecnologia discreta:** gráficos, linhas técnicas e microinterações pontuais; nada de estética de videogame ou filme de ficção científica.

### 2.2 O que evitar

- Emojis em navegação, botões, mensagens, estados vazios, relatórios ou documentação da interface.
- Chuva Matrix, caveiras, cadeados gigantes decorativos, circuitos genéricos, partículas, grids luminosos e imagens de stock de hackers.
- Neon em todos os elementos, glow em cards, gradientes de fundo em larga escala e glassmorphism aplicado indiscriminadamente.
- Uma tela inteira formada por cards idênticos com ícone colorido, título e número grande.
- Bordas arredondadas excessivas, sombras pesadas, painéis dentro de painéis e grandes espaços vazios sem função.
- Tabelas sem hierarquia, colunas com largura imprevisível, textos truncados sem forma de leitura completa ou informações relevantes escondidas apenas em hover.
- Skeletons genéricos, números ilustrativos, progresso artificial ou notificações que dizem “sucesso” antes da confirmação real da API.
- Mudanças visuais aleatórias entre páginas, ícones misturados, cores sem semântica ou estilos locais que contradizem os tokens globais.

### 2.3 Assinatura visual própria

Criar uma marca gráfica vetorial minimalista inspirada em **foco, campo de visão e análise**, sem desenhar um olho literal ou usar referências de anime. Pode ser construída por dois arcos assimétricos e um ponto focal, com uma geometria reconhecível em 16–32 px. O logo precisa funcionar em sidebar expandida, sidebar compacta, login, favicon e capa de relatório.

Usar uma textura de fundo quase imperceptível apenas em áreas de marca ou cabeçalhos selecionados. A textura nunca pode competir com dados, reduzir contraste ou ser usada atrás de parágrafos longos.

---

## 3. Sistema visual proposto

Os valores abaixo são a proposta inicial, não valores finais imutáveis. Validar contraste e percepção em tela real antes de consolidar. Todas as cores devem ser definidas em tokens semânticos; componentes não devem depender de hexadecimais espalhados por arquivos.

### 3.1 Paleta operacional

| Token | Valor inicial | Aplicação |
|---|---|---|
| `background` | `#0B0D10` | Fundo principal do produto |
| `sidebar` | `#0E1115` | Navegação lateral, ligeiramente distinta do fundo |
| `surface` | `#13171C` | Painéis e superfícies de conteúdo |
| `surface-raised` | `#191F26` | Popovers, menus, drawers e elementos elevados |
| `surface-subtle` | `#101317` | Campos, áreas de código e superfícies internas |
| `border` | `#293039` | Divisores e contornos discretos |
| `border-strong` | `#3A444F` | Separação de tabelas, foco secundário e limites importantes |
| `text-primary` | `#F0F1EE` | Texto principal; branco levemente aquecido |
| `text-secondary` | `#B0B7BF` | Descrições e rótulos secundários |
| `text-muted` | `#858E99` | Metadados; nunca para conteúdo essencial de baixo contraste |
| `brand` | `#D4AE73` | Acento de marca, seleção e ação primária pontual |
| `brand-hover` | `#E1BF89` | Hover do acento principal |
| `brand-subtle` | `#2A241A` | Fundo discreto de seleção e destaque da marca |

O acento em tom de latão mineral diferencia o produto de dashboards cyber azul-neon e permite uma linguagem técnica mais editorial. Usar com parcimônia: o acento não deve colorir todos os links, bordas e ícones. Se a validação de marca indicar outro caminho, substituir o token `brand`, mantendo o restante do sistema semântico.

### 3.2 Cores semânticas

| Estado | Token sugerido | Regra |
|---|---|---|
| Crítico | `#F06B73` | Reservado para gravidade crítica e falhas de alto impacto |
| Alto | `#F29A63` | Risco alto; não confundir com ação primária |
| Médio | `#E3C66F` | Risco moderado; sempre acompanhado de texto |
| Baixo | `#80B7D4` | Baixa severidade; não significa automaticamente seguro |
| Informativo | `#A7B0BC` | Informação neutra |
| Sucesso | `#75C6A3` | Ação concluída ou controle verificado |
| Atenção | `#E3C66F` | Expiração próxima, condição pendente ou decisão requerida |
| Erro | `#F06B73` | Erro de operação, validação ou API |
| Desabilitado | `#626B76` | Controle indisponível, mantendo leitura suficiente |

A severidade precisa ser identificada por **texto + cor + posição consistente**. Nunca depender apenas da cor. O acento de marca não equivale a severidade e não deve ser reutilizado como “alto risco”.

### 3.3 Tipografia

- **Interface:** Geist Sans, se já estiver disponível ou puder ser adicionada de forma consistente. Alternativa de fallback: `Inter, system-ui, sans-serif`.
- **Dados técnicos:** Geist Mono ou `ui-monospace, SFMono-Regular, Consolas, monospace` para IPs, portas, hashes, IDs, CVEs, códigos, timestamps técnicos e trechos de evidência.
- **PDF:** fonte sans-serif embutida, consistente em todas as páginas e com suporte a português; usar uma família regular, medium e bold de qualidade. Validar acentos, símbolos e quebra de linha.
- Não usar fonte monoespaçada para parágrafos comuns.
- Evitar texto inteiro em caixa alta. Reservar tracking ampliado para pequenos rótulos, metadados e cabeçalhos de seção.

Escala de referência para a aplicação:

| Uso | Tamanho / peso inicial |
|---|---|
| Título principal da página | 28–32 px / semibold |
| Título de seção | 18–20 px / semibold |
| Título de painel | 14–16 px / semibold |
| Texto padrão | 14 px / regular |
| Texto denso de tabela | 13–14 px / regular |
| Rótulo e metadado | 12 px / medium |
| Código e identificador | 12–13 px / regular mono |
| Número de KPI | 28–36 px, conforme contexto |

Evitar fontes menores que 12 px para dados importantes. Em tabelas muito densas, preferir reduzir colunas ou criar uma visualização de detalhe em vez de comprimir tudo.

### 3.4 Grid, espaçamento e forma

- Base de espaçamento: múltiplos de 4 px, usando 8 px como unidade recorrente.
- Padding de conteúdo desktop: 28–32 px; tablet: 20–24 px; mobile: 16 px.
- Sidebar expandida: aproximadamente 248 px; compacta: 68–76 px.
- Altura do topbar: 60–64 px.
- Campos e botões primários: em geral 40–44 px de altura; controles densos de tabela podem ser menores sem perder acessibilidade.
- Bordas com raio moderado: 6 px para campos e botões, 8–10 px para painéis, 10–12 px para modais principais. Não arredondar tudo como cápsulas.
- Divisores finos e sombras quase invisíveis. Elevação deve ser expressa principalmente por contraste de superfície e borda, não por sombra escura exagerada.
- Definir uma largura máxima de leitura para telas textuais e deixar dashboards e tabelas utilizarem a largura disponível.

### 3.5 Ícones e movimentos

- Usar exclusivamente ícones consistentes do `lucide-react`, com tamanho e stroke padronizados.
- Ícones decorativos não devem competir com rótulos. Ações com ícone sem texto precisam de tooltip, nome acessível e alvo de clique adequado.
- Sem emojis como ícones ou substitutos de pictogramas.
- Transições comuns: 120–180 ms; drawers e modais: 160–220 ms; easing suave e consistente.
- Animação deve comunicar mudança de estado, não decorar. Respeitar `prefers-reduced-motion`.
- Sem parallax, cursor customizado, scroll hijacking, barras piscando ou animação contínua de fundo.

---

## 4. Arquitetura de navegação e estrutura global

### 4.1 Mapa de navegação recomendado

**Operação**

1. Overview
2. Alvos
3. Inventário de ativos
4. Scans
5. Vulnerabilidades
6. Evidências
7. Relatórios
8. Base de conhecimento

**Administração** — visível conforme papel e permissões

- Auditoria
- Administração de usuários, somente se houver tela e endpoints autorizados existentes
- Preferências da sessão/conta, apenas para funcionalidades realmente suportadas

Não mostrar itens que o usuário não possa acessar como se fossem funcionalidades disponíveis. Usar `usePermissions` e respostas reais da API para construir a navegação. O README lista `admin`, `analyst` e `viewer`; essa distinção precisa ser consistente em menus, botões, ações em lote e rotas diretas.

### 4.2 Shell da aplicação

**Sidebar:** logo e nome, navegação organizada por grupos, item ativo com fundo sutil e marcador de borda, botão de expandir/compactar, identificação do perfil no rodapé. No mobile, converter para drawer com overlay e fechar ao navegar.

**Topbar:** breadcrumb, título contextual quando necessário, botão de busca/command menu somente para ações e registros que possam ser realmente consultados, e menu da conta. A busca global só deve ser anunciada como global se houver implementação real sobre as entidades do backend.

**Área principal:** título de página, descrição curta quando útil, ação primária no local esperado, filtros, conteúdo e paginação. Manter uma hierarquia previsível; não mudar a posição dos botões primários a cada tela.

**Feedback global:** um ponto consistente para toast e erros de comunicação. Toasts são para eventos breves; erros importantes e recuperáveis devem permanecer na página com instrução e opção de tentar novamente.

### 4.3 Padrões de navegação

- Breadcrumbs em páginas de detalhe com mais de um nível.
- Manter filtros, página e ordenação ao entrar em um detalhe e voltar para a listagem, sempre que tecnicamente possível.
- Navegação por teclado para ações recorrentes; command menu opcional, somente se for implementado e testado com as ações reais.
- Evitar abrir modais em cascata. Para objetos complexos, preferir página de detalhe ou drawer amplo.
- Não colocar controles destrutivos junto às ações comuns sem separação visual.

---

## 5. Especificação de telas e fluxos

## 5.1 Login e estados de autenticação

**Objetivo:** transmitir confiança e levar a pessoa à plataforma sem distrações.

**Composição:** tela escura de largura total, marca à esquerda/superior e formulário em coluna estreita (aproximadamente 380–440 px). Pode haver uma composição geométrica proprietária em baixa intensidade no fundo, sem imagem de stock, animação permanente ou frases promocionais exageradas.

**Elementos:** logotipo vetorial; nome Byakugan; mensagem curta e técnica; campo de e-mail/usuário de acordo com o backend real; senha com mostrar/ocultar; botão “Entrar”; estado de carregamento; região de erro acessível; nota discreta de ambiente restrito, caso apropriado.

**Estados obrigatórios:** inicial, validação local, envio, credencial inválida, falha de API, indisponibilidade, sessão expirada e login bem-sucedido. A mensagem não deve revelar se uma conta específica existe. Não criar link de cadastro público se a criação for restrita a administradores.

**Cuidados:** desativar o botão enquanto a requisição estiver em andamento; evitar dupla submissão; preservar o usuário digitado quando apropriado, nunca preencher ou armazenar a senha; foco no primeiro campo; label persistente, não placeholder como único rótulo.

## 5.2 Dashboard / Overview

**Objetivo:** responder rapidamente: “Qual é a condição do ambiente? O que exige atenção agora? O que aconteceu recentemente?”

**Estrutura sugerida:**

1. Cabeçalho com saudação neutra ou título “Overview”, período/filtro quando suportado e ação “Novo scan”.
2. Linha de indicadores: risco agregado (se o endpoint fornecer), findings abertos por severidade, ativos monitorados, scans recentes/concluídos e autorizações expiradas/próximas do vencimento se os dados estiverem disponíveis.
3. Área principal em duas colunas: evolução ou distribuição do risco e lista priorizada de ativos/finding chains.
4. Seção “Prioridades” com os itens mais relevantes, link direto para o detalhe e explicação textual concisa do motivo da prioridade.
5. “Atividade recente” baseada em registros reais; não inventar eventos ou tempos.
6. “Cobertura” apenas com métricas semanticamente corretas. Não transformar “não testado” em “sem vulnerabilidade”.

**Visualização:** gráficos simples, eixo rotulado, valores legíveis, tooltips acessíveis, cores semânticas consistentes e resumo em texto/tabela equivalente. Evitar donut charts pequenos ou grandes áreas de visualização sem decisão associada.

**Estados vazios:** explicar o que falta para popular o dashboard e oferecer a ação adequada, como cadastrar alvo ou executar primeiro scan. Não exibir KPIs zerados como se fosse uma avaliação realizada quando não há dados.

## 5.3 Alvos e autorização

A listagem de alvos deve priorizar identificação, tipo de alvo, escopo/autorização, validade, último scan e ações permitidas. Mostrar host, domínio, IPv4, IPv6 ou CIDR com tipografia mono, truncando apenas com forma de copiar/ver completo.

**Colunas iniciais:** nome; alvo; tipo; estado de autorização; validade; último scan; menu de ações.

**Estados explícitos:** autorizado e válido; expiração próxima; expirado; escopo insuficiente; alvo sem autorização cadastrada quando o modo de deployment permitir; bloqueado por regra. Não exibir um único selo “Ativo” para situações diferentes.

**Cadastro/edição:** formulário dividido em “Identificação”, “Alvo” e “Autorização/escopo” quando os campos existirem no modelo. Validar tipo e formato antes do envio e apresentar erros junto ao campo. A ajuda de autorização deve explicar o conceito em linguagem direta, sem texto jurídico excessivo.

**Ações destrutivas:** explicar que excluir um alvo preserva histórico de scans, mas remove o vínculo com o alvo, de acordo com o comportamento documentado. Confirmar a ação com nome/valor do alvo visível.

## 5.4 Inventário de ativos

A tela de ativos deve funcionar como inventário navegável, não como outra lista genérica. Separar visualmente host, serviço, porta, DNS e tecnologias.

**Listagem:** ativo/host; IP ou hostname; quantidade de serviços quando disponível; principais tecnologias; TLS/indicadores relevantes; scan de origem/última observação; ações.

**Detalhe do ativo:** cabeçalho com hostname/IP; resumo do perfil tecnológico; serviços e portas; registros DNS; tecnologias; histórico de observações/scans relacionados; findings associados. Usar abas internas apenas se reduzirem rolagem e tiverem conteúdo suficiente.

**Regras:** indicar fonte e momento de observação quando a API fornecer; não afirmar que um serviço está atualmente ativo com base apenas em histórico. Diferenciar “não observado” de “inexistente”.

## 5.5 Scans: lista, criação e detalhe

### Lista de scans

Filtros consistentes por status, alvo, período e tipo/intensidade quando disponíveis. Status como `pending`, `running`, `completed`, `failed` e `cancelled` precisam ter rótulos legíveis em português e aparência semântica definida.

Colunas: identificação; alvo; perfil/intensidade; status; progresso/fase, quando em execução; findings relevantes; início/fim; iniciador quando disponível; ações compatíveis com o estado.

### Assistente de criação de scan

Fluxo recomendado de quatro passos:

1. **Selecionar alvo:** escolha explícita de alvo cadastrado e exibição do escopo reconhecido.
2. **Configurar análise:** tipos/checks e perfil `safe`, `normal` ou `aggressive`, com explicação do impacto operacional esperado.
3. **Prova de impacto:** área separada, desligada por padrão, com explicação de que exploração é distinta da detecção e só é permitida após os gates globais, opt-in e revalidação de escopo descritos pelo backend.
4. **Revisar e confirmar:** resumo final com alvo, autorização, validade, opções e modo selecionado. O botão deve indicar exatamente a ação que será iniciada.

Não replicar no frontend os kill-switches globais como se pudessem ser ligados por ali, salvo se existir um fluxo administrativo real e autorizado. Se o switch global estiver desligado, mostrar um aviso de “operação bloqueada pela configuração do ambiente” e refletir a resposta real do backend. O frontend não deve contornar as validações RN007, RN015, RN021–RN023.

### Detalhe e execução

Exibir status atual, progresso real, fase corrente quando disponível, timestamps, alvo, parâmetros e eventos relevantes. Mostrar progresso indeterminado quando a API não fornece percentual válido. Não simular incrementos artificiais.

Cancelar scan deve apresentar uma confirmação simples e explicar que o cancelamento é cooperativo, se esse comportamento estiver confirmado na implementação. Não mostrar exclusão como disponível enquanto um scan estiver em execução se a API retorna conflito nesse caso.

### Histórico

A exclusão de scan, disponível somente a admins e quando permitido, precisa informar que findings e relatórios associados também serão removidos conforme a regra RN014. O modal deve exigir confirmação clara, nunca um alerta genérico.

## 5.6 Vulnerabilidades e findings

Essa área deve ser o núcleo analítico do produto. A listagem consolida vulnerabilidades lógicas entre alvos, conforme descrito no README, e não deve parecer apenas uma coleção de cartões coloridos.

**Tabela principal:** título; severidade; ativo(s) afetado(s); categoria; estado de triagem; evidência/prova; identificadores (CVE/CWE/OWASP quando aplicável); observada em. Escolher colunas por largura de tela e permitir configuração ou overflow previsível em desktop.

**Filtros:** severidade; estado de triagem; ativo; scan; categoria; OWASP 2021; OWASP 2025; CWE; MITRE ATT&CK quando disponível. Mostrar filtros aplicados como chips removíveis, botão “Limpar filtros” e contagem de resultados.

**Detalhe de finding:**

1. Nome, severidade, estado de triagem e identificador.
2. Resumo executivo da falha.
3. Ativos/localizações afetados.
4. Evidência de detecção, claramente rotulada.
5. Prova de impacto, somente quando existir um registro de exploração correspondente.
6. Impacto técnico e impacto de negócio, sem alegações além dos dados.
7. Classificações OWASP 2021/2025, CWE, CVE/CVSS e MITRE ATT&CK quando existentes.
8. Recomendações de remediação e referências da Knowledge Base.
9. Histórico de triagem e auditoria quando disponível.

**Triagem:** “Aberto”, “Corrigido”, “Falso positivo” e “Risco aceito” devem ser estados inequívocos. Se houver comentário/motivo exigido pela API, validar antes de confirmar. Depois de salvar, atualizar a linha e o detalhe sem estado visual divergente.

**Confiança:** comunicar a diferença entre sinal detectado, finding confirmado e exploração comprovada. Não usar linguagem de “comprometimento” se a evidência só demonstrar exposição ou comportamento suspeito.

## 5.7 Evidências e playbooks

Evidências são imutáveis segundo o README; por isso, a experiência deve priorizar rastreabilidade e contexto, sem dar aparência de um editor.

**Listagem:** finding relacionado; ativo; classe; nível de impacto; status; data/hora; scan; identificador da evidência.

**Detalhe:** resumo da prova; origem e vínculo com finding; passos executados; artefato extraído; horário; nível de impacto; playbook associado; regra Sigma se existir. Renderizar artefatos em blocos técnicos legíveis, com copiar texto, quebra de linha e opção de expandir. Não expor conteúdo como HTML executável.

**Playbooks:** separar claramente “O que o motor comprovou”, “Como reproduzir manualmente em escopo autorizado”, “Limitações” e “Detecção defensiva” quando esses dados existirem. A regra Sigma deve ter visualização monoespaçada, cópia de YAML e indicação clara quando não há uma regra curada. Nunca preencher a ausência com uma regra inventada.

## 5.8 Cobertura OWASP, classificação e cadeias de risco

A matriz de cobertura deve diferenciar as dimensões do README: **testada**, **encontrada** e **provada**. Categorias de cobertura limitada devem ser apresentadas explicitamente como limitações, e não em verde como “seguras”.

**Matriz:** categoria; edição OWASP; testada; encontrada; prova de impacto; observações/limitações. Em telas estreitas, usar linha expansível ou detalhe por categoria, sem reduzir fonte a ponto de comprometer leitura.

**Cadeias de risco:** exibir a combinação de findings e explicar por que a correlação muda a prioridade. A visualização padrão pode ser uma sequência de etapas ou um grafo pequeno com alternativa textual. Evitar grafos decorativos grandes que não possam ser interpretados. Cada nó deve abrir o finding correspondente.

## 5.9 Relatórios dentro da aplicação

A página de relatórios precisa separar geração, histórico, pré-visualização e download.

**Geração:** selecionar somente scans concluídos, conforme RN012; escolher relatório executivo ou técnico; escolher PDF, CSV ou JSON; apresentar resumo do conteúdo e observações sobre quais seções estarão disponíveis. A opção não deve prometer conteúdo sem dados.

**Histórico:** tipo; scan; formato; data de geração; autor quando disponível; status; tamanho quando disponível; download; exclusão apenas para admin. Downloads devem continuar autenticados e auditados conforme RN011.

**Pré-visualização:** usar um viewer ou visualização de página confiável; apresentar nome do relatório, versão/data, paginação e ações de download/fechar. Não renderizar o PDF dentro de um container com altura arbitrária que gere barras de rolagem aninhadas ruins.

## 5.10 Base de conhecimento

Criar uma experiência de leitura técnica editorial. Listagem com busca, categoria, título e resumo. Detalhe com descrição, impacto, remediação passo a passo, referências e links de findings relacionados quando disponíveis.

Edição deve ser reservada a papéis autorizados, com formulário legível, preview de conteúdo e avisos de alteração. A base é o conteúdo de domínio editável; não confundir alterações na Knowledge Base com o histórico imutável de scans/evidências/auditoria.

## 5.11 Auditoria e permissões

A trilha de auditoria precisa privilegiar integridade e consulta: data/hora, ator, evento, entidade relacionada e detalhes existentes. Filtros por período, ator, ação e tipo de entidade quando suportados.

Não oferecer editar/apagar registros de auditoria. Mostrar claramente ausência de permissão e não carregar informações administrativas para `viewer` se não autorizado. A UI oculta ações não autorizadas, mas a API continua sendo a autoridade final da permissão.

## 5.12 Conta, sessão e falhas globais

Criar padrões consistentes para: token expirado, logout, falha de refresh, perda de conexão, API indisponível, acesso negado, rota inexistente e sessão sem permissão. Se refresh falhar, limpar o estado local com segurança e direcionar para login com aviso claro, sem loop de redirecionamento.

---

## 6. PDFs: uma publicação profissional, não uma impressão da interface

O relatório PDF é parte central do produto e precisa ter linguagem própria. **Não usar o tema escuro da aplicação como modelo de página.** O PDF deve ser claro, limpo, excelente na tela e impresso, com tipografia editorial, margens generosas e hierarquia consistente.

### 6.1 Sistema editorial

- Papel A4, margens consistentes, grid editorial e linhas de texto confortáveis.
- Fundo branco ou branco quente; texto quase preto; cinzas neutros; cores de severidade apenas para dados que realmente representem severidade.
- Cabeçalho discreto com marca, classificação/confidencialidade quando aplicável e identificador do relatório.
- Rodapé com número de página, título abreviado e data de geração; evitar excesso de elementos fixos.
- Capa sem grandes efeitos: marca, título, organização/alvo, tipo do relatório, intervalo ou data do scan, data de emissão e versão.
- Sumário com numeração correta; seções sem viúvas/órfãs e tabelas sem cabeçalho perdido em outra página.
- Gráficos vetoriais quando possível, rótulos legíveis e alternativa textual dos principais números.
- Links de referência clicáveis quando apropriado; metadados PDF e fontes embutidas.

### 6.2 Relatório executivo

Público: liderança, gestor técnico e responsável pela remediação. Deve responder o que foi avaliado, quão confiável é o resultado, qual o maior risco e o que fazer primeiro.

Estrutura sugerida:

1. Capa.
2. Resumo executivo — objetivo, escopo, data e limites.
3. Panorama de risco — somente métricas derivadas dos dados reais do scan.
4. Distribuição de achados por severidade e categorias relevantes.
5. Principais riscos priorizados, com impacto em linguagem clara.
6. Cadeias de risco relevantes, se houver.
7. Plano de ação recomendado por prioridade.
8. Cobertura e limitações da avaliação.
9. Apêndice com metodologia, nomenclaturas e referências essenciais.

O relatório deve evitar listas intermináveis de portas e detalhes de payload. Usar tabelas curtas e explicações voltadas a decisão.

### 6.3 Relatório técnico

Público: pentester, analista, time de engenharia e segurança. Deve ser reproduzível, auditável e útil para remediação.

Estrutura sugerida:

1. Capa e controle do documento.
2. Sumário.
3. Escopo, alvos, datas, configuração do scan e limitações.
4. Metodologia e tipos de checagem realizados.
5. Sumário técnico de risco.
6. Inventário de ativos, serviços, tecnologias e observações pertinentes.
7. Findings por prioridade.
8. Para cada finding: ID; título; severidade; ativo afetado; estado de triagem; confiança/limitação quando disponível; descrição; impacto; evidência; prova de impacto quando comprovada; remediação; referências CVE/NVD, CWE, OWASP e MITRE quando existentes.
9. Matriz de cobertura OWASP 2021 e 2025, com os estados testada/encontrada/provada e limitações.
10. Cadeias de risco com justificativa.
11. Narrativa de ataque apenas quando houver exploração comprovada e dados que sustentem cada etapa.
12. Regras Sigma disponíveis, sem fabricar regra para classes sem conteúdo curado.
13. Referências e apêndices.

### 6.4 Tratamento rigoroso da evidência

- Distinguir sempre **detecção**, **confirmação** e **prova de impacto**.
- Não rotular uma categoria como segura só porque nenhum finding foi encontrado.
- Apresentar limitações e cobertura não testada.
- Não criar valores, CVSS, ativos, eventos, datas ou conclusões que não existam na origem.
- Não colocar uma narrativa de ataque como fato se as etapas não estiverem sustentadas por evidências.
- Proteger quebras de página: não dividir cabeçalho de finding de seu conteúdo; manter rótulos e valores próximos; repetir cabeçalhos de tabelas em novas páginas.
- Se uma evidência for longa, usar quebra controlada e bloco monoespaçado; nunca cortar silenciosamente payload, identificador ou artefato.
- Adicionar paginação correta, metadados do documento, nome de arquivo previsível e tratamento de acentos em português.

### 6.5 QA específico de PDF

Criar amostras automatizadas e uma revisão visual real para: relatório vazio/minimalista; um finding; dezenas de findings; evidência longa; texto com acentos; tabelas extensas; todas as severidades; ausência de CVE; ausência de técnica MITRE; sem exploração comprovada; com cadeia de risco; página final e sumário. Conferir também extração/cópia do texto, links, paginação, clipping, fontes, quebras e impressão em escala de cinza.

---

## 7. Biblioteca de componentes do design system

Aproveitar Radix/shadcn/ui como base acessível, mas customizar a aparência e o comportamento. Os componentes prontos não devem determinar a identidade do produto.

### Fundação

- `AppShell`, `Sidebar`, `Topbar`, `PageHeader`, `Breadcrumbs`, `ContentSection`.
- `Button` com variantes primária, secundária, outline, ghost e destructive.
- `IconButton` com nome acessível e tooltip.
- `Input`, `PasswordInput`, `Textarea`, `Select`, `Combobox`, `DatePicker` e `Checkbox` com estados completos.
- `Badge`/`StatusPill` para status textual e `SeverityIndicator` para severidade.
- `Tooltip`, `Popover`, `DropdownMenu`, `Dialog`, `Drawer`, `Tabs` e `Accordion`.
- `Toast`, `InlineAlert`, `ErrorPanel`, `EmptyState`, `Skeleton` e `LoadingIndicator`.
- `CopyButton`, `CodeBlock`, `KeyValueList`, `MonospaceValue` e `Timestamp`.

### Dados e análise

- `DataTable` com ordenação, filtros, paginação, seleção em lote quando autorizada e estados vazios.
- `FilterBar` com filtros ativos visíveis e opção de limpar.
- `KpiMetric` com legenda, período/escopo quando aplicável e variação apenas se houver dado comparativo real.
- `SeverityDistribution`, `CoverageMatrix`, `RiskChain`, `ScanProgress`, `AssetSummary`, `FindingSummary`.
- `EvidenceViewer`, `SigmaRuleViewer`, `ReportPreview` e `ReportGenerationForm`.

### Contrato de cada componente

Cada componente deve especificar: propósito, variantes, props, teclado/foco, loading, disabled, erro, vazio, conteúdo longo, comportamento mobile e exemplos. Não criar um componente global antes de saber quais estados e diferenças reais ele precisa suportar.

---

## 8. Responsividade e adaptação de conteúdo

Breakpoints de referência: 360 px, 390 px, 768 px, 1024 px, 1280 px, 1440 px e 1920 px. O comportamento deve ser verificado nesses tamanhos ou próximos deles, incluindo zoom do navegador.

### Desktop amplo

Sidebar expandida, tabelas completas e layouts em duas colunas quando melhorarem comparação. Evitar esticar formulários e parágrafos por toda a largura.

### Laptop e tablet

Sidebar compacta quando apropriado, painéis que passam de duas colunas para uma, filtros que podem abrir em drawer e tabelas com colunas menos críticas ocultadas ou deslocadas para detalhe.

### Mobile

Sidebar em drawer; cabeçalho com título e ação principal sem sobreposição; KPIs em uma coluna ou grade reduzida; filtros em painel; tabela convertida em linhas-resumo/cartões quando horizontalmente ilegível; detalhes técnicos com quebra de linha e controle de cópia; modais transformados em telas/drawers adequados.

### Regras de adaptação

- Não usar `overflow-x: hidden` para esconder bugs de layout.
- Não reduzir todo o site via escala ou fontes minúsculas.
- Não fixar alturas de cards que cortem textos, etiquetas, validações ou botões.
- Conteúdo longo deve quebrar ou ter truncamento explícito com acesso ao valor completo.
- Nunca permitir que dropdowns, tooltips ou botões fiquem fora do viewport sem uma alternativa.
- Testar áreas seguras e teclado virtual em telas pequenas.

---

## 9. Estados de interface que precisam ser desenhados

Uma página só está pronta quando todos os seus estados relevantes foram implementados e testados.

1. **Loading inicial:** skeleton que respeita o layout real, sem saltos grandes.
2. **Atualização em background:** indicador discreto; não substituir conteúdo estável por skeleton a cada polling.
3. **Vazio genuíno:** explica por que não há conteúdo e apresenta próxima ação autorizada.
4. **Sem resultados:** diferencia “não há dados” de “os filtros não retornaram resultados”.
5. **Erro de validação:** junto ao campo e no resumo quando necessário; mensagem acionável.
6. **Erro de API/rede:** explicar falha e oferecer retry quando seguro; preservar filtros e formulário.
7. **Sem permissão:** não expor controle funcional; ao acessar URL direta, mostrar estado de acesso negado apropriado.
8. **Operação bloqueada por política:** por exemplo, scan não autorizado, autorização expirada ou kill-switch desligado.
9. **Operação em andamento:** mostrar status verdadeiro, prevenção de dupla ação e caminho de cancelamento permitido.
10. **Sucesso:** somente após confirmação real; preservar feedback onde o usuário o verá.
11. **Estado destrutivo:** confirmação específica para exclusões, com consequência explícita.
12. **Conteúdo incompleto:** indicar dado ausente/limitação em vez de preencher com estimativa disfarçada de fato.

### Microcopy

Usar português técnico natural e consistente. Preferir verbos explícitos: “Criar alvo”, “Iniciar scan”, “Cancelar scan”, “Marcar como corrigido”, “Gerar relatório”. Evitar rótulos vagos como “Executar”, “Continuar” ou “Processar” quando a consequência puder ser dita claramente. Manter nomes de classificações oficiais (CVE, CWE, OWASP, MITRE ATT&CK, Sigma) sem traduções improvisadas.

---

## 10. Acessibilidade e usabilidade

Objetivo mínimo: **WCAG 2.2 nível AA** nos fluxos críticos, com validações manuais além de ferramentas automatizadas. A referência do W3C inclui contraste mínimo, navegação por teclado, foco e uso de cor como pontos explícitos de verificação: https://www.w3.org/WAI/WCAG22/quickref/.

Requisitos:

- Contraste de texto normal de pelo menos 4,5:1 e de texto grande de pelo menos 3:1, de acordo com WCAG 2.2 AA.
- Nenhum estado transmitido apenas pela cor; combinar cor, rótulo e/ou ícone vetorial apropriado.
- Fluxos principais operáveis por teclado; foco sempre visível, lógico e não encoberto por header/drawer/modal.
- Labels persistentes, mensagens de erro associadas ao campo e anúncio apropriado de mudanças de estado.
- Modais com foco controlado, fechamento previsível e retorno de foco ao acionador.
- Alvos interativos confortáveis para toque; conferir tamanho e espaçamento nos breakpoints pequenos.
- Respeitar `prefers-reduced-motion`, zoom e aumento de texto.
- Gráficos com resumo acessível ou tabela equivalente.
- PDF com texto selecionável, ordem de leitura razoável e contraste legível; avaliar tagging/acessibilidade de PDF conforme a capacidade da ferramenta utilizada.

---

## 11. Plano técnico para implementar sem regressões

### 11.1 Primeiro, mapear antes de substituir

Antes de editar, o agente de desenvolvimento deve inspecionar o repositório e documentar:

- Rotas existentes e componentes de cada página.
- Tokens CSS e configuração do tema atual.
- Componentes shadcn/ui já existentes e customizações locais.
- Chamadas API, hooks React Query, store Zustand e permissões.
- Estados atuais de loading/erro/vazio.
- Páginas e endpoints reais para cada funcionalidade listada no README.
- Implementação atual dos PDFs no `backend/apps/reports/pdf/` ou diretório equivalente confirmado no repositório.

Não apagar componentes ou rotas em massa antes de entender dependências. Não presumir endpoints além dos documentados/descobertos no código.

### 11.2 Tokens semânticos

Concentrar cores, tipografia, radius, spacing, sombras, z-index e motion em uma camada compartilhada. A documentação do shadcn/ui recomenda tokens semânticos via CSS variables para que o tema possa mudar sem reescrever classes de cada componente: https://ui.shadcn.com/docs/theming.

Regras técnicas:

- Usar tokens como `background`, `foreground`, `card`, `popover`, `primary`, `muted`, `border`, `input`, `ring`, além de tokens próprios para severidade e status.
- Não espalhar hexadecimais em JSX.
- Não adicionar dependência visual nova sem necessidade real.
- Manter os componentes Radix/shadcn como base comportamental onde forem adequados; redesenhar as variantes e composições.
- Evitar CSS global com seletores frágeis que alterem componentes inesperados.
- Centralizar formatadores de datas, bytes, percentuais, status, severidade e identificadores.
- Evitar duplicar fetch state no Zustand quando React Query já é a fonte adequada para dados remotos.
- Preservar invalidação e atualização do cache depois de criação, triagem, cancelamento e exclusão.

### 11.3 Arquitetura de componentes

Organização sugerida, adaptando ao que já existe:

- `components/brand/`: logotipo, símbolo e assets da marca.
- `components/layout/`: shell, sidebar, topbar, breadcrumb e cabeçalho.
- `components/ui/`: primitivos gerais e variantes personalizadas.
- `components/data-display/`: tabelas, métricas, severidade, códigos e timestamps.
- `components/security/`: escopo, autorização, scan state, finding, evidence e risk chain.
- `components/reports/`: geração, histórico e preview.
- `styles/tokens.css` ou arquivo global já utilizado para o tema.

Não criar abstrações excessivas nem mover todos os arquivos só para obedecer a essa sugestão. O objetivo é ter componentes reaproveitáveis e responsabilidades claras, respeitando a arquitetura real do projeto.

### 11.4 Testes técnicos

- Rodar build/typecheck e os testes existentes antes de mudanças para obter baseline.
- Depois de cada fase, executar `npm run build` e `npm test` nos comandos reais do projeto; não assumir que os comandos existem sem conferir `package.json`.
- Corrigir avisos relevantes de React, TypeScript, keys, acessibilidade e console.
- Testar autenticação e RBAC, estados de erro e refresh JWT sem alterar a semântica de segurança.
- Confirmar que filtros e paginação continuam funcionando com a API real.
- Validar geração/download/preview de PDFs em navegador e arquivo baixado.
- Não remover ou enfraquecer testes para “passar” o redesign.

---

## 12. Fases de execução

A implementação deve ser incremental para reduzir risco, mas a identidade visual deve ser definida antes de redesenhar páginas isoladas.

### Fase 0 — Auditoria de UI e inventário

**Entrega:** mapa de rotas, dependências, tokens atuais, componentes reutilizáveis, pontos inconsistentes, endpoints usados e screenshots de baseline.

**Aceite:** nenhuma alteração funcional; inventário de todos os estados e páginas; dependências incertas documentadas.

### Fase 1 — Direção de arte e design system

**Entrega:** tokens semânticos; tipografia; grid; sidebar/topbar; buttons; fields; badges; tabelas; modais; toasts; estados de loading/erro/vazio; marca vetorial.

**Aceite:** tela de demonstração interna com todos os componentes e estados; contraste verificado; nenhum componente genérico sem variantes definidas.

### Fase 2 — Autenticação e shell

**Entrega:** login; estado de sessão expirada; shell responsivo; navegação RBAC; padrões globais de erro e feedback.

**Aceite:** fluxos de login/logout/refresh e permissão funcionam com a API atual; navegação utilizável por teclado; layout estável nos breakpoints previstos.

### Fase 3 — Fluxo crítico de operação

**Entrega:** alvos/autorização, criação de scan, lista e detalhe/progresso/cancelamento.

**Aceite:** escopo e validade aparecem antes de iniciar operação; kill-switch e gates são comunicados corretamente; não existe progresso artificial; confirmações e permissões respeitam backend.

### Fase 4 — Análise e investigação

**Entrega:** dashboard, inventário de ativos, vulnerabilidades, detalhe de finding, evidências/playbooks, matriz OWASP e cadeias de risco.

**Aceite:** detecção e prova de impacto diferenciadas; filtros e links entre entidades consistentes; estados vazios e limitações apresentados corretamente.

### Fase 5 — Relatórios e documentos

**Entrega:** tela de relatórios, geração, preview, download; redesign das saídas PDF executivo e técnico; CSV/JSON preservados.

**Aceite:** PDFs sem clipping/overflow; conteúdo verdadeiro; paginação; fontes e acentos corretos; narrativa condicionada a evidência; visualização em mobile e desktop.

### Fase 6 — Acabamento, acessibilidade e QA

**Entrega:** revisão de cada tela, correção de inconsistências, testes visuais, keyboard pass, responsividade, regressão e documentação do design system.

**Aceite:** checklist final aprovado; nenhum bug visual conhecido em rotas e breakpoints cobertos; build e suíte de testes passam.

---

## 13. Matriz mínima de QA visual

Validar cada rota importante em pelo menos estes cenários:

| Cenário | O que conferir |
|---|---|
| 1440 × 900 | Hierarquia, alinhamento, densidade, uso de largura e sidebar |
| 1280 × 800 | Tabelas, formulários, drawers e conteúdo sem sobreposição |
| 1024 × 768 | Transição desktop/tablet e ações principais visíveis |
| 768 × 1024 | Navegação adaptada, filtros e tabelas úteis |
| 390 × 844 | Header, drawer, botões, forms e conteúdo técnico |
| 360 × 800 | Sem overflow global, clipping ou controles inacessíveis |
| Zoom 200% | Conteúdo permanece operável sem perda de função |
| Dados longos | Hosts, IPv6, CVEs, títulos, nomes de usuário, códigos e evidências |
| Dados vazios | Zero alvos, zero findings, nenhum scan, nenhum relatório |
| Erros | API indisponível, 401/403, validação, timeout, ação rejeitada |
| Permissões | `admin`, `analyst` e `viewer` conforme regras existentes |
| Operação em curso | Estado verdadeiro, polling estável, cancelamento permitido |
| PDF | Capa, sumário, página intermediária, tabela longa, última página e impressão |

### Bugs visuais que bloqueiam entrega

- Texto cortado sem forma de acessar o conteúdo.
- Botões, dropdowns, tooltips, menus ou modais fora da viewport.
- Sobreposição entre header, conteúdo, toast, drawer ou modal.
- Horizontal overflow inesperado na aplicação inteira.
- Layout que muda de altura continuamente por polling ou skeleton.
- Cor de texto insuficiente, foco invisível ou status comunicados apenas por cor.
- Gráfico sem rótulo/unidade ou sem interpretação equivalente.
- Estado vazio que parece carregamento quebrado.
- Ações que parecem clicáveis, mas não funcionam.
- Confirmações destrutivas vagas ou inconsistentes.
- PDF com fonte ausente, acento quebrado, conteúdo cortado, paginação errada ou tabela ilegível.

---

## 14. Critérios de aceite do redesign completo

O redesign só estará concluído quando:

1. Todas as rotas existentes estiverem alinhadas ao novo sistema visual.
2. Login, navegação, formulários, tabelas, detalhes, filtros, diálogos e feedback estiverem consistentes.
3. As telas funcionarem com dados reais e todos os estados de carregamento, vazio, erro, bloqueio e sucesso estiverem cobertos.
4. RBAC continuar respeitado tanto na interface quanto nas chamadas à API.
5. As regras de escopo, expiração, kill-switch, opt-in e auditoria não forem enfraquecidas por alterações de UX.
6. Não existirem emojis em nenhum elemento da interface ou nos PDFs.
7. Não existirem números ou eventos falsos usados como preenchimento visual.
8. O layout estiver testado nos breakpoints definidos e com zoom ampliado.
9. O contraste, teclado, foco, labels e mensagens de estado atenderem ao objetivo WCAG 2.2 AA nos fluxos críticos.
10. PDF executivo e técnico tiverem identidades editoriais próprias, legibilidade, conteúdo íntegro e tratamento de paginação.
11. Build, typecheck e testes existentes passarem; regressões forem corrigidas, não mascaradas.
12. O repositório possuir documentação breve dos tokens, componentes e padrões de interação adotados.

---

## 15. Referências técnicas utilizadas

- README do Byakugan fornecido no contexto: funcionalidades existentes, estrutura de frontend/backend, API resumida, controles RN007/RN015/RN016/RN021–RN023, taxonomias, relatórios e RBAC.
- [Documentação oficial de theming do shadcn/ui](https://ui.shadcn.com/docs/theming): uso de CSS variables e tokens semânticos para personalização consistente.
- [W3C — WCAG 2.2 Quick Reference](https://www.w3.org/WAI/WCAG22/quickref/): contraste, teclado, foco, uso de cor e requisitos de acessibilidade.

---

## Resultado esperado

O Byakugan deve parecer um produto proprietário, deliberadamente desenhado para profissionais de segurança que trabalham com dados sensíveis e decisões de alto impacto. A excelência visual virá da consistência e da clareza dos detalhes — não de efeitos chamativos. A aplicação deve ser visualmente distinta, rápida de ler, previsível sob pressão, utilizável em diferentes telas e honesta sobre o que foi testado, encontrado e comprovado.
