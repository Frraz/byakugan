# Redesign — ponto de retomada

Atualizado em **11/10/2026** a partir da documentação, do código e do histórico Git.

## Onde o trabalho parou

A referência a **“Fase E (QA)”** está no comentário de `frontend/src/index.css`.
O plano mestre usa fases **0–6**, sem letras; a etapa correspondente pelo conteúdo
é a **Fase 6 — Acabamento, acessibilidade e QA**. Não foi localizado um checklist
de conclusão da Fase E. Portanto, esse é o ponto recomendado de retomada, não
uma certificação de que todas as fases anteriores passaram pelo aceite.

O commit `8b2b982` já reúne a identidade Forensic Instrument, os tokens claro/escuro,
a marca vetorial, ajustes de login e shell, matriz OWASP, evidências/Sigma, base de
conhecimento, auditoria e PDFs com acento em latão. A existência dessas implementações
foi conferida no código; não equivale a uma validação visual de todas as telas.

| Área do plano | Evidência no repositório | Situação de aceite |
|---|---|---|
| 0 — Auditoria | Plano mestre e documentação de UI | Baseline visual completo não documentado |
| 1 — Sistema visual | `index.css`, `tailwind.config.js`, `components/ui/`, `brand/Logo.tsx` | Contraste e demonstração de todos os estados pendentes |
| 2 — Autenticação e shell | `LoginPage`, `AppLayout`, stores de autenticação/tema | Revisão de teclado, sessão e permissões pendente |
| 3 — Operação | Alvos, formulário/lista/detalhe de scans | Revisão ponta a ponta com API pendente |
| 4 — Investigação | Dashboard, ativo, findings, evidências, `OwaspCoverageMatrix` | Revisão visual e funcional integrada pendente |
| 5 — Documentos | Relatórios, preview PDF/JSON e PDF editorial ReportLab | Inspeção de PDFs longos, fontes e mobile pendente |
| 6 / referência E — QA | Primeira rodada de correções e testes abaixo | **Em andamento** |

## Rodada de retomada

- [x] Distinguir carregamento, erro recuperável e ausência real de scans no gerador de relatórios.
- [x] Permitir selecionar scans concluídos além da primeira página da API.
- [x] Nomear campos e filtros para tecnologias assistivas.
- [x] Bloquear nova submissão e mudanças no formulário durante geração; resetar erro ao reabrir.
- [x] Diferenciar ausência de relatórios de ausência de resultados filtrados; oferecer limpar filtros.
- [x] Adicionar nova tentativa ao preview e à listagem em caso de erro.
- [x] Ignorar leitura JSON atrasada após troca/fechamento do preview; preservar liberação da URL do PDF.
- [x] Limitar altura/largura dos diálogos à viewport e permitir rolagem; separar cabeçalho e download no mobile.
- [x] Testar estados do formulário, paginação e ciclo de vida do preview com Vitest/Testing Library.

As mudanças de layout acima ainda exigem inspeção em navegador. Testes de componentes
em jsdom não verificam dimensões, contraste, comportamento do visualizador PDF ou zoom.

## Próxima sequência de QA

1. Validar login → alvo → scan → finding/evidência → relatório com API local e dados de laboratório.
2. Conferir cada rota nos seis breakpoints do §13 do plano mestre, temas claro/escuro,
   zoom de 200%, navegação por teclado e conteúdo longo. Registrar evidência e resultado por cenário.
3. Medir contraste dos tokens e das variantes com transparência, inclusive badges,
   texto secundário, foco e ações destrutivas.
4. Revisar as permissões: `usePermissions` atualmente libera `canWrite` e `isAdmin`
   para qualquer usuário autenticado, uma escolha documentada do deployment privado.
   Isso diverge do objetivo de navegação por papel do plano; o backend mantém RBAC.
   Resolver essa decisão antes de declarar o aceite de permissões. Esta rodada não altera essa política.
5. Gerar PDFs executivo/técnico com campos longos, acentos, múltiplas páginas e muitos findings;
   inspecionar capa, cabeçalhos, tabelas, última página e impressão. Verificar fontes embutidas.
6. Executar regressão integrada e registrar as limitações restantes antes de encerrar a fase.

Busca global, formulários com react-hook-form/zod, geração assíncrona e gestão de usuários
continuam backlog de evolução; não devem ser confundidos com correções visuais já entregues.

## Verificação desta rodada

- Frontend: `npm test` — **18 testes aprovados** (7 novos).
- Frontend: `npm run build` — inclui verificação TypeScript e bundle Vite.
- Backend: **45 testes de relatórios aprovados** (API, payload, renderização e OWASP),
  usando o ambiente `/tmp/byakugan-venv` com SQLite em memória. O `.venv` do backend
  não possui pytest. Esta execução local não substitui o CI com PostgreSQL; sem scans reais.
- QA visual completo, E2E com API e contraste: **pendentes**.
