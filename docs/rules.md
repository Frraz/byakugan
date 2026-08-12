# Regras de Negócio

> As regras (RN) são invariantes do domínio. Toda feature deve mapear as RNs que a afetam.

| ID | Regra |
| --- | --- |
| RN001 | Todo scan deve possuir um alvo válido (host, domínio ou lista de IPs corretamente formatados). |
| RN002 | Um scan não pode ser executado duas vezes simultaneamente para o mesmo alvo (evita duplicidade e sobrecarga). Retorna `409`. |
| RN003 | Resultados históricos (scans, findings, reports) nunca podem ser sobrescritos. São imutáveis. A exclusão administrativa da RN014 é a única exceção controlada. |
| RN004 | Toda vulnerabilidade/finding com CVE associado deve possuir classificação de severidade e, quando disponível, CVSS. |
| RN005 | Todo relatório deve manter rastreabilidade com o scan que o originou. |
| RN006 | Apenas administradores podem excluir registros; exclusões são auditadas. |
| RN007 | Nenhum scan pode ser executado sem registro de autorização (`authorized_by` + escopo). Uso não autorizado é proibido. |
| RN008 | Nenhum finding pode ser salvo sem `description`, `evidence` e `recommendation` (finding sem contexto é inválido). |
| RN009 | A IA nunca executa ações que alterem sistemas; apenas analisa, explica, resume e recomenda. A decisão final é do usuário. |
| RN010 | Estados de scan seguem a máquina: `pending → running → (completed | failed | cancelled)`. Transições inválidas são rejeitadas. |
| RN011 | Todo evento sensível (login, criação/execução de scan, exportação e exclusão) gera registro de auditoria. |
| RN012 | Relatórios só podem ser gerados a partir de scans com status `completed` (dados parciais de scans em execução/falhos não geram relatório). Retorna `409`. |
| RN013 | Nenhum artigo da Knowledge Base pode ser salvo sem `summary`, `impact` e ao menos um passo em `remediation_steps` (conteúdo sem contexto não é publicado). |
| RN014 | Excluir um scan (apenas `admin`) remove **em cascata** seus findings e relatórios, incluindo os artefatos em disco. Scans `pending`/`running` não podem ser excluídos (retorna `409` — cancele antes). A exclusão é auditada com as contagens do que foi removido. |

## Papéis (RBAC)

| Papel | Permissões |
| --- | --- |
| `admin` | Acesso total, incluindo gestão de usuários e exclusão de registros. |
| `analyst` | Criar/cancelar scans, consultar resultados, gerar relatórios. |
| `viewer` | Somente leitura (assets, scans, findings, reports, knowledge base). |
