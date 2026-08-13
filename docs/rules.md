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
| RN015 | Um `Target` com `authorization_expires_at` no passado bloqueia a criação de novos scans contra ele (`403` + auditoria `scan.authorization_expired`). A expiração é reavaliada a cada tentativa de scan, não apenas no cadastro. |
| RN016 | Todo teste ativo (web, credenciais default, injeção) é **detecção, não exploração**: usa marcadores inertes/únicos em vez de payloads vivos, é idempotente (GET/OPTIONS/TRACE; nunca PUT/DELETE/escrita), e limita testes time-based a uma única requisição curta, restrita à intensidade `aggressive`. Nenhuma funcionalidade pode alterar, apagar ou indisponibilizar dados/serviços do alvo. |
| RN017 | A expansão de um alvo em múltiplos hosts (CIDR, lista) é limitada por `max_hosts` (padrão 256, teto absoluto 1024) e **cada host expandido é revalidado individualmente contra o `authorization_scope`** antes de qualquer probe — nenhum host fora do escopo é tocado, mesmo que pertença ao CIDR original autorizado apenas em parte. |
| RN018 | Achados (`Finding`) são identificados por um `dedup_key` (hash de ativo + categoria + título normalizado) que reconhece o "mesmo" achado lógico entre execuções de scan distintas, sem violar a imutabilidade da RN003. Um analista pode **triar** esse achado lógico (`open`/`fixed`/`false-positive`/`accepted-risk`, via `FindingTriage`) — achados triados como `fixed`/`false-positive`/`accepted-risk` são excluídos da soma do `risk_score` e do heatmap, evitando que reexecuções do mesmo scan inflem o risco artificialmente. |
| RN019 | RN008 é validada no próprio modelo (`Finding.clean()`/`save()` chama `full_clean()`), não apenas por convenção do parser — nenhum finding sem `description`/`evidence`/`recommendation` chega a ser persistido, independente do caminho de código que o criou. |
| RN020 | Excluir um ativo (apenas `admin`) remove **em cascata** seus findings (`Finding.asset` é `PROTECT` no schema — removidos explicitamente antes); serviços, tecnologias, registros DNS e triagens associados cascadeiam automaticamente (`CASCADE`). A exclusão é auditada com as contagens do que foi removido. |

## Papéis (RBAC)

| Papel | Permissões |
| --- | --- |
| `admin` | Acesso total, incluindo gestão de usuários e exclusão de registros. |
| `analyst` | Criar/cancelar scans, consultar resultados, gerar relatórios. |
| `viewer` | Somente leitura (assets, scans, findings, reports, knowledge base). |
