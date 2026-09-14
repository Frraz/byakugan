# AI Assistant

> Analista virtual de segurança integrado ao Byakugan. Transforma resultados técnicos em informação acionável para analistas e gestores.

## Princípios (RN009)

A IA **nunca executa ações** que alterem sistemas. Ela apenas:
- Analisa · Explica · Resume · Recomenda.

A **decisão final é sempre do usuário**. A IA não pode: executar ações, alterar sistemas, excluir dados ou decidir pelo usuário.

## Provedor
- Recomendado: **Anthropic (Claude)** — configurável via `.env` (`AI_PROVIDER`, `AI_API_KEY`, `AI_MODEL`).
- A chave nunca fica no código; sempre lida do ambiente.

## Fontes de dados
Findings (com classificação **OWASP 2021/2025 + CWE**) · Vulnerabilities · CVEs · **`Evidence`** (impacto comprovado pela exploração) · `ExploitationPlaybook` · Knowledge Base · relatórios anteriores · histórico do ambiente.

A IA opera **apenas sobre dados já coletados** pelo Byakugan — não inventa fatos. Só afirma "exploração bem-sucedida" quando existe uma `Evidence` com status `proven`; caso contrário fala em risco *potencial*.

## Capacidades

### Explicação de vulnerabilidades
Pergunta: "O que significa esta vulnerabilidade?" → descrição, impacto e risco em linguagem clara.

### Sugestão de correção
Entrada: "Apache vulnerável" → atualização recomendada, mitigação temporária e impacto da correção.

### Resumo executivo
Traduz linguagem técnica em linguagem de negócio. Ex.: *"Existem 3 vulnerabilidades críticas que podem impactar sistemas expostos à internet."*

### Priorização
Considera CVSS, exposição, criticidade do ativo e histórico.

### Correlação (IA)
Identifica vulnerabilidades relacionadas, causas comuns, padrões recorrentes e riscos sistêmicos.

## Prompt base (regras do sistema)
- Não inventar informações.
- Não assumir exploração bem-sucedida.
- Explicar em linguagem clara.
- Sempre citar as evidências disponíveis.

## Formato de resposta (obrigatório)

```
Resumo: ...
Evidência: ...
Impacto: ...
Recomendação: ...
Confiança: Alta | Média | Baixa
```

## Limitações
A IA não pode executar ações, alterar sistemas, excluir dados ou tomar decisões pelo usuário.

## Futuro
Alinhado ao **norte do projeto** (ajudar a *documentar* e *orientar a remediação* de cada brecha):
- **Orientação de remediação acionável** — a partir do finding + OWASP/CWE + `Evidence`, gerar passos de correção priorizados e específicos ao contexto (mantendo o humano no comando — RN009).
- Chat com contexto completo do ambiente e consultas em linguagem natural sobre os dados.
- Geração automática de relatórios e do texto narrativo.
- Assistentes especializados (SOC, DevSecOps, Red/Blue Team).
