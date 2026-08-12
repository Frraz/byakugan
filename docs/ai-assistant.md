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
Findings · Vulnerabilities · CVEs · Knowledge Base · relatórios anteriores · histórico do ambiente.

A IA opera **apenas sobre dados já coletados** pelo Byakugan — não inventa fatos nem assume exploração bem-sucedida.

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
- Chat com contexto completo do ambiente.
- Consultas em linguagem natural sobre os dados.
- Geração automática de relatórios.
- Assistentes especializados (SOC, DevSecOps).
