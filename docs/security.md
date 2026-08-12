# Segurança do Byakugan

> Este documento descreve como o **próprio Byakugan** é protegido. Uma ferramenta de segurança precisa ser exemplar. Security by Design em todos os componentes: Confidencialidade, Integridade, Disponibilidade e Auditabilidade.

## Autenticação
- **JWT** com dois tokens:
  - Access Token — expira em **15 minutos**.
  - Refresh Token — expira em **7 dias**.
- Rotação de refresh token e blacklist no logout.
- Assinado com `JWT_SECRET` (env própria, separada de `DJANGO_SECRET_KEY` — rotacionar uma não afeta a outra; sem `JWT_SECRET` definida, cai no `DJANGO_SECRET_KEY`). Rotacionar `JWT_SECRET` invalida todos os tokens já emitidos.

## Controle de acesso (RBAC)
| Papel | Acesso |
| --- | --- |
| Administrator | Total (inclui gestão de usuários e exclusões). |
| Security Analyst | Criar scans e consultar resultados. |
| Viewer | Somente leitura. |

Autorização verificada por permissão em cada endpoint (DRF permissions).

## Proteção de senhas
- Hashing com **Argon2** (salt automático).
- **Nunca** armazenar senha em texto puro.
- Política de senha forte na criação.

## Comunicação
- **HTTPS obrigatório em produção**, TLS 1.2+ (preferência TLS 1.3).
- HTTP proibido em produção; redirect forçado + HSTS.

## Segurança da API
- **Rate limiting** (throttling do DRF) por usuário/IP.
- Validação e **sanitização** de toda entrada.
- Proteção **CSRF** (endpoints baseados em sessão) e **CORS** restrito às origens conhecidas.
- Cabeçalhos de segurança: CSP, HSTS, X-Frame-Options, X-Content-Type-Options.

## Auditoria
Todos os eventos sensíveis são registrados (imutável): login, logout, criação/execução/cancelamento de scan, exportação de relatório, exclusão de registro, mudanças de permissão.

Log estruturado (JSON) com campos: `timestamp`, `user`, `action`, `severity`, `source`, `metadata`.

## Segredos
- Nunca em código-fonte. Lidos de `.env` (ver `.env.example`).
- Futuro: Secret Manager (Vault/cloud) em produção.

## Banco de dados
- Backups automáticos.
- Criptografia em trânsito.
- Princípio do menor privilégio para o usuário da aplicação.

## Hardening (produção)
- Containers **não privilegiados** e usuário **não-root**.
- Imagens mínimas; dependências fixadas.
- Cabeçalhos de segurança aplicados no gateway/nginx.

## Dependências
- **SCA** (Software Composition Analysis) no CI.
- Verificação de vulnerabilidades e atualizações regulares (Dependabot/`pip-audit`/`npm audit`).

## Conformidade / referências
OWASP Top 10 · OWASP ASVS · NIST CSF · CIS Controls.

## Kill-switch de varredura (protótipo)
Por ser um protótipo de uso restrito (nunca público; apenas empresas de cybersecurity com autorização documentada), a execução real de varredura é gated pela env **`BYAKUGAN_SCANNING_ENABLED`** (default **desligado**). Com o switch desligado, scans são registrados mas não executam varredura real — falham de forma controlada e auditada. Combinado com o enforcement de escopo (RN007), evita varredura acidental ou fora de laboratório autorizado.

## Uso ético (ver também CLAUDE.md §2)
O Byakugan só opera contra alvos autorizados. A plataforma registra a autorização de cada scan e não implementa recursos cujo propósito primário seja uso ofensivo não autorizado ou evasão maliciosa.
