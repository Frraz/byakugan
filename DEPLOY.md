# Deploy — Byakugan no servidor Ferzion

> Guia específico para o VPS `warley.dev.ferzion.com.br` (147.93.15.214), onde
> convivem vários sistemas Docker atrás de um único nginx no host. Este guia
> segue as convenções de `/var/www/docker-instances/README.md`.

## Regras de ouro do servidor (não quebrar)

1. **Nenhum container mapeia 80/443.** Só o nginx do HOST é dono dessas portas.
   O `docker-compose.prod.yml` do Byakugan não publica 80/443.
2. **O web publica apenas em `127.0.0.1:8012`** (loopback). O nginx do host faz o proxy.
3. **Banco e Redis não expõem portas ao host** — ficam só na rede interna do compose.
4. **container_name prefixado** com `byakugan_` para não colidir (`byakugan_db`,
   `byakugan_redis`, `byakugan_web`, `byakugan_celery`).

Reserva deste projeto:

| Recurso | Valor |
| --- | --- |
| Domínio | `byakugan.ferzion.com.br` |
| Porta loopback (web) | `127.0.0.1:8012` |
| Diretório | `/var/www/docker-instances/Byakugan` |
| Compose | `docker-compose.prod.yml` |
| Settings | `config.settings.production` |

> As portas 8001-8006, 8010, 8011, 8080, 8110 e 9000 já estão em uso. Antes de
> subir, **confirme que a 8012 está livre**:
> ```bash
> ss -tlnp | grep 8012 || echo "8012 livre"
> ```
> Se estiver ocupada, escolha outra e atualize `docker-compose.prod.yml` e o
> `.conf` do nginx.

---

## 1. Enviar o código

```bash
cd /var/www/docker-instances
git clone <repo> Byakugan   # ou: rsync/scp do projeto para cá
cd Byakugan
```

## 2. Configurar o ambiente

```bash
cp .env.production.example .env
nano .env   # preencher DJANGO_SECRET_KEY, POSTGRES_PASSWORD, JWT_SECRET, etc.
```

Gerar uma secret forte:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```

## 3. Subir os containers (backend + db + redis + celery)

```bash
cd /var/www/docker-instances/Byakugan
docker compose -f docker-compose.prod.yml up -d --build
```

O `entrypoint.sh` aplica as migrações e roda `collectstatic` automaticamente.
Verificar:
```bash
docker ps --filter "name=byakugan"
docker logs byakugan_web --tail 30
# health direto no gunicorn (loopback):
curl -s -H "X-Forwarded-Proto: https" http://127.0.0.1:8012/api/health/
```

## 4. Build do frontend (SPA)

O nginx do host serve o SPA a partir de `frontend/dist`. Gerar o build
(usa Docker, não precisa de Node no host):

```bash
cd /var/www/docker-instances/Byakugan
./deploy/build-frontend.sh
# saída em frontend/dist (VITE_API_BASE_URL=/api por padrão — mesma origem)
```

## 5. Configurar o nginx do host

```bash
sudo cp deploy/nginx/byakugan.ferzion.com.br.conf \
  /etc/nginx/sites-available/byakugan.ferzion.com.br
sudo ln -s /etc/nginx/sites-available/byakugan.ferzion.com.br \
  /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

## 6. Emitir o certificado SSL

O certbot edita o `.conf` e adiciona o bloco 443 + redirect automaticamente
(não adicione SSL manualmente antes):

```bash
sudo certbot --nginx -d byakugan.ferzion.com.br
```

## 7. Verificação final

```bash
curl -I https://byakugan.ferzion.com.br            # SPA (200)
curl -s https://byakugan.ferzion.com.br/api/health/  # {"status":"ok",...}
```

Criar um superusuário para o admin:
```bash
docker exec -it byakugan_web python manage.py createsuperuser
```

---

## Atualizações (redeploy)

```bash
cd /var/www/docker-instances/Byakugan
git pull origin main
docker compose -f docker-compose.prod.yml up -d --build   # backend
./deploy/build-frontend.sh                                 # frontend
sudo systemctl reload nginx                                # se mudou o .conf
```

## Parar / remover

```bash
docker compose -f docker-compose.prod.yml down       # para (mantém o volume do banco)
docker compose -f docker-compose.prod.yml down -v     # CUIDADO: apaga o banco
```

## Checagem anti-interferência (antes de subir)

```bash
# Nenhum mapeamento de 80/443 neste compose (deve retornar vazio):
grep -E '"80:80"|"443:443"' docker-compose.prod.yml || echo "OK: sem 80/443"

# Confirmar que o web está só no loopback:
grep -E '127\.0\.0\.1:8012' docker-compose.prod.yml && echo "OK: loopback"
```

## Monitoramento

Adicionar `https://byakugan.ferzion.com.br` ao UptimeRobot (HTTPS, 5 min),
como os demais sistemas.
