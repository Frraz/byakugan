FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependências de sistema mínimas
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements-dev.txt ./
ARG INSTALL_DEV=false
RUN pip install -r requirements.txt \
    && if [ "$INSTALL_DEV" = "true" ]; then pip install -r requirements-dev.txt; fi

COPY . .
RUN chmod +x entrypoint.sh

# Usuário não-root (hardening — ver docs/security.md)
# media/reports é criado aqui (mesmo vazio) para que o volume nomeado do
# compose de produção (report_media:/app/media) herde o dono correto ao ser
# inicializado — Docker copia conteúdo E permissões do diretório da imagem
# para dentro de um volume nomeado vazio na primeira montagem.
RUN useradd --create-home appuser \
    && mkdir -p /app/media/reports \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# entrypoint aplica migrações/collectstatic e então executa o CMD abaixo.
ENTRYPOINT ["./entrypoint.sh"]
# Produção: gunicorn. Em dev, o docker-compose.yml sobrescreve com runserver.
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", \
     "--workers", "3", "--timeout", "60", \
     "--access-logfile", "-", "--error-logfile", "-"]
