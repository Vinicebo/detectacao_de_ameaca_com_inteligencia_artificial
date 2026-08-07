# syntax=docker/dockerfile:1

# ---------------------------------------------------------------- builder
FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.5.14 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /build
COPY pyproject.toml ./
COPY app ./app

# O container `api` roda só inferência (onnxruntime, ~50 MB). O `detector` também
# treina, e aí precisa do torch — mas da roda CPU: o torch do PyPI traz CUDA junto
# e infla a imagem em vários GB sem uso nenhum aqui.
ARG INSTALL_TRAIN=false
ARG INSTALL_DEV=false
RUN uv venv /opt/venv && \
    EXTRAS="" && \
    if [ "$INSTALL_TRAIN" = "true" ]; then EXTRAS="train"; fi && \
    if [ "$INSTALL_DEV" = "true" ]; then EXTRAS="${EXTRAS:+$EXTRAS,}dev"; fi && \
    if [ -n "$EXTRAS" ]; then \
        uv pip install --extra-index-url https://download.pytorch.org/whl/cpu \
            --index-strategy unsafe-best-match ".[$EXTRAS]"; \
    else \
        uv pip install "."; \
    fi

# ---------------------------------------------------------------- runtime
FROM python:3.12-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl libpq5 && \
    rm -rf /var/lib/apt/lists/*

# Sem root: se o motor de detecção for comprometido por um payload malformado,
# o estrago fica contido.
RUN useradd --create-home --uid 10001 detector

# Estes diretórios recebem volumes nomeados. O Docker inicializa o volume com a
# dona do diretório que já existe na imagem — sem criá-los aqui, o volume nasce
# do root e o processo (uid 10001) não consegue gravar os modelos treinados.
RUN mkdir -p /models /mlruns /data/geoip && \
    chown -R detector:detector /models /mlruns /data

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY --chown=detector:detector app ./app
COPY --chown=detector:detector alembic.ini ./
COPY --chown=detector:detector entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER detector

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["api"]
