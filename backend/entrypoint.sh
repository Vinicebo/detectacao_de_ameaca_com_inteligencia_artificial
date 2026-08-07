#!/usr/bin/env sh
# Arranque dos containers `api` e `detector`.
#
#   api       → espera dependências, migra o banco, serve REST + WebSocket
#   detector  → espera dependências, garante os modelos, roda o pipeline
#   train     → treina uma vez e sai (usado pelo `just train`)
#
# Só o `api` roda as migrações: se os dois rodassem, um `alembic upgrade`
# concorrente poderia colidir no arranque.

set -eu

ROLE="${1:-api}"

python -m app.cli wait-for-deps

case "$ROLE" in
    api)
        echo "[entrypoint] aplicando migrações"
        alembic upgrade head
        exec uvicorn app.main:app \
            --host 0.0.0.0 \
            --port 8000 \
            --no-access-log \
            --proxy-headers
        ;;

    detector)
        # Espera o `api` terminar as migrações antes de tocar nas tabelas.
        python -m app.cli wait-for-migrations
        python -m app.cli ensure-models
        exec python -m app.cli detector
        ;;

    train)
        exec python -m app.ml.train
        ;;

    *)
        echo "[entrypoint] papel desconhecido: $ROLE" >&2
        echo "[entrypoint] esperado: api | detector | train" >&2
        exit 64
        ;;
esac
