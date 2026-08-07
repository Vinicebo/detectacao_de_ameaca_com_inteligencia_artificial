# Atalhos do projeto. `just` é opcional — cada receita é um comando comum, dá
# para copiar e rodar direto se preferir.
#
# Instalar: https://github.com/casey/just

compose := "docker compose -f dev.compose.yml"
devlog := "docker compose -f dev-log/compose.yml"

# Lista as receitas disponíveis
default:
    @just --list

# ---------------------------------------------------------------- stack
# Sobe a stack inteira (primeira vez leva alguns minutos: treina os modelos)
up:
    {{compose}} up -d --build

# Derruba a stack, mantendo os dados
down:
    {{compose}} down

# Derruba e apaga TUDO — banco, modelos e histórico do MLflow
reset:
    {{compose}} down -v

# Acompanha os logs (ex.: `just logs detector`)
logs service="":
    {{compose}} logs -f {{service}}

# Estado dos serviços
ps:
    {{compose}} ps

# Abre um shell no container da API
shell:
    {{compose}} exec api /bin/bash

# ---------------------------------------------------------------- qualidade
# Testes do backend
test:
    {{compose}} exec api python -m pytest

# Testes com relatório de cobertura
test-cov:
    {{compose}} exec api python -m pytest --cov=app --cov-report=term-missing

# Lint e checagem de tipos do backend
lint:
    {{compose}} exec api python -m ruff check .
    {{compose}} exec api python -m ruff format --check .
    {{compose}} exec api python -m mypy app

# Formata o backend
fmt:
    {{compose}} exec api python -m ruff format .
    {{compose}} exec api python -m ruff check --fix .

# Testes, lint e build do frontend
web-check:
    cd frontend && npm run lint && npm run typecheck && npm test -- --run && npm run build

# ---------------------------------------------------------------- banco
# Nova migração a partir das mudanças nos modelos
migration message:
    {{compose}} exec api alembic revision --autogenerate -m "{{message}}"

# Aplica as migrações pendentes
migrate:
    {{compose}} exec api alembic upgrade head

# Abre o psql
psql:
    {{compose}} exec postgres psql -U detector -d detector

# ---------------------------------------------------------------- modelos
# Treina do zero com dados sintéticos
train:
    {{compose}} exec api python -m app.ml.train

# Recarrega os modelos no detector (depois de um retreino)
reload-models:
    {{compose}} restart detector

# ---------------------------------------------------------------- teste de tráfego
# Sobe o nginx de teste
devlog-up:
    {{devlog}} up -d

# Derruba o nginx de teste
devlog-down:
    {{devlog}} down

# Gera tráfego (ex.: `just simulate sqli 50`)
simulate mode="mixed" count="100":
    python dev-log/simulate.py {{mode}} -n {{count}}
