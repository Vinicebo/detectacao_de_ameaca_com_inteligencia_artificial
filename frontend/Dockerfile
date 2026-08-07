# syntax=docker/dockerfile:1

FROM node:22-alpine AS builder

WORKDIR /build

# package.json antes do código: enquanto as dependências não mudarem, o Docker
# reaproveita a camada do npm ci, que é a parte lenta do build.
COPY package.json package-lock.json* ./
RUN npm ci || npm install

COPY . .
RUN npm run build

# ---------------------------------------------------------------- runtime
FROM nginx:1.27-alpine AS runtime

COPY --from=builder /build/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

# 127.0.0.1 e não `localhost`: o resolvedor do container tenta ::1 primeiro e o
# nginx escuta só em IPv4 (`listen 80`), então o healthcheck receberia
# "connection refused" com o servidor perfeitamente no ar.
HEALTHCHECK --interval=15s --timeout=4s --start-period=10s --retries=3 \
    CMD wget -q --spider http://127.0.0.1/ || exit 1
