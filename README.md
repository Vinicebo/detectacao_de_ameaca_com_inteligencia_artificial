# Detector de Ameaças com IA

Motor de detecção que lê logs de acesso do nginx, pontua cada requisição HTTP com
um motor de regras somado a um ensemble de três modelos de machine learning, e
transmite os alertas para um dashboard em tempo real.

Roda como sidecar: não fica no caminho do tráfego, não bloqueia nada. Observa o
log que o nginx já escreve.

```
Python 3.12 · FastAPI · PostgreSQL 18 · Redis 7.4 · ONNX Runtime · PyTorch · React 19
```

## Como funciona

```
logs do nginx (volume compartilhado)
      │  leitura por polling, com offset persistido
      ▼
 Estágio 1  Parse       formato combined → registro estruturado
 Estágio 2  Features    vetor de 35 dimensões + janela por IP + GeoIP
 Estágio 3  Detecção    61 regras + ensemble ONNX (AE 40% · RF 40% · IF 20%)
 Estágio 4  Dispatch    PostgreSQL em lote + Redis pub/sub → WebSocket
```

**Regras** pegam ataque conhecido com evidência exata: o payload *contém*
`${jndi:ldap://`. **Modelos** pegam o que não tem assinatura escrita — inclusive
categoria que ainda não existia quando o sistema foi treinado.

A pontuação final é `max(regras, ml)`, com um bônus pequeno quando as duas fontes
concordam. Não é média: uma regra crítica (0.95) não pode ser diluída por um
modelo indeciso (0.30) até 0.62 e deixar um Log4Shell passar.

| Severidade | Faixa | O que acontece |
|---|---|---|
| HIGH | ≥ 0.70 | Persiste, alerta no WebSocket, recomenda bloqueio |
| MEDIUM | 0.50–0.70 | Persiste e monitora |
| LOW | < 0.50 | Persiste amostrado (5%), para análise de padrão |

## Começando

Requisitos: Docker Desktop.

```bash
cp .env.example .env
```

Edite o `.env` e troque a `API_KEY` — o valor de exemplo não serve para nada
exposto. Gere uma com `openssl rand -hex 32`.

```bash
docker compose -f dev.compose.yml up -d --build
```

A primeira subida leva alguns minutos: baixa as imagens e treina os modelos
iniciais. Depois disso os artefatos ficam num volume e o arranque é imediato.

O dashboard abre em **http://localhost:46969**. Ele pede a API key na primeira
visita; é a mesma do `.env`.

## Gerando tráfego de teste

Um nginx separado, que escreve no mesmo volume que o detector lê:

```bash
docker compose -f dev-log/compose.yml up -d
```

```bash
python dev-log/simulate.py mixed -n 200
```

O simulador dispara requisições HTTP reais — o log é gerado pelo nginx, não
escrito à mão, então o parser é exercitado de verdade.

Modos: `normal`, `sqli`, `xss`, `traversal`, `cmdi`, `log4shell`, `ssrf`,
`scanner`, `flood`, `mixed`.

## API

Tudo exige o header `X-API-Key`, menos `/health`. O WebSocket pede a chave num
frame logo após o handshake — nunca em query string, que vazaria a credencial
para log de proxy e histórico do navegador.

| Endpoint | Descrição |
|---|---|
| `GET /health` | Estado de Postgres, Redis e modelos |
| `GET /stats` | Agregados, distribuição, linha do tempo |
| `GET /stats/pipeline` | Profundidade das filas, descartes, taxa de parse |
| `GET /threats` | Listagem paginada por cursor, com filtros |
| `GET /threats/{id}` | Detalhe, com regras casadas e vetor de features |
| `PATCH /threats/{id}/review` | Marca verdadeiro ou falso positivo |
| `GET /models/status` | Versão ativa, métricas, histórico |
| `POST /models/retrain` | Retreina com os eventos armazenados |
| `POST /ingest/batch` | Ingestão manual de linhas |
| `WS /ws/alerts` | Feed de alertas em tempo real |

Documentação interativa em http://localhost:46970/docs.

## Modelos

Três modelos, porque cada um enxerga o que os outros perdem:

- **Autoencoder** — treinado só em tráfego benigno. O que ele reconstrói mal é,
  por definição, incomum. Pega ataque sem assinatura.
- **Random Forest** — supervisionado. O mais preciso nas famílias que conhece.
- **Isolation Forest** — isola outlier por partição aleatória. Barato e
  independente do autoencoder, o que torna o desacordo entre os dois informativo.

Todos exportados para ONNX: a inferência não carrega PyTorch, e o container da API
fica em centenas de MB em vez de vários GB.

**Portões de qualidade.** Nenhum modelo é promovido sem F1 ≥ 0.80 e PR-AUC ≥ 0.85
em holdout. Reprovou, a versão anterior continua ativa e o motivo fica registrado
em `model_versions` — a pergunta "por que a versão ativa ainda é a de três semanas
atrás?" precisa ter resposta.

PR-AUC e não ROC-AUC porque ataque é a classe rara: com 1% de positivos, um
classificador medíocre atinge ROC-AUC de 0.95 sem esforço.

### Sobre as métricas do modelo inicial

O modelo que sobe na primeira execução é treinado com **dados sintéticos**, e as
métricas dele (F1 perto de 0.99) medem separabilidade no próprio conjunto
sintético — não desempenho no seu ambiente. Tráfego real tem formas que nenhum
gerador antecipa.

O caminho para um modelo útil é o retreino: revise alertas no dashboard marcando
verdadeiro e falso positivo, depois use **Modelos → Retreinar agora**. Eventos
revisados entram com o rótulo humano; os não revisados entram só nos extremos de
escore, porque a faixa do meio é exatamente onde o sistema está incerto e
rotulá-la ensinaria o próprio erro.

## Desenvolvimento

O projeto usa [`just`](https://github.com/casey/just) como atalho, mas cada
receita é um comando comum — dá para copiar e rodar direto.

```bash
just up          # sobe tudo
just test        # pytest dentro do container
just lint        # ruff + mypy
just logs api    # acompanha um serviço
just simulate sqli 50
just reset       # apaga banco, modelos e histórico
```

Testes do frontend:

```bash
cd frontend && npm install && npm test
```

### Estrutura

```
backend/app/
  api/          rotas REST, WebSocket, schemas
  db/           modelos SQLAlchemy e migrações
  detection/    motor de regras, regras YAML, fusão de escores, sessões ONNX
  ml/           features, dados sintéticos, treino, calibração, portões
  pipeline/     os quatro estágios e o orquestrador
  realtime/     barramento de alertas
frontend/src/   dashboard React
dev-log/        nginx de teste e gerador de tráfego
docs/           documentação em português
```

Os arquivos que mais importam:

- `backend/app/ml/features_spec.py` — o contrato das 35 dimensões. Treino e
  inferência importam daqui; divergência entre os dois degrada a detecção sem
  gerar erro nenhum.
- `backend/app/detection/scoring.py` — a política de detecção inteira num lugar só.
- `backend/app/detection/rules/*.yaml` — as regras, editáveis sem tocar em código.

## Limitações conhecidas

- **Só observa.** Não bloqueia nem altera tráfego. `recommend_block` é uma
  sugestão para outro sistema agir; bloquear automaticamente derruba usuário
  legítimo no primeiro falso positivo.
- **GeoIP é opcional.** Sem a base GeoLite2 da MaxMind em `/data/geoip`, a
  dimensão de país vira zero e o resto funciona igual.
- **Formato combined.** Outros formatos de log exigem ajustar
  `app/pipeline/stage1_parse.py`.
- **Sob flood, as filas descartam o item mais antigo** em vez de crescer sem
  limite. Todo descarte é contado e exposto em `/stats/pipeline` — perda
  silenciosa num sistema de segurança é pior que perda nenhuma.
- **O modelo inicial é genérico.** Ver a seção sobre métricas acima.

## Créditos

Reimplementação independente, inspirada no projeto `ai-threat-detection` de
[CarterPerez-dev](https://github.com/CarterPerez-dev/Cybersecurity-Projects). O
código aqui foi escrito do zero a partir da descrição de funcionalidades; nada do
fonte original foi copiado.

## Licença

MIT — ver [LICENSE](LICENSE).
