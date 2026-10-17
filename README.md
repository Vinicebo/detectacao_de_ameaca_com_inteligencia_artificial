# Detector de Ameaças com IA

Sistema de detecção de ameaças web que lê os logs de acesso do nginx, pontua cada
requisição com **61 regras** somadas a um **ensemble de três modelos de machine
learning** e transmite os alertas para um dashboard em tempo real.

Roda como *sidecar*: fica fora do caminho do tráfego, não bloqueia nem altera
nada. Observa apenas o log que o nginx já escreve.

```
Python 3.12 · FastAPI · PostgreSQL 18 · Redis 7.4 · ONNX Runtime · PyTorch · React 19
```

---

## Destaques

- **Detecção em duas camadas.** Regras pegam ataques conhecidos com evidência
  exata; modelos pegam padrões sem assinatura, inclusive categorias que não
  existiam quando o sistema foi treinado.
- **Pontuação conservadora.** A decisão é `max(regras, ML)` com bônus quando as
  duas fontes concordam, e nunca uma média: um Log4Shell (regra 0.95) não pode ser
  diluído por um modelo indeciso (0.30) e passar despercebido.
- **Inferência sem PyTorch.** Os modelos são exportados para ONNX, o que mantém o
  container da API em centenas de MB, e não em vários GB.
- **Portões de qualidade.** Nenhum modelo é promovido sem F1 ≥ 0.80 e PR-AUC ≥ 0.85
  em holdout. Se reprova, a versão anterior continua ativa e o motivo fica
  registrado.
- **Ciclo de aprendizado com revisão humana.** O analista marca falso ou
  verdadeiro positivo no dashboard, e o retreino usa esses rótulos.
- **Degradação controlada.** Sem modelos, o sistema segue só com regras. Sem
  Redis ou GeoIP, as features afetadas zeram e o resto continua. Toda degradação
  aparece no log.
- **Perda contada, nunca silenciosa.** Filas com teto descartam o item mais antigo
  durante rajadas, e cada descarte é exposto em `/stats/pipeline`.

---

## Como funciona

```
logs do nginx (volume compartilhado)
      │  leitura por polling, com offset persistido no Postgres
      ▼
 Estágio 1  Parse       formato combined → registro estruturado
 Estágio 2  Features    vetor de 35 dimensões + janela deslizante por IP + GeoIP
 Estágio 3  Detecção    61 regras + ensemble ONNX (AE 40% · RF 40% · IF 20%)
 Estágio 4  Dispatch    PostgreSQL em lote + Redis pub/sub → WebSocket
```

Cada estágio é uma tarefa asyncio ligada à seguinte por uma fila. Um estágio lento
(inferência) não trava um rápido (parse), e a contrapressão aparece como
profundidade de fila.

### Severidade

| Severidade | Faixa de score | O que acontece |
|---|---|---|
| **HIGH** | ≥ 0.70 | Persiste, alerta no WebSocket e recomenda bloqueio |
| **MEDIUM** | 0.50 – 0.70 | Persiste e monitora |
| **LOW** | < 0.50 | Persiste amostrado (5%), para análise de padrões |

---

## Arquitetura

Dois processos e um banco compartilhado:

```
┌──────────────┐         ┌──────────────┐
│   detector   │         │     api      │
│ tail → parse │         │ REST + WS    │
│ → features   │         │ (só leitura) │
│ → detecção   │         │              │
│ → dispatch   │         │              │
└──────┬───────┘         └──────┬───────┘
       ├──── PostgreSQL ────────┤
       └──── Redis ─────────────┘
```

- **Separados de propósito.** Uma rajada de log é vazão contínua e intensiva em
  CPU; servir o dashboard é latência e I/O. No mesmo processo, um flood de
  ingestão travaria o dashboard justamente durante o ataque.
- **Um único escritor.** Só o `detector` grava eventos. A `api` é somente leitura,
  o que elimina concorrência de escrita entre os dois.
- **Alerta vs. persistência.** O alerta vai ao Redis imediatamente, porque é o
  produto. A persistência vai em lote, porque um INSERT por requisição custaria
  mais que todo o pipeline de detecção.

Detalhes em [docs/arquitetura.md](docs/arquitetura.md).

---

## Modelos

Três modelos, cada um enxergando o que os outros perdem:

| Modelo | Como aprende | Ponto forte |
|---|---|---|
| **Autoencoder** | Só com tráfego benigno | Reconstrói mal o que é incomum, então pega ataque sem assinatura |
| **Random Forest** | Supervisionado | O mais preciso nas famílias de ataque que conhece |
| **Isolation Forest** | Não supervisionado | Isola outliers por partição aleatória; o desacordo com o autoencoder é informativo |

**Por que PR-AUC e não ROC-AUC?** Ataque é a classe rara. Com 1% de positivos, um
classificador medíocre alcança ROC-AUC de 0.95 sem esforço.

### Sobre o modelo inicial

O modelo que sobe na primeira execução é treinado com **dados sintéticos**. Suas
métricas (F1 perto de 0.99) medem separabilidade no conjunto sintético, não o
desempenho no seu ambiente. Tráfego real tem formas que nenhum gerador antecipa.

O caminho para um modelo útil é o retreino: revise os alertas no dashboard e use
**Modelos → Retreinar agora**. Eventos revisados entram com o rótulo humano. Os
não revisados entram apenas nos extremos de score, porque a faixa do meio é onde o
sistema está incerto, e rotulá-la ensinaria o próprio erro.

---

## Dashboard

| Página | Conteúdo |
|---|---|
| **Visão geral** | Agregados, distribuição por severidade e linha do tempo |
| **Ao vivo** | Alertas conforme chegam, via WebSocket |
| **Eventos** | Histórico paginado com filtros e revisão de falso/verdadeiro positivo |
| **Modelos** | Versão ativa, métricas, histórico e botão de retreino |

---

## Começando

**Requisito:** Docker Desktop.

```bash
cp .env.example .env
```

Edite o `.env` e troque a `API_KEY`. O valor de exemplo não serve para uso exposto.
Gere uma chave com:

```bash
openssl rand -hex 32
```

Suba a stack:

```bash
docker compose -f dev.compose.yml up -d --build
```

A primeira subida leva alguns minutos: baixa as imagens e treina os modelos
iniciais. Depois disso os artefatos ficam num volume e o arranque é imediato.

- **Dashboard:** http://localhost:46969 (pede a API key na primeira visita)
- **Documentação da API:** http://localhost:46970/docs

### Gerando tráfego de teste

Um nginx separado escreve no mesmo volume que o detector lê:

```bash
docker compose -f dev-log/compose.yml up -d
python dev-log/simulate.py mixed -n 200
```

O simulador dispara requisições HTTP reais. O log é gerado pelo nginx, não escrito
à mão, então o parser é exercitado de verdade.

Modos disponíveis: `normal`, `sqli`, `xss`, `traversal`, `cmdi`, `log4shell`,
`ssrf`, `scanner`, `flood` e `mixed`.

---

## API

Todas as rotas exigem o header `X-API-Key`, exceto `/health`. O WebSocket envia a
chave em um frame logo após o handshake, nunca na query string, que vazaria a
credencial para logs de proxy e histórico do navegador.

| Endpoint | Descrição |
|---|---|
| `GET /health` | Estado de Postgres, Redis e modelos |
| `GET /stats` | Agregados, distribuição e linha do tempo |
| `GET /stats/pipeline` | Profundidade das filas, descartes e taxa de parse |
| `GET /threats` | Listagem paginada por cursor, com filtros |
| `GET /threats/{id}` | Detalhe, com regras casadas e vetor de features |
| `PATCH /threats/{id}/review` | Marca verdadeiro ou falso positivo |
| `GET /models/status` | Versão ativa, métricas e histórico |
| `POST /models/retrain` | Retreina com os eventos armazenados |
| `POST /ingest/batch` | Ingestão manual de linhas |
| `WS /ws/alerts` | Feed de alertas em tempo real |

---

## Qualidade e testes

Números verificados na última execução:

| Verificação | Resultado |
|---|---|
| Backend: pytest (dentro do container) | **222 testes passando** |
| Frontend: Vitest | **13 testes passando** |
| **Total** | **235 testes automatizados** |
| Backend: ruff (lint e formatação) | sem problemas |
| Backend: mypy | sem problemas em 47 arquivos |
| Frontend: lint, typecheck e build | sem problemas |

Comandos:

```bash
just test        # pytest dentro do container da API
just lint        # ruff + mypy
cd frontend && npm install && npm test
```

Sem o `just`, cada receita é um comando comum: `docker compose -f dev.compose.yml exec api python -m pytest`.

---

## Desenvolvimento

O projeto usa [`just`](https://github.com/casey/just) como atalho, mas cada receita
é um comando comum.

```bash
just up              # sobe a stack
just logs api        # acompanha um serviço
just simulate sqli 50
just migrate         # aplica migrações do banco
just reset           # apaga banco, modelos e histórico
```

### Estrutura

```
backend/app/
  api/          rotas REST, WebSocket e schemas
  db/           modelos SQLAlchemy e migrações
  detection/    motor de regras, regras YAML, fusão de scores e sessões ONNX
  ml/           features, dados sintéticos, treino, calibração e portões
  pipeline/     os quatro estágios e o orquestrador
  realtime/     barramento de alertas
frontend/src/   dashboard React
dev-log/        nginx de teste e gerador de tráfego
docs/           documentação técnica em português
```

Arquivos que mais importam:

- `backend/app/ml/features_spec.py`: o contrato das 35 dimensões. Treino e
  inferência usam o mesmo arquivo. Divergência entre os dois degrada a detecção
  sem gerar erro algum.
- `backend/app/detection/scoring.py`: a política de detecção inteira em um lugar.
- `backend/app/detection/rules/*.yaml`: as regras, editáveis sem tocar em código.

Documentação aprofundada: [arquitetura](docs/arquitetura.md),
[features](docs/features.md), [regras](docs/regras.md), [ML](docs/ml.md) e
[operação](docs/operacao.md).

---

## Limitações conhecidas

- **Só observa.** Não bloqueia nem altera tráfego. `recommend_block` é uma
  sugestão para outro sistema agir. Bloqueio automático derrubaria usuários
  legítimos no primeiro falso positivo.
- **GeoIP é opcional.** Sem a base GeoLite2 (MaxMind) em `/data/geoip`, a dimensão
  de país vira zero e o restante funciona normalmente.
- **Apenas formato combined do nginx.** Outros formatos exigem ajuste em
  `app/pipeline/stage1_parse.py`.
- **O modelo inicial é genérico.** Ver a seção sobre o modelo inicial.

---

## Créditos

Reimplementação independente, inspirada no projeto `ai-threat-detection` de
[CarterPerez-dev](https://github.com/CarterPerez-dev/Cybersecurity-Projects). O
código foi escrito do zero a partir da descrição de funcionalidades; nada do fonte
original foi copiado.

## Licença

MIT. Veja [LICENSE](LICENSE).
