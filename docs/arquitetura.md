# Arquitetura

## Dois processos, um banco

```
┌──────────────┐         ┌──────────────┐
│   detector   │         │     api      │
│              │         │              │
│ tail → parse │         │ REST + WS    │
│ → features   │         │ (só leitura) │
│ → detecção   │         │              │
│ → dispatch   │         │              │
└──────┬───────┘         └──────┬───────┘
       │                        │
       ├──── PostgreSQL ────────┤
       └──── Redis ─────────────┘
```

Separados porque as cargas são incompatíveis: uma rajada de log é vazão contínua e
CPU-bound; servir o dashboard é latência e I/O. No mesmo processo, um flood de
ingestão faria o dashboard travar exatamente durante o ataque — o momento em que
alguém mais precisa dele.

O `api` nunca escreve eventos. Só o `detector` escreve, o que elimina qualquer
concorrência de escrita entre os dois.

## Os quatro estágios

Cada estágio é uma tarefa asyncio consumindo de uma fila e produzindo na próxima.
Assim um estágio lento (inferência ONNX) não bloqueia um rápido (parse), e a
contrapressão aparece como profundidade de fila em vez de travar tudo.

### 1 — Leitura e parse

Polling puro, sem inotify. Em volume compartilhado do Docker — que é como o nginx
entrega os logs aqui — o inotify não dispara de forma confiável através do limite
do mount, e um observador por evento perde escrita. Um `stat` por segundo é barato
e sempre funciona.

O que precisa estar certo:

- **Offset persistido** no Postgres, ou todo restart reprocessaria o arquivo
  inteiro e duplicaria os eventos.
- **Rotação** detectada por mudança de inode.
- **Truncamento** (`> access.log`) detectado comparando tamanho com offset.
- **Linha parcial**: a cauda sem `\n` fica no buffer e o offset não avança além
  dela, senão um evento sairia com a URI cortada e o resto viraria um segundo
  evento igualmente errado.

O parser é tolerante por necessidade: a linha de requisição é controlada por quem
manda a requisição. Linha malformada é sinal, não lixo — scanner mandando bytes
crus e tentativa de request smuggling aparecem assim. Vira um registro com método
`INVALID` para as regras avaliarem, em vez de ser descartada.

### 2 — Features

Vetor de 35 dimensões, especificado em `app/ml/features_spec.py`. Ver
[features.md](features.md).

A janela deslizante por IP fica em Redis Sorted Set, não em memória: sobrevive a
restart do detector — senão todo deploy zeraria o histórico e uma varredura em
curso passaria batida.

### 3 — Detecção

Regras e ensemble, fundidos em `app/detection/scoring.py`. Ver [regras.md](regras.md)
e [ml.md](ml.md).

### 4 — Dispatch

Duas saídas com exigências opostas:

- **Alerta** vai para o Redis na hora. É o produto do sistema; segurá-lo num
  buffer por dois segundos para economizar uma escrita troca a única coisa que o
  usuário percebe por eficiência que ele não vê.
- **Persistência** vai em lote. Um INSERT por requisição custaria mais que o
  pipeline de detecção inteiro.

## Contrapressão

As filas têm teto e descartam o **item mais antigo** quando enchem. As duas
alternativas são piores:

- Fila ilimitada: o processo cresce até o OOM killer.
- Bloquear na escrita: a pressão volta para o leitor de log, o arquivo rotaciona
  por baixo dele, e a perda é muito maior.

Numa rajada de ataque, a requisição de 40 segundos atrás vale menos que a que está
chegando agora. Todo descarte é contado e exposto em `/stats/pipeline`.

## Degradação

O sistema tem três níveis de funcionamento, e cai entre eles sem parar:

| Situação | Comportamento |
|---|---|
| Tudo no ar | Regras + ensemble |
| Modelos ausentes ou incompatíveis | Somente regras, registrado no log |
| Redis fora | As 5 features de janela zeram; as outras 30 seguem |
| GeoIP ausente | A dimensão de país zera |
| Postgres fora | Alertas continuam saindo; o lote é perdido e contado |

Um detector fora do ar não protege nada. Degradar e continuar é sempre melhor que
parar — desde que a degradação apareça no log, porque descobrir que rodou um mês
em modo somente-regras é pior que a degradação em si.

## Desligamento

SIGTERM não corta o processo no meio. O leitor para, injeta uma sentinela na fila,
e cada estágio termina o que tem em mãos, repassa a sentinela e encerra. O
dispatcher grava o último lote antes de sair. Um `kill -9` perderia até 100
eventos já detectados.
