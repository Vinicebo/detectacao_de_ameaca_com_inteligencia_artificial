# Modelos

## Por que três

Cada um enxerga o que os outros perdem.

**Autoencoder** (PyTorch, 35→24→12→24→35) — treinado *só em tráfego benigno*.
Aprende a reconstruir o que é normal; o que ele reconstrói mal é, por definição,
incomum. Pega ataque que nunca esteve no conjunto de treino, inclusive categoria
que ainda não existia.

O gargalo de 12 é ~1/3 da entrada: apertado o bastante para forçar o modelo a
aprender a estrutura do tráfego em vez de copiar a entrada, largo o bastante para
não perder as features de janela.

**Random Forest** — supervisionado. O mais preciso nas famílias que conhece, e o
único que dá alguma explicabilidade por importância de feature.

**Isolation Forest** — não supervisionado, isola outlier por partição aleatória.
Barato e independente do autoencoder, o que faz o desacordo entre os dois ser
informativo.

Um ataque que imita tráfego normal engana o autoencoder mas não o Random Forest;
uma categoria nova engana o Random Forest mas não o autoencoder.

Pesos: 40% / 40% / 20%. Configuráveis no `.env`, precisam somar 1.0 (validado no
arranque).

## Calibração

Os três produzem saídas em escalas incompatíveis: erro de reconstrução (0 a ∞),
probabilidade (0 a 1) e distância de anomalia (negativa para outlier). Combiná-las
exige mapear tudo para [0, 1], e as constantes desse mapeamento vêm da distribuição
do treino — por isso viajam junto com os modelos, em `scaler.json`.

- **Autoencoder**: `erro / (erro + p99_benigno)`. O percentil 99 do erro em tráfego
  benigno mapeia para 0.5 — "tão incomum quanto o 1% mais incomum do que considero
  normal".
- **Random Forest**: probabilidade da classe positiva, direto.
- **Isolation Forest**: `decision_function` invertida e normalizada pelos limites
  observados no treino.

O `scaler.json` também guarda a lista de nomes das features. Modelos treinados com
outro contrato são **recusados** no carregamento, e o sistema cai para modo somente
regras com o motivo no log — em vez de rodar com um vetor que significa outra coisa.

## Portões de qualidade

Nenhum modelo é promovido sem **F1 ≥ 0.80 e PR-AUC ≥ 0.85** em holdout de 25%.

Reprovou, a versão anterior continua ativa e o motivo fica registrado em
`model_versions`. Registramos toda tentativa, aprovada ou não: guardar só as
aprovadas deixaria sem resposta a pergunta "por que a versão ativa ainda é a de três
semanas atrás?" — que é justamente a pergunta que se faz quando a detecção parece
estar piorando.

**PR-AUC e não ROC-AUC** porque ataque é a classe rara. Com 1% de positivos, um
classificador medíocre atinge ROC-AUC de 0.95 sem esforço, porque a métrica é
dominada pelos negativos.

Um modelo pior entrando em produção sem ninguém perceber é o modo de falha mais caro
deste sistema: a detecção degrada, nenhum erro aparece, e o sintoma só surge semanas
depois como "ando vendo menos alertas".

## Dados sintéticos

Na primeira subida não existe tráfego real, e um detector que só começa a funcionar
depois de semanas de coleta não serve. `app/ml/synthetic.py` gera requisições
plausíveis, benignas e maliciosas.

Os exemplos são `LogEntry` completos que passam pelo **mesmo**
`FeatureExtractor.build_vector` da inferência. Gerar vetores de features diretamente
seria mais rápido e introduziria exatamente a divergência treino/inferência que o
contrato existe para impedir.

### As classes precisam se sobrepor

Na primeira versão, o treino atingiu F1 = **1.000**. Isso não é um modelo bom, é um
conjunto de dados ruim: se benigno e ataque não se sobrepõem em lugar nenhum do
espaço de features, qualquer classificador separa os dois e aprende a fronteira do
*gerador* em vez da fronteira do problema. Em produção, onde as distribuições se
tocam, ele erra sem aviso.

A correção foi criar a sobreposição de propósito:

- **25% dos benignos são casos difíceis** (`generate_hard_benign`): pesquisa por
  termos de SQL, caminho relativo legítimo, URL em parâmetro de OAuth, painel
  administrativo acessado por quem tem acesso, cliente de API com volume alto e
  User-Agent não-navegador.
- **15% dos ataques são furtivos** (`generate_stealthy_attack`): User-Agent de
  navegador, resposta 200, ritmo lento, carga mínima.

Há um teste (`test_classes_overlap_in_feature_space`) que falha se **qualquer**
feature isolada conseguir separar as classes por completo.

### Tráfego benigno tem erro

Segunda correção, vinda de teste com tráfego real: o gerador produzia quase só
respostas 200. O modelo aprendeu que qualquer erro é suspeito, e `/login`
devolvendo 401 — o resultado normal de uma senha errada — virava alerta HIGH.

Site real serve 404 de link quebrado o dia inteiro, 401 de senha errada, 403 de
sessão expirada. O gerador agora reflete isso, e a taxa de erro da janela sobe até
1.0 numa fração dos casos benignos: uma janela com uma requisição só, sendo essa um
404, dá taxa de erro 1.0 sem nada de errado.

## Retreino

O modelo de bootstrap aprende com uma caricatura. O modelo bom aprende com o
tráfego do ambiente real: as URLs que existem de fato, os clientes que existem de
fato, os ataques que esse alvo específico atrai.

Duas fontes de rótulo, com pesos bem diferentes:

- **Eventos revisados** — julgamento humano, via `PATCH /threats/{id}/review`. É o
  rótulo de verdade.
- **Eventos não revisados** — heurística sobre o escore que o próprio sistema
  atribuiu. Isso é parcialmente circular, então usamos só os extremos: escore
  ≥ 0.7 vira ataque, ≤ 0.2 vira benigno. A faixa do meio é exatamente onde o
  sistema está incerto, e transformar essa incerteza em rótulo ensinaria o erro.

Se faltar volume mínimo de alguma classe, completa com sintético e registra
`training_source = mixed`. Um ambiente que ainda não sofreu ataque nenhum tem zero
exemplos positivos, e treinar assim produziria um classificador que diz "benigno"
para tudo.

## Por que ONNX

O container da API roda inferência com `onnxruntime` (~50 MB) em vez de PyTorch
(vários GB). O custo por predição também cai, e isso importa porque o pipeline
pontua cada requisição individualmente — latência por amostra pesa mais que vazão
em lote.

Detalhes de exportação que custaram tempo:

- A partir do torch 2.9 o exportador padrão é o baseado em dynamo, que precisa do
  pacote `onnxscript` e usa `dynamic_shapes` (não `dynamic_axes`).
- `external_data=False` é necessário, senão os pesos vão para um `.onnx.data`
  separado que escaparia da checagem de artefatos do healthcheck.
- O skl2onnx escolhe a versão 4 do domínio `ai.onnx.ml` por padrão e depois recusa
  a própria escolha; é preciso fixar em 3.

Todo artefato exportado é executado uma vez antes de ser aceito
(`verify_export`). Exportação que grava um arquivo mas produz um grafo inválido
acontece, e sem essa checagem o sintoma seria o detector entrando em crash loop
depois do deploy, não o treino falhando.
