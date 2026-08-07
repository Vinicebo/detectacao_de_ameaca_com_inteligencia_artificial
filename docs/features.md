# As 35 features

Definidas em `backend/app/ml/features_spec.py`. Esse arquivo é a **fonte única de
verdade**: treino e inferência importam dele.

Se os dois lados calculassem as features separadamente, uma divergência não geraria
erro nenhum — os modelos simplesmente passariam a receber um vetor com significado
diferente do que aprenderam, e a detecção degradaria em silêncio. É a falha mais
difícil de perceber neste tipo de sistema, e a proteção é estrutural: existe um
código só.

## Regras para mexer

1. **Ordem é contrato.** O índice de cada feature é o índice na entrada do ONNX.
   Nunca reordene nem remova — só acrescente no fim, e aí todos os modelos
   precisam ser retreinados.
2. **Tudo limitado a [0, 1].** Transformações saturantes em vez de valores crus.
   Uma URL de 8 KB não pode virar um outlier que domina o `StandardScaler`.
3. **Sem NaN, sem infinito.** Campo ausente vira 0.0. `validate_vector` é a
   barreira final.

A calibração guarda a lista de nomes junto com os modelos. Se alguém acrescentar
uma dimensão e esquecer de retreinar, o carregamento **recusa** os modelos antigos
em vez de alimentá-los com um vetor que significa outra coisa.

## O vetor

### Estrutura da URI (12)

| # | Nome | O que captura |
|---|---|---|
| 0 | `path_length` | Payload longo tende a ser injeção |
| 1 | `query_length` | Idem, na query string |
| 2 | `path_entropy` | Entropia de Shannon — texto codificado ou ofuscado pontua alto |
| 3 | `query_entropy` | Idem |
| 4 | `param_count` | Número de parâmetros |
| 5 | `max_param_value_length` | O maior valor: uma injeção fica num parâmetro só |
| 6 | `special_char_ratio` | Proporção de `<>"'`;\|&$()` etc. |
| 7 | `digit_ratio` | Distingue id numérico de payload |
| 8 | `pct_encoded_count` | Quantidade de `%XX` |
| 9 | `double_encoded_count` | `%25XX` — a evasão mais barata que existe |
| 10 | `path_depth` | Número de `/` |
| 11 | `suspicious_extension` | `.php`, `.env`, `.git`, `.bak`… |

### Tokens de ataque (5)

| # | Nome |
|---|---|
| 12 | `sql_token_count` |
| 13 | `xss_token_count` |
| 14 | `traversal_token_count` |
| 15 | `cmdi_token_count` |
| 16 | `jndi_token_count` |

Contagem grosseira e barata, de propósito: aqui só produzimos um número para o
modelo. A decisão precisa de "isto é SQLi" é do motor de regras, que casa padrões
completos e com contexto.

Contadas sobre o texto **decodificado em duas passadas** — `%2527` vira `%27` e só
então a aspa.

### Requisição e resposta (7)

| # | Nome | Observação |
|---|---|---|
| 17 | `method_id` | Método fora da lista comum recebe 1.0 — método exótico já é anomalia |
| 18 | `is_write_method` | POST/PUT/DELETE/PATCH |
| 19 | `status_normalized` | 401/403/404/405 pesam mais: é o rastro de varredura e força bruta |
| 20 | `bytes_sent_log` | Escala log |
| 21 | `protocol_version` | HTTP/1.0 é raro em navegador atual |
| 22 | `hour_sin` | Hora do dia como seno |
| 23 | `hour_cos` | …e cosseno |

A hora vai como seno/cosseno porque codificá-la como 0–23 cru ensinaria o modelo
que 23h e 0h são opostos, quando são vizinhos. Isso importa: tráfego de bot se
concentra de madrugada.

### Cliente (5)

| # | Nome |
|---|---|
| 24 | `ua_length` |
| 25 | `ua_entropy` |
| 26 | `ua_is_empty` |
| 27 | `ua_is_known_scanner` |
| 28 | `referer_state` |

`referer_state`: 0 ausente, 0.5 interno, 1.0 externo. O nginx grava `"-"` quando o
cabeçalho não veio, e isso conta como **ausente** — tratar `"-"` como presente
colocaria a maioria do tráfego de API e de bot numa faixa intermediária inexistente.

### Janela por IP, 60 segundos (5)

| # | Nome | O que captura |
|---|---|---|
| 29 | `window_request_count` | Volume |
| 30 | `window_unique_paths` | Muitos caminhos distintos = varredura de diretório |
| 31 | `window_error_rate` | Proporção de 4xx |
| 32 | `window_mean_interarrival` | **Invertido**: intervalo curto pontua alto |
| 33 | `window_burstiness` | Coeficiente de variação dos intervalos |

`burstiness` é o desvio padrão dos intervalos dividido pela média. Tráfego humano
chega irregular; script chega em intervalo quase constante (valor perto de zero) ou
em rajada concentrada (valor alto). Os dois extremos são suspeitos.

É esta seção que transforma sondagens isoladas — que sozinhas ficam em MEDIUM — em
um alerta HIGH quando vêm cem em sessenta segundos do mesmo IP com 95% de 404.

### GeoIP (1)

| # | Nome |
|---|---|
| 34 | `country_risk` |

Sinal fraco de propósito, e o peso reflete isso: geografia não é evidência. Serve
de desempate, nunca de motivo isolado para classificar algo como ataque. Sem a base
GeoLite2 instalada, a dimensão vira zero e o sistema segue igual.
