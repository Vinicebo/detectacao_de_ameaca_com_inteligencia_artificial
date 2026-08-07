# Motor de regras

As regras ficam em `backend/app/detection/rules/*.yaml`, para poderem ser revisadas
e ajustadas sem mexer no código — quem escreve regra de detecção nem sempre é quem
escreve o motor.

61 regras em 8 categorias: `sqli`, `xss`, `traversal`, `cmdi`, `log4shell`, `ssrf`,
`scanner`, `protocol`.

## Anatomia

```yaml
- id: SQLI-001
  category: sqli
  severity: critical
  score: 0.95
  description: UNION SELECT — extração de dados de outra tabela
  targets: [uri_decommented, user_agent, referer]
  pattern: '\bunion\b(\s+all)?\s+select\b'
```

Alvos disponíveis: `method`, `path`, `query`, `uri`, `uri_decommented`,
`user_agent`, `referer`, `raw_path`, `raw_query`.

As regex são compiladas no arranque. Uma regex inválida quebra o deploy, não a
detecção em produção — e o custo de compilação sai do caminho quente.

## Normalização

É aqui que se ganha ou se perde contra evasão. Um filtro que casa `UNION SELECT` no
texto cru é contornado em segundos:

```
UNION/**/SELECT      comentário no lugar do espaço
%55NION %53ELECT     percent-encoding parcial
%2555NION            codificação dupla
UNION%09SELECT       tab em vez de espaço
UnIoN sElEcT         variação de caixa
UN%00ION             byte nulo no meio
```

Todos viram a mesma coisa depois de: decodificar percent-encoding duas vezes,
remover bytes de controle, colapsar espaços (incluindo os unicode) e passar para
minúsculas.

O custo é falso positivo — quanto mais agressiva a normalização, mais tráfego
legítimo passa a parecer ataque. Por isso as regras casam contra **duas** visões, e
a mais agressiva (`uri_decommented`, sem comentários) só é usada nas categorias em
que comentário é evasão conhecida. Remover `/* */` de todo tráfego geraria falso
positivo em qualquer URL que contenha `/*`.

Todo campo é cortado em 8 KB antes do match: regex sobre megabytes seria negação de
serviço contra o próprio detector.

## Pontuação

O escore da requisição é o **maior** escore casado, mais 0.05 por categoria
distinta adicional (teto de 0.15).

Somar tudo faria três regras fracas da mesma família — que costumam casar juntas no
mesmo payload — valerem mais que uma regra forte e específica. Já casar SQLi *e*
traversal na mesma requisição é sinal genuinamente independente, e aí o bônus se
justifica.

## Falso positivo é o critério

Regra que dispara em tráfego normal é pior que regra que não existe: enterra o
analista em ruído até ele parar de olhar os alertas.

O arquivo `backend/tests/test_rules_engine.py` mantém um corpus de 25 requisições
legítimas que **não podem** chegar a HIGH. Ele existe para impedir que alguém
"melhore a detecção" afrouxando um padrão e transforme o dashboard em ruído.

Três armadilhas que esse corpus pegou durante a construção:

**`&` não é separador de shell.** O padrão óbvio para injeção de comando é
`[;|&]\s*(cat|ls|id|...)`. Mas `&` separa parâmetros de query string, e `env`,
`id`, `ps`, `pwd`, `dir`, `cp`, `rm` e `export` são nomes de parâmetro
corriqueiros. `?a=1&env=prod` casaria como injeção com escore 0.95. A regra usa
`[;|`]` e exige que o comando não seja seguido de `=`.

**`on\w+\s*=` casa `?online=1`.** O padrão para handler de evento inline aparece em
muito filtro caseiro e pega `online`, `once`, `only`, `onboarding`. Os handlers são
listados um a um.

**Palavra-chave SQL sozinha não diz nada.** `?select=nome,preco` é o padrão de
sparse fieldsets do JSON:API; `?order=data` é ordenação. Nenhuma regra casa
palavra-chave isolada — todas exigem a estrutura da sintaxe SQL em volta.

## Sinal de apoio versus evidência

Nem toda regra é evidência. `SSRF-005` (URL absoluta em parâmetro de proxy) tem
escore 0.4, **abaixo do limiar de MEDIUM**, e isso é deliberado.

Durante os testes com tráfego real, essa regra estava em 0.5 — exatamente no limiar
de MEDIUM. Isso a habilitava a participar do bônus de concordância do ensemble: um
`redirect_uri=https://...` de OAuth, com o modelo achando o caminho pouco familiar,
somava 0.5 + 0.1 e virava HIGH. Todo login com OAuth gerava alerta.

Sinal de apoio não pode alcançar sozinho o patamar que dispara o bônus. Quem decide
se há SSRF é o **destino** da URL (`SSRF-001` a `SSRF-003`), não a presença de uma
URL.

## Adicionando uma regra

1. Escreva o padrão contra o texto **já normalizado** — não trate caixa nem `%20`.
2. Adicione um caso positivo em `test_attack_payloads_are_detected`.
3. Rode a suíte inteira. Se algum caso do corpus benigno quebrar, o padrão está
   largo demais.
4. Escolha o escore pelo que a regra prova: 0.9+ só quando o padrão é
   inequivocamente malicioso; abaixo de 0.5 quando é apenas indício.
