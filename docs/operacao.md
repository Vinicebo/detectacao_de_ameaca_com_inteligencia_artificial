# Operação

## Portas

| Porta | Serviço |
|---|---|
| 46969 | Dashboard (nginx, faz proxy de `/api` e `/ws`) |
| 46970 | API direta — só para depuração e `/docs` |
| 5000 | MLflow |
| 8080 | nginx de teste do `dev-log` |

O navegador usa só a 46969. Um domínio só para tudo evita CORS e mantém o WebSocket
na mesma origem.

## Volumes

| Volume | Conteúdo | Perder significa |
|---|---|---|
| `pgdata` | Eventos, versões de modelo, checkpoints | Perder o histórico e os rótulos de revisão |
| `models` | Artefatos ONNX e calibração | Retreinar na próxima subida (~2 min) |
| `mlruns` | Histórico do MLflow | Perder o rastro dos experimentos |
| `redisdata` | Janelas por IP, buffer de alertas | Nada relevante — é cache |
| `threat-detector-nginx-logs` | Logs compartilhados com o detector | Nada; os eventos já foram processados |

`just reset` (ou `docker compose -f dev.compose.yml down -v`) apaga todos.

## Ligando a um nginx de verdade

Monte o diretório de log do seu nginx no container `detector`, somente leitura:

```yaml
detector:
  volumes:
    - /var/log/nginx:/var/log/nginx:ro
```

Confira duas coisas:

1. **O formato é `combined`.** É o padrão do nginx. Outro formato exige ajustar
   `app/pipeline/stage1_parse.py`.
2. **O log é um arquivo comum, não um symlink para `/dev/stdout`.** A imagem oficial
   do nginx cria `access.log` como symlink para o stdout, para o log sair no
   `docker logs`. O detector ignora tudo que não seja arquivo comum, então nesse
   caso ele não veria nada — e sem erro em lugar nenhum. Configure um caminho
   próprio, como `access_log /var/log/nginx/app-access.log combined;`.

`LOG_GLOB` controla quais arquivos são acompanhados (padrão `*access*.log`).

## O que observar

`GET /stats/pipeline` é o endpoint que responde "a ingestão está funcionando?".

| Campo | O que significa |
|---|---|
| `queues.*.depth` | Profundidade atual. Persistentemente alta = o consumo não acompanha |
| `queues.*.dropped` | **Descartes.** Qualquer valor acima de zero é perda de dado |
| `parse.malformed` | Linhas que não casaram o formato. Taxa alta = formato errado |
| `dispatch.failed_writes` | Lotes perdidos por falha no Postgres |
| `detection_mode` | `rules_only` significa que os modelos não carregaram |

O campo `status` vale `stale` se o detector não publica há mais de 30 segundos.
Isso é diferente de servir números congelados como se fossem atuais.

## Ajustando o ruído

Tudo por variável de ambiente, sem rebuild:

```bash
SEVERITY_HIGH_THRESHOLD=0.75    # menos alertas HIGH
SEVERITY_MEDIUM_THRESHOLD=0.55
LOW_SEVERITY_SAMPLE_RATE=0.01   # guarda menos eventos LOW
RATE_LIMIT_PER_MINUTE=300
```

Se estiver alertando demais, a ordem certa é:

1. Revise alguns alertas como falso positivo no dashboard.
2. Retreine (**Modelos → Retreinar agora**). O modelo aprende com os rótulos.
3. Só então mexa nos limiares.

Subir o limiar esconde o sintoma sem melhorar a detecção — e esconde junto os
ataques que estavam pontuando perto da fronteira.

## Retreino

Roda em segundo plano; a resposta é imediata com um id de job. Uma trava no Redis
impede dois retreinos simultâneos (dois cliques no botão, ou duas réplicas da API):
competiriam pela CPU e poderiam escrever no mesmo arquivo ONNX ao mesmo tempo.

O progresso aparece em `GET /models/status` quando a versão nova é registrada. Se
reprovar nos portões, a versão ativa não muda e o motivo fica no campo
`rejection_reason`.

Depois de um retreino bem-sucedido, reinicie o `detector` para carregar os modelos
novos:

```bash
docker compose -f dev.compose.yml restart detector
```

## Segurança do próprio detector

- **A API key** protege tudo menos `/health`. Comparação em tempo constante — `==`
  em string vaza o tamanho do prefixo correto pelo tempo de resposta.
- **O WebSocket** exige a chave num frame, em até 5 segundos. Nunca em query
  string: vazaria para log de proxy, histórico do navegador e cabeçalho Referer. E
  um feed de alertas aberto entrega reconhecimento de graça — quem ataca vê em
  tempo real o que foi detectado e ajusta a evasão.
- **O container roda sem root** (uid 10001). Se o motor for comprometido por um
  payload malformado, o estrago fica contido.
- **O volume de log é montado somente leitura.**
- **O dashboard guarda a chave em `sessionStorage`**, não `localStorage`: some ao
  fechar a aba.

## Diagnóstico rápido

**Nenhum evento aparecendo.** Confira `parse.parsed` em `/stats/pipeline`. Se for
zero, o detector não está lendo nada — verifique o symlink do `access.log` e o
`LOG_GLOB`.

**`detection_mode: rules_only`.** Os modelos não carregaram. O log do detector diz o
motivo: artefato ausente, corrompido, ou treinado com outro contrato de features.

**Alertas param de chegar mas os eventos são gravados.** É o WebSocket, não a
detecção. O indicador de conexão na barra lateral mostra o estado; o histórico
continua íntegro em Eventos.

**`dropped` subindo.** O consumo não acompanha a ingestão. Aumente
`RAW_QUEUE_MAXSIZE` se for pico passageiro; se for constante, o gargalo costuma ser
a inferência ONNX.
