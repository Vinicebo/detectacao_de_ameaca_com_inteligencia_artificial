"""Bounded queues connecting the pipeline stages.

Sob flood — que é exatamente o cenário que este sistema existe para detectar — a
ingestão passa a chegar mais rápido do que a detecção consegue pontuar. Duas saídas
ruins: fila ilimitada (o processo cresce até o OOM killer) ou bloquear na escrita
(a pressão volta para o leitor de log e o arquivo rotaciona por baixo dele, aí a
perda é bem maior).

A escolha aqui é descartar o item **mais antigo**. Numa rajada de ataque, a
requisição de 40 segundos atrás vale menos que a que está chegando agora. E todo
descarte é contado e exposto em ``/stats`` — perda silenciosa num sistema de
segurança é pior que perda nenhuma.
"""

from __future__ import annotations

import asyncio

from app.logging_setup import get_logger

log = get_logger(__name__)

# Sentinela de desligamento: cada estágio repassa e encerra, esvaziando a
# pipeline em ordem em vez de cortar tarefas no meio de uma escrita.
SHUTDOWN = object()


class BoundedQueue[T]:
    """Fila com teto e descarte do mais antigo."""

    __slots__ = ("_name", "_queue", "dropped", "enqueued")

    def __init__(self, maxsize: int, name: str) -> None:
        self._queue: asyncio.Queue[T | object] = asyncio.Queue(maxsize=maxsize)
        self._name = name
        self.dropped = 0
        self.enqueued = 0

    async def put(self, item: T) -> None:
        """Enfileira, descartando o mais antigo se estiver cheia. Nunca bloqueia."""
        try:
            self._queue.put_nowait(item)
            self.enqueued += 1
            return
        except asyncio.QueueFull:
            pass

        try:
            self._queue.get_nowait()
            self.dropped += 1
            # Log só a cada 1000 descartes: sob flood, logar cada um viraria o
            # próprio problema.
            if self.dropped % 1000 == 1:
                log.warning("queue.dropping", queue=self._name, dropped_total=self.dropped)
        except asyncio.QueueEmpty:
            # Outro consumidor esvaziou entre o QueueFull e agora. Sem problema.
            pass

        try:
            self._queue.put_nowait(item)
            self.enqueued += 1
        except asyncio.QueueFull:
            # Produtores concorrentes reencheram. Descarta o item novo em vez de
            # entrar em laço de tentativa.
            self.dropped += 1

    async def put_sentinel(self) -> None:
        """Enfileira a sentinela de desligamento, esperando espaço se preciso."""
        await self._queue.put(SHUTDOWN)

    async def get(self) -> T | object:
        return await self._queue.get()

    def task_done(self) -> None:
        self._queue.task_done()

    async def join(self) -> None:
        await self._queue.join()

    def qsize(self) -> int:
        return self._queue.qsize()

    @property
    def name(self) -> str:
        return self._name

    def stats(self) -> dict[str, int]:
        return {
            "depth": self._queue.qsize(),
            "enqueued": self.enqueued,
            "dropped": self.dropped,
        }


class PipelineQueues:
    """As três filas que ligam os quatro estágios."""

    def __init__(self, raw_size: int, parsed_size: int, scored_size: int) -> None:
        self.raw: BoundedQueue[str] = BoundedQueue(raw_size, "raw")
        self.parsed: BoundedQueue[object] = BoundedQueue(parsed_size, "parsed")
        self.scored: BoundedQueue[object] = BoundedQueue(scored_size, "scored")

    def stats(self) -> dict[str, dict[str, int]]:
        return {
            "raw": self.raw.stats(),
            "parsed": self.parsed.stats(),
            "scored": self.scored.stats(),
        }
