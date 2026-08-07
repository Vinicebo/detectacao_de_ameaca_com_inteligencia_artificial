"""Backpressure tests."""

from __future__ import annotations

from app.pipeline.queues import BoundedQueue, PipelineQueues


async def test_accepts_items_under_capacity() -> None:
    queue: BoundedQueue[str] = BoundedQueue(maxsize=3, name="teste")
    for item in ("a", "b", "c"):
        await queue.put(item)

    assert queue.qsize() == 3
    assert queue.dropped == 0


async def test_drops_oldest_when_full() -> None:
    """Cheia, descarta o mais antigo — nunca bloqueia.

    Bloquear empurraria a pressão de volta para o leitor de log, e aí o arquivo
    rotaciona por baixo dele: perde-se muito mais do que uma entrada velha.
    """
    queue: BoundedQueue[str] = BoundedQueue(maxsize=2, name="teste")
    await queue.put("antiga")
    await queue.put("meio")
    await queue.put("nova")

    assert queue.qsize() == 2
    assert queue.dropped == 1
    # A mais antiga saiu; as recentes ficaram.
    assert await queue.get() == "meio"
    assert await queue.get() == "nova"


async def test_drops_are_counted_for_observability() -> None:
    """Perda silenciosa num sistema de segurança é pior que perda nenhuma."""
    queue: BoundedQueue[int] = BoundedQueue(maxsize=5, name="teste")
    for i in range(100):
        await queue.put(i)

    stats = queue.stats()
    assert stats["depth"] == 5
    assert stats["dropped"] == 95
    assert stats["enqueued"] == 100


async def test_put_never_blocks_under_flood() -> None:
    """O cenário que o sistema existe para detectar não pode travá-lo."""
    queue: BoundedQueue[int] = BoundedQueue(maxsize=10, name="flood")
    for i in range(10_000):
        await queue.put(i)

    assert queue.qsize() == 10


async def test_pipeline_queue_stats_shape() -> None:
    queues = PipelineQueues(raw_size=10, parsed_size=10, scored_size=10)
    await queues.raw.put("linha")

    stats = queues.stats()
    assert set(stats) == {"raw", "parsed", "scored"}
    assert stats["raw"]["depth"] == 1
    assert stats["parsed"]["depth"] == 0
