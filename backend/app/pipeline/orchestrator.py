"""Wires the four stages together and owns the detector process lifecycle.

Cada estágio é uma tarefa que consome de uma fila e produz na próxima. Separar em
tarefas — em vez de uma função que faz tudo por linha — permite que estágios
lentos (inferência ONNX) e rápidos (parse) trabalhem em paralelo, e que a
contrapressão apareça na profundidade das filas em vez de travar tudo.

**Desligamento é ordenado, não abrupto.** Ao receber SIGTERM, o leitor de log
para e injeta uma sentinela; cada estágio termina o que tem em mãos, repassa a
sentinela e encerra. O dispatcher grava o último lote antes de sair. Um `kill -9`
no meio de um lote perderia até 100 eventos já detectados.
"""

from __future__ import annotations

import asyncio
import contextlib
import signal
from typing import Any

import orjson

from app.config import Settings
from app.db.session import dispose_engine, init_engine
from app.detection.engine import RuleEngine
from app.logging_setup import configure_logging, get_logger
from app.pipeline.queues import SHUTDOWN, PipelineQueues
from app.pipeline.stage1_parse import ParseStats, parse_line
from app.pipeline.stage2_features import FeatureExtractor
from app.pipeline.stage3_detect import Detector
from app.pipeline.stage4_dispatch import Dispatcher, to_alert_payload
from app.pipeline.watcher import LogWatcher
from app.realtime.bus import AlertBus
from app.redis_client import close_redis, get_redis, init_redis

log = get_logger(__name__)

# O processo `detector` guarda os contadores em memória, mas quem serve /stats é o
# processo `api`. O detector publica um retrato aqui a cada poucos segundos.
PIPELINE_STATS_KEY = "pipeline:stats"
STATS_INTERVAL_SECONDS = 5.0


class Pipeline:
    """Os quatro estágios e seu ciclo de vida."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self.queues = PipelineQueues(
            settings.raw_queue_maxsize,
            settings.parsed_queue_maxsize,
            settings.scored_queue_maxsize,
        )
        self.parse_stats = ParseStats()
        self._redis = get_redis()
        self.bus = AlertBus(self._redis, settings.alerts_channel)
        self.extractor = FeatureExtractor(settings, self._redis)
        self.detector = Detector(settings, RuleEngine())
        self.dispatcher = Dispatcher(settings, self.bus)
        self.watcher = LogWatcher(settings, self.queues.raw)
        self._tasks: list[asyncio.Task[Any]] = []

    # ------------------------------------------------------------ estágios
    async def _parse_stage(self) -> None:
        while True:
            item = await self.queues.raw.get()
            try:
                if item is SHUTDOWN:
                    await self.queues.parsed.put_sentinel()
                    return
                entry = parse_line(item, self.parse_stats)  # type: ignore[arg-type]
                if entry is not None:
                    await self.queues.parsed.put(entry)
            finally:
                self.queues.raw.task_done()

    async def _feature_stage(self) -> None:
        while True:
            item = await self.queues.parsed.get()
            try:
                if item is SHUTDOWN:
                    await self.queues.scored.put_sentinel()
                    return
                try:
                    featured = await self.extractor.extract(item)  # type: ignore[arg-type]
                except Exception as exc:
                    # Uma entrada que quebra a extração não pode derrubar o estágio.
                    log.warning("features.failed", error=str(exc))
                    continue
                await self.queues.scored.put(featured)
            finally:
                self.queues.parsed.task_done()

    async def _detect_and_dispatch_stage(self) -> None:
        """Estágios 3 e 4 na mesma tarefa.

        Não vale a pena separar: a inferência ONNX é síncrona e o dispatcher já
        acumula em lote. Uma quarta fila entre eles só adicionaria latência.
        """
        settings = self._settings
        last_flush_check = asyncio.get_running_loop().time()

        while True:
            timeout = max(0.05, settings.dispatch_flush_seconds)
            try:
                item = await asyncio.wait_for(self.queues.scored.get(), timeout=timeout)
            except TimeoutError:
                await self.dispatcher.flush()
                continue

            try:
                if item is SHUTDOWN:
                    return
                scored = self.detector.score(item)  # type: ignore[arg-type]
                await self.dispatcher.handle(scored)
            except Exception as exc:
                log.warning("detect.failed", error=str(exc))
            finally:
                self.queues.scored.task_done()

            now = asyncio.get_running_loop().time()
            if now - last_flush_check >= settings.dispatch_flush_seconds:
                await self.dispatcher.flush()
                last_flush_check = now

    async def _publish_stats(self) -> None:
        """Retrato periódico dos contadores, para o processo `api` ler."""
        with contextlib.suppress(asyncio.CancelledError):
            while True:
                await asyncio.sleep(STATS_INTERVAL_SECONDS)
                payload = {
                    "queues": self.queues.stats(),
                    "parse": self.parse_stats.as_dict(),
                    "dispatch": self.dispatcher.stats(),
                    "detection_mode": self.detector.mode,
                    "model_version": self.detector.model_version,
                }
                # Telemetria indisponível não pode derrubar a detecção.
                with contextlib.suppress(Exception):
                    await self._redis.set(PIPELINE_STATS_KEY, orjson.dumps(payload), ex=30)

    # ------------------------------------------------------------ ciclo de vida
    async def start(self) -> None:
        log.info(
            "pipeline.start",
            mode=self.detector.mode,
            model_version=self.detector.model_version,
            rules=self.detector.rule_count,
        )
        self._tasks = [
            asyncio.create_task(self.watcher.run(), name="watcher"),
            asyncio.create_task(self._parse_stage(), name="parse"),
            asyncio.create_task(self._feature_stage(), name="features"),
            asyncio.create_task(self._detect_and_dispatch_stage(), name="detect"),
            asyncio.create_task(self._publish_stats(), name="stats"),
        ]

    # ASYNC109 sugere usar asyncio.timeout no lugar do parâmetro. Aqui o valor é
    # repassado direto ao asyncio.wait, que é o mecanismo correto: queremos saber
    # *quais* tarefas não terminaram para cancelá-las, e um timeout externo
    # cancelaria o drain inteiro sem essa informação.
    async def drain(self, timeout: float = 20.0) -> None:  # noqa: ASYNC109
        """Desligamento ordenado: para de ler e esvazia o que já entrou."""
        log.info("pipeline.draining")
        self.watcher.stop()
        await self.queues.raw.put_sentinel()

        # As tarefas de estágio terminam sozinhas ao ver a sentinela.
        stage_tasks = [t for t in self._tasks if t.get_name() != "stats"]
        _done, pending = await asyncio.wait(stage_tasks, timeout=timeout)
        if pending:
            log.warning("pipeline.drain_timeout", pending=[t.get_name() for t in pending])
            for task in pending:
                task.cancel()

        for task in self._tasks:
            if task.get_name() == "stats":
                task.cancel()

        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self.dispatcher.flush()
        self.extractor.close()
        log.info("pipeline.stopped", **self.dispatcher.stats())

    async def ingest_lines(self, lines: list[str]) -> dict[str, int]:
        """Ingestão direta, sem passar pelo arquivo — usada por POST /ingest/batch."""
        stats = ParseStats()
        accepted = 0
        for line in lines:
            entry = parse_line(line, stats)
            if entry is None:
                continue
            featured = await self.extractor.extract(entry)
            scored = self.detector.score(featured)
            await self.dispatcher.handle(scored)
            accepted += 1
        await self.dispatcher.flush()
        return {"accepted": accepted, "parsed": stats.parsed, "malformed": stats.malformed}


async def run_detector(settings: Settings) -> None:
    """Ponto de entrada do processo `detector`."""
    configure_logging(settings)
    init_engine(settings)
    init_redis(settings)

    pipeline = Pipeline(settings)
    stopping = asyncio.Event()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            # O Docker manda SIGTERM no `stop`; sem tratar, o processo morre no
            # meio de um lote e perde eventos já detectados.
            loop.add_signal_handler(sig, stopping.set)

    await pipeline.start()
    try:
        await stopping.wait()
    finally:
        await pipeline.drain()
        await close_redis()
        await dispose_engine()


__all__ = ["PIPELINE_STATS_KEY", "Pipeline", "run_detector", "to_alert_payload"]
