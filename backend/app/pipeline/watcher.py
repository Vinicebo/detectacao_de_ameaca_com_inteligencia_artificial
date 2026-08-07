"""Log file tailing with offset checkpointing.

Polling puro, sem inotify. Em volume compartilhado do Docker — que é justamente
como o nginx entrega os logs aqui — o inotify não dispara de forma confiável
através do limite do mount, então um observador baseado em evento perde escrita.
Um `stat` por segundo por arquivo é barato e sempre funciona.

O que precisa estar certo:

* **Retomar após restart.** O offset vai para o Postgres; sem isso, todo deploy
  reprocessaria o arquivo inteiro e duplicaria todos os eventos.
* **Rotação.** `access.log` vira `access.log.1` e um arquivo novo nasce com o
  mesmo nome. Detectado pelo inode.
* **Truncamento.** `> access.log` mantém o inode e zera o tamanho. Detectado
  comparando o tamanho com o offset.
* **Linha parcial.** O poll pode pegar o arquivo no meio de uma escrita. A cauda
  sem `\\n` fica no buffer e o offset não avança além dela.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import stat as stat_module
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.config import Settings
from app.db.models import IngestCheckpoint
from app.db.session import session_scope
from app.logging_setup import get_logger
from app.pipeline.queues import BoundedQueue

log = get_logger(__name__)

# Teto por ciclo de leitura. Um arquivo com backlog de 2 GB (o `detector` ficou
# fora do ar a noite toda) não pode virar uma leitura única que trava o loop de
# eventos — vai sendo consumido em pedaços a cada poll.
MAX_READ_BYTES = 4 * 1024 * 1024


class TailedFile:
    """Estado de leitura de um arquivo."""

    __slots__ = ("_buffer", "inode", "offset", "path")

    def __init__(self, path: Path, inode: int, offset: int) -> None:
        self.path = path
        self.inode = inode
        self.offset = offset
        self._buffer = b""

    def read_new_lines(self) -> list[str]:
        """Lê do offset até o fim e devolve as linhas completas."""
        try:
            stat = self.path.stat()
        except OSError:
            return []

        if stat.st_size < self.offset:
            # Truncado (`> arquivo`): mesmo inode, tamanho menor. Recomeça do zero.
            log.info("watcher.truncated", path=str(self.path), previous_offset=self.offset)
            self.offset = 0
            self._buffer = b""

        if stat.st_size == self.offset:
            return []

        to_read = min(stat.st_size - self.offset, MAX_READ_BYTES)
        try:
            with self.path.open("rb") as handle:
                handle.seek(self.offset)
                chunk = handle.read(to_read)
        except OSError as exc:
            log.warning("watcher.read_failed", path=str(self.path), error=str(exc))
            return []

        if not chunk:
            return []

        data = self._buffer + chunk
        # rsplit no último \n: o que sobra depois é linha incompleta e volta ao buffer.
        complete, sep, remainder = data.rpartition(b"\n")
        if not sep:
            self._buffer = data
            self.offset += len(chunk)
            return []

        self._buffer = remainder
        self.offset += len(chunk)

        # errors="replace": a linha de request é controlada pelo cliente e pode
        # trazer byte inválido de propósito, justamente para quebrar o parser.
        return [
            line for line in complete.decode("utf-8", errors="replace").split("\n") if line.strip()
        ]


class LogWatcher:
    """Varre o diretório de logs e empurra linhas cruas para a fila."""

    def __init__(self, settings: Settings, raw_queue: BoundedQueue[str]) -> None:
        self._settings = settings
        self._queue = raw_queue
        self._files: dict[str, TailedFile] = {}
        self._lines_since_checkpoint = 0
        self._stop = asyncio.Event()

    async def _load_checkpoints(self) -> dict[str, tuple[int, int]]:
        async with session_scope() as session:
            rows = (await session.execute(select(IngestCheckpoint))).scalars().all()
            return {row.file_path: (row.inode, row.byte_offset) for row in rows}

    async def _save_checkpoints(self) -> None:
        if not self._files:
            return
        values = [
            {"file_path": str(f.path), "inode": f.inode, "byte_offset": f.offset}
            for f in self._files.values()
        ]
        try:
            async with session_scope() as session:
                statement = pg_insert(IngestCheckpoint).values(values)
                # Upsert: o arquivo já pode ter checkpoint de uma execução anterior.
                await session.execute(
                    statement.on_conflict_do_update(
                        index_elements=[IngestCheckpoint.file_path],
                        set_={
                            "inode": statement.excluded.inode,
                            "byte_offset": statement.excluded.byte_offset,
                            "updated_at": statement.excluded.updated_at,
                        },
                    )
                )
        except Exception as exc:
            # Falha ao gravar checkpoint custa reprocessamento no próximo restart,
            # não perda de dado. Não vale derrubar a ingestão por isso.
            log.warning("watcher.checkpoint_failed", error=str(exc))
        self._lines_since_checkpoint = 0

    def _discover(self, checkpoints: dict[str, tuple[int, int]]) -> None:
        """Procura arquivos novos e trata rotação nos já conhecidos.

        Síncrono de propósito, chamado por ``asyncio.to_thread``. ``glob``, ``stat``
        e ``exists`` são todos bloqueantes; num diretório com muitos arquivos
        rotacionados isso seguraria o loop de eventos a cada ciclo de polling —
        justamente o loop que precisa estar livre para drenar as filas.
        """
        try:
            candidates = sorted(self._settings.log_dir.glob(self._settings.log_glob))
        except OSError as exc:
            log.warning("watcher.glob_failed", dir=str(self._settings.log_dir), error=str(exc))
            return

        for path in candidates:
            try:
                stat = path.stat()
            except OSError:
                continue

            # Só arquivo comum. A imagem do nginx deixa `access.log` como symlink
            # para /dev/stdout; tentar acompanhar um pipe daria leitura bloqueante
            # ou tamanho sempre zero, dependendo do caso.
            if not stat_is_regular(stat.st_mode):
                continue

            inode = stat.st_ino

            key = str(path)
            known = self._files.get(key)

            if known is None:
                saved_inode, saved_offset = checkpoints.get(key, (0, 0))
                # Mesmo inode do checkpoint: retoma de onde parou. Inode diferente
                # (ou desconhecido): arquivo novo, lê do começo.
                offset = saved_offset if saved_inode == inode else 0
                self._files[key] = TailedFile(path, inode, offset)
                log.info("watcher.tailing", path=key, offset=offset, resumed=offset > 0)
            elif known.inode != inode:
                # Rotacionou: o nome aponta para um arquivo novo.
                log.info("watcher.rotated", path=key, old_inode=known.inode, new_inode=inode)
                self._files[key] = TailedFile(path, inode, 0)

        # Arquivo que sumiu (rotação com compressão) para de ser acompanhado.
        for key in [k for k in self._files if not Path(k).exists()]:
            log.info("watcher.gone", path=key)
            del self._files[key]

    async def run(self) -> None:
        checkpoints = await self._load_checkpoints()
        log.info(
            "watcher.start",
            dir=str(self._settings.log_dir),
            glob=self._settings.log_glob,
            checkpoints=len(checkpoints),
        )

        try:
            while not self._stop.is_set():
                await asyncio.to_thread(self._discover, checkpoints)

                total = 0
                for tailed in list(self._files.values()):
                    # A leitura é síncrona; to_thread evita segurar o loop de
                    # eventos enquanto o disco responde.
                    lines = await asyncio.to_thread(tailed.read_new_lines)
                    for line in lines:
                        await self._queue.put(line)
                    total += len(lines)

                if total:
                    self._lines_since_checkpoint += total
                    # Checkpoint por volume, não por linha: uma escrita no Postgres
                    # por linha de log seria mais cara que a detecção inteira.
                    if self._lines_since_checkpoint >= 500:
                        await self._save_checkpoints()

                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(
                        self._stop.wait(), timeout=self._settings.poll_interval_seconds
                    )
        finally:
            await self._save_checkpoints()
            log.info("watcher.stopped")

    def stop(self) -> None:
        self._stop.set()


def stat_is_regular(mode: int) -> bool:
    """True para arquivo comum — exclui symlink para pipe, socket e dispositivo."""
    return stat_module.S_ISREG(mode)


def file_inode(path: Path) -> int:
    """Inode do arquivo, ou 0 se inacessível."""
    try:
        return os.stat(path).st_ino
    except OSError:
        return 0
