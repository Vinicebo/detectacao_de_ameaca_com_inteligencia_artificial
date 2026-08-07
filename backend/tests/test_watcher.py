"""Log tailing tests.

Estes cobrem os quatro modos de falha que fazem um tailer perder ou duplicar
linhas em produção: linha parcial, rotação, truncamento e retomada por offset.
"""

from __future__ import annotations

from pathlib import Path

from app.pipeline.watcher import MAX_READ_BYTES, TailedFile, file_inode


def tailed(path: Path, offset: int = 0) -> TailedFile:
    return TailedFile(path, path.stat().st_ino, offset)


def test_reads_complete_lines(tmp_path: Path) -> None:
    log_file = tmp_path / "access.log"
    log_file.write_text("linha um\nlinha dois\n", encoding="utf-8")

    assert tailed(log_file).read_new_lines() == ["linha um", "linha dois"]


def test_partial_line_is_held_until_complete(tmp_path: Path) -> None:
    """Uma linha sem \\n ainda está sendo escrita.

    Entregá-la agora produziria um evento com a URI cortada — e no ciclo seguinte
    a outra metade viraria um segundo evento, igualmente errado.
    """
    log_file = tmp_path / "access.log"
    log_file.write_text("completa\nparcial-sem-", encoding="utf-8")

    tail = tailed(log_file)
    assert tail.read_new_lines() == ["completa"]

    with log_file.open("a", encoding="utf-8") as handle:
        handle.write("quebra\n")

    assert tail.read_new_lines() == ["parcial-sem-quebra"]


def test_resumes_from_offset(tmp_path: Path) -> None:
    """Retomar do offset é o que impede reprocessar tudo a cada restart."""
    log_file = tmp_path / "access.log"
    first = "primeira\n"
    log_file.write_text(first + "segunda\n", encoding="utf-8")

    tail = tailed(log_file, offset=len(first.encode()))
    assert tail.read_new_lines() == ["segunda"]


def test_truncation_resets_offset(tmp_path: Path) -> None:
    """`> access.log` mantém o inode e zera o tamanho.

    Sem detectar isso, o offset ficaria além do fim do arquivo e o tailer nunca
    mais leria nada — silenciosamente.
    """
    log_file = tmp_path / "access.log"
    log_file.write_text("a\nb\nc\n", encoding="utf-8")

    tail = tailed(log_file)
    assert tail.read_new_lines() == ["a", "b", "c"]

    log_file.write_text("nova\n", encoding="utf-8")
    assert tail.read_new_lines() == ["nova"]
    assert tail.offset == len("nova\n")


def test_no_new_data_returns_empty(tmp_path: Path) -> None:
    log_file = tmp_path / "access.log"
    log_file.write_text("linha\n", encoding="utf-8")

    tail = tailed(log_file)
    assert tail.read_new_lines() == ["linha"]
    assert tail.read_new_lines() == []
    assert tail.read_new_lines() == []


def test_missing_file_returns_empty_without_raising(tmp_path: Path) -> None:
    log_file = tmp_path / "some.log"
    log_file.write_text("x\n", encoding="utf-8")
    tail = tailed(log_file)
    log_file.unlink()

    assert tail.read_new_lines() == []


def test_invalid_utf8_is_replaced_not_fatal(tmp_path: Path) -> None:
    """A linha do request é controlada pelo cliente e pode trazer byte inválido.

    Byte cru em UTF-8 é exatamente o que um scanner manda para quebrar o parser —
    tem que virar caractere de substituição, não exceção.
    """
    log_file = tmp_path / "access.log"
    log_file.write_bytes(b"valida\n\xff\xfe invalida\n")

    lines = tailed(log_file).read_new_lines()
    assert len(lines) == 2
    assert lines[0] == "valida"
    assert "invalida" in lines[1]


def test_blank_lines_are_skipped(tmp_path: Path) -> None:
    log_file = tmp_path / "access.log"
    log_file.write_text("a\n\n   \nb\n", encoding="utf-8")

    assert tailed(log_file).read_new_lines() == ["a", "b"]


def test_large_backlog_is_read_in_chunks(tmp_path: Path) -> None:
    """Backlog grande não pode virar uma leitura única.

    Se o detector ficou fora do ar, o arquivo pode ter gigabytes. Ler tudo de uma
    vez seguraria o loop de eventos e estouraria a memória; o teto por ciclo faz
    o backlog ser consumido aos poucos.
    """
    log_file = tmp_path / "access.log"
    line = "x" * 99 + "\n"
    with log_file.open("w", encoding="utf-8") as handle:
        for _ in range((MAX_READ_BYTES // 100) + 5000):
            handle.write(line)

    tail = tailed(log_file)
    first = tail.read_new_lines()
    assert tail.offset <= MAX_READ_BYTES
    assert len(first) > 0

    second = tail.read_new_lines()
    assert len(second) > 0, "o restante precisa sair no ciclo seguinte"


def test_file_inode_of_missing_path_is_zero(tmp_path: Path) -> None:
    assert file_inode(tmp_path / "nao-existe.log") == 0
