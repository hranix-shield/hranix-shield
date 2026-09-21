"""A-63-4 regression anchor (первое живое тестирование с полным стеком,
2026-09-21): «clamd INSTREAM failed: » с ПУСТЫМ сообщением на больших
файлах (Downloads/*.zip).

Реальный clamd отвечает на поток свыше `StreamMaxLength` (25 MiB по
умолчанию, тот же лимит, что и клиентский `_MAX_STREAM_BYTES`) строкой
`INSTREAM size limit exceeded. ERROR` и ОБРЫВАЕТ соединение, не дочитав
выгрузку. Клиент ловил reset как `ClamdError("clamd INSTREAM failed: " +
str(exc))` — у голого ConnectionResetError от asyncio текст пуст, отсюда и
живой симптом «INSTREAM failed: <пусто>», а реальная причина clamd
терялась.

Фикс: `scan_bytes` при обрыве дочитывает всё, что clamd успел передать, и
если там size-limit-ответ — возвращает честный `error`-вердикт с этой
причиной (скан-циклы логируют её и пропускают файл, НЕ считая это падением
clamd); `ClamdError` теперь всегда называет класс исключения — сообщение
больше не бывает пустым. `_parse_scan_response` распознаёт size-limit
ответ явно.

Тесты: фейковые reader/writer (детерминированный recover-путь) + реальный
TCP-путь через `FakeClamd` с новым abort-режимом (A-63-4), повторяющим
поведение настоящего clamd — обрыв MID-STREAM с ответом перед закрытием.
"""

from __future__ import annotations

import asyncio

import pytest

from app.services.mcp.security_connectors.clamav import (
    ClamdClient,
    ClamdError,
    _parse_scan_response,
)
from tests.common.fake_clamd import FakeClamd


class _FakeReader:
    """Ответы по вызовам read(): исключения и байты — по сценарию теста."""

    def __init__(self, script: list[bytes | Exception]):
        self._script = list(script)

    async def read(self, n: int) -> bytes:
        item = self._script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class _FakeWriter:
    def __init__(self):
        self.written: list[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> None:
        self.written.append(data)

    async def drain(self) -> None:
        await asyncio.sleep(0)

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


def _client_with(monkeypatch: pytest.MonkeyPatch, reader: _FakeReader, writer: _FakeWriter) -> ClamdClient:
    client = ClamdClient(host="127.0.0.1", port=3310, timeout=2.0)

    async def _fake_open():
        return reader, writer

    monkeypatch.setattr(ClamdClient, "_open", lambda self: _fake_open())
    return client


@pytest.mark.unit
async def test_size_limit_answer_before_reset_becomes_an_honest_error_verdict(
    monkeypatch: pytest.MonkeyPatch,
):
    """Живой clamd-сценарий: основной read падает reset'ом (clamd оборвал
    соединение), но ответ «INSTREAM size limit exceeded. ERROR» успел дойти
    — recover-ветка дочитывает его и возвращает error-вердикт с причиной, а
    не безликое ClamdError."""
    reader = _FakeReader(
        [ConnectionResetError(), b"INSTREAM size limit exceeded. ERROR\0"]
    )
    writer = _FakeWriter()
    client = _client_with(monkeypatch, reader, writer)

    result = await client.scan_bytes(b"x" * 8192)

    assert result.status == "error"
    assert "size limit exceeded" in result.raw
    assert writer.closed is True


@pytest.mark.unit
async def test_reset_without_any_answer_raises_clamderror_with_a_non_empty_message(
    monkeypatch: pytest.MonkeyPatch,
):
    """Обрыв вообще без ответа (буфер убит RST) — ClamdError остаётся, но
    сообщение больше никогда не пустое: класс исключения назван."""
    reader = _FakeReader([ConnectionResetError(), b""])
    writer = _FakeWriter()
    client = _client_with(monkeypatch, reader, writer)

    with pytest.raises(ClamdError) as excinfo:
        await client.scan_bytes(b"x" * 8192)

    message = str(excinfo.value)
    assert message.startswith("clamd INSTREAM failed: ")
    assert "ConnectionResetError" in message
    assert not message.endswith("failed: ")


@pytest.mark.unit
def test_parse_scan_response_recognizes_the_size_limit_line_explicitly():
    result = _parse_scan_response("INSTREAM size limit exceeded. ERROR")

    assert result.status == "error"
    assert result.signature is None
    assert result.raw == "INSTREAM size limit exceeded. ERROR"


@pytest.mark.unit
async def test_fake_clamd_midstream_abort_over_real_tcp_returns_the_reason():
    """Реальный TCP-путь: FakeClamd в abort-режиме (A-63-4) — читает только
    часть потока, отвечает size-limit-строкой и закрывает сокет, ровно как
    настоящий clamd при превышении StreamMaxLength. Ответ приходит в
    ОСНОВНОЙ read (без reset) — парсер сразу даёт честный error-вердикт."""
    fake = FakeClamd(
        scan_responder=lambda data: b"INSTREAM size limit exceeded. ERROR\0",
        abort_stream_after_bytes=1024,
    )
    async with fake:
        client = ClamdClient(host="127.0.0.1", port=fake.port, timeout=2.0)
        result = await client.scan_bytes(b"x" * 8192)

    assert result.status == "error"
    assert "size limit exceeded" in result.raw
