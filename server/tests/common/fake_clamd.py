"""A-17: a minimal in-process stand-in for `clamd`'s TCP protocol (PING/
VERSION/INSTREAM framing) — enough of it to exercise `ClamdClient` end to
end over a real loopback socket without Docker. Shared between
tests/unit/test_clamav_client.py and tests/unit/test_clamav_scan.py so both
files test against identical fake-server behavior rather than two
independently-drifting copies.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
from collections.abc import Callable


class FakeClamd:
    """`scan_responder(data: bytes) -> bytes` decides what an INSTREAM
    upload gets answered with (defaults to always-clean: `b"stream: OK\\0"`).
    """

    def __init__(
        self,
        *,
        version: str = "ClamAV 1.5.3/28059/Mon Jul 13 06:25:07 2026",
        scan_responder: Callable[[bytes], bytes] | None = None,
    ) -> None:
        self.version = version
        self.scan_responder = scan_responder or (lambda data: b"stream: OK\0")
        self.received_stream_bytes: bytes | None = None
        self._server: asyncio.AbstractServer | None = None

    @property
    def port(self) -> int:
        assert self._server is not None
        return self._server.sockets[0].getsockname()[1]  # type: ignore[union-attr, index]

    async def __aenter__(self) -> "FakeClamd":
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        command = (await reader.readuntil(b"\0"))[:-1].decode()
        if command == "zPING":
            writer.write(b"PONG\0")
        elif command == "zVERSION":
            writer.write(self.version.encode() + b"\0")
        elif command == "zINSTREAM":
            buf = bytearray()
            while True:
                length = int.from_bytes(await reader.readexactly(4), "big")
                if length == 0:
                    break
                buf += await reader.readexactly(length)
            self.received_stream_bytes = bytes(buf)
            writer.write(self.scan_responder(bytes(buf)))
        else:
            writer.write(b"UNKNOWN COMMAND\0")
        await writer.drain()
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def free_but_closed_port() -> int:
    """A port nothing is listening on right now — reliable "connection
    refused" target for unreachable-state tests."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port
