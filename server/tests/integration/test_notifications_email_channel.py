"""A-13 DoD: channel 5 (email) — a genuinely received email (subject/body
with the real event's data), through the actual stdlib `smtplib` client
(services/notifications/smtp_client.py), not a mocked `send_email`.

`_FakeSMTPServer` is a minimal hand-rolled SMTP listener (raw
`asyncio.start_server`, understands just enough of the protocol for
`smtplib` to complete a plain, non-STARTTLS send: EHLO/MAIL/RCPT/DATA/QUIT)
— chosen over `aiosmtpd` per the A-13 spec's "решите сам, что честнее для
живой проверки без реального внешнего почтового сервера": this avoids a
new dependency (aiosmtpd is not already in requirements.txt) for a single
test file, while still exercising a REAL TCP connection and the REAL
`smtplib.SMTP` client end to end — nothing about smtplib itself is mocked.

Runs in its OWN thread with its OWN event loop, deliberately NOT the test
coroutine's loop: `smtplib`'s blocking connect happens inside
`asyncio.to_thread` on FastAPI's TestClient portal thread (its own separate
event loop, not the pytest-asyncio test's), and a server bound to the
test's loop would never get to run its accept callback while the test
thread sits synchronously inside `client.post(...)` waiting on that
portal — confirmed live: the very first version of this fixture (server on
the test's own loop) deadlocked every `client.post()` call until smtplib's
connect timed out. A plain background thread sidesteps the whole "which
loop is currently free to schedule callbacks" question, the same way a
real SMTP server (a separate OS process) would never share a loop with
either side either.
"""

from __future__ import annotations

import asyncio
import threading

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.services.notifications.service as notifications_service_module
from app.config import Settings
from app.services.auth import MAX_FAILED_LOGIN_ATTEMPTS
from tests.common.factories import create_user


class _FakeSMTPServer:
    """Records every completed DATA transaction as
    {"mail_from": ..., "rcpt_to": [...], "data": "..."}."""

    def __init__(self) -> None:
        self.received: list[dict] = []
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: asyncio.base_events.Server | None = None
        self._stop_event: asyncio.Event | None = None
        self._thread: threading.Thread | None = None
        self._port: int | None = None
        self._ready = threading.Event()

    def start(self, timeout: float = 5.0) -> int:
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout=timeout):
            raise RuntimeError("fake SMTP server did not start in time")
        return self._port

    def stop(self, timeout: float = 5.0) -> None:
        if self._loop is not None and self._stop_event is not None:
            self._loop.call_soon_threadsafe(self._stop_event.set)
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def _run_loop(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._serve())

    async def _serve(self) -> None:
        self._stop_event = asyncio.Event()
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self._port = self._server.sockets[0].getsockname()[1]
        self._ready.set()
        async with self._server:
            await self._stop_event.wait()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"220 localhost fake-smtp\r\n")
        await writer.drain()

        mail_from: str | None = None
        rcpt_to: list[str] = []
        data_lines: list[str] = []
        in_data = False

        while True:
            line = await reader.readline()
            if not line:
                break
            text = line.decode(errors="replace").rstrip("\r\n")

            if in_data:
                if text == ".":
                    in_data = False
                    self.received.append(
                        {"mail_from": mail_from, "rcpt_to": list(rcpt_to), "data": "\n".join(data_lines)}
                    )
                    data_lines = []
                    writer.write(b"250 OK: queued\r\n")
                    await writer.drain()
                else:
                    data_lines.append(text[1:] if text.startswith("..") else text)
                continue

            command = text.split(" ", 1)[0].upper()
            if command in ("EHLO", "HELO"):
                writer.write(b"250-localhost\r\n250 OK\r\n")
            elif command == "MAIL":
                mail_from = text
                writer.write(b"250 OK\r\n")
            elif command == "RCPT":
                rcpt_to.append(text)
                writer.write(b"250 OK\r\n")
            elif command == "DATA":
                in_data = True
                writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
            elif command == "QUIT":
                writer.write(b"221 Bye\r\n")
                await writer.drain()
                break
            else:
                writer.write(b"250 OK\r\n")
            await writer.drain()

        writer.close()


@pytest.fixture
def fake_smtp_server():
    server = _FakeSMTPServer()
    port = server.start()
    try:
        yield server, port
    finally:
        server.stop()


async def _token(client: TestClient, session_maker: async_sessionmaker[AsyncSession]) -> str:
    await create_user(session_maker, username="mailobserver", password="pw", role="admin")
    response = client.post("/auth/login", json={"username": "mailobserver", "password": "pw"})
    return response.json()["access_token"]


@pytest.mark.integration
async def test_security_alert_delivers_a_real_email_over_a_real_smtp_connection(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    fake_smtp_server,
):
    server, port = fake_smtp_server
    settings = Settings(
        _env_file=None,
        quiet_hours_enabled=False,
        smtp_host="127.0.0.1",
        smtp_port=port,
        smtp_from="hranix-shield@example.com",
        trusted_contact_emails="ops@example.com,ciso@example.com",
    )
    monkeypatch.setattr(notifications_service_module, "get_settings", lambda: settings)
    # The trusted-contacts registry is seeded from Settings at create_app()
    # time, before this monkeypatch exists — reach into the already-built
    # app instance and set it directly, same recipients the real deployment
    # flow would seed from TRUSTED_CONTACT_EMAILS.
    client.app.state.trusted_contact_registry.set_all(settings.trusted_contact_emails_list)

    await create_user(migrated_session_maker, username="mailtarget", password="right-pass")
    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
        client.post("/auth/login", json={"username": "mailtarget", "password": "wrong-pass"})

    # Give the fake server's asyncio task a moment to finish handling the
    # connection smtplib just made synchronously inside asyncio.to_thread.
    for _ in range(50):
        if server.received:
            break
        await asyncio.sleep(0.05)

    assert len(server.received) == 1, "expected exactly one real email transaction"
    email = server.received[0]
    assert "hranix-shield@example.com" in email["mail_from"]
    assert any("ops@example.com" in rcpt for rcpt in email["rcpt_to"])
    assert any("ciso@example.com" in rcpt for rcpt in email["rcpt_to"])
    assert "Subject: Hranix Shield: security.alert" in email["data"]
    assert "mailtarget" in email["data"]  # the real event's payload, not a placeholder

    # And the notification row genuinely reflects that the send succeeded.
    token = await _token(client, migrated_session_maker)
    recent = client.get(
        "/notifications/recent", headers={"Authorization": f"Bearer {token}"}
    ).json()
    security_item = next(item for item in recent["items"] if item["topic"] == "security.alert")
    assert security_item["email_sent"] is True


@pytest.mark.integration
async def test_email_channel_is_skipped_and_logged_when_smtp_unconfigured(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    caplog: pytest.LogCaptureFixture,
):
    """Regression anchor for the honest-skip path (no fake server involved
    at all here — SMTP_HOST/SMTP_FROM are simply unset, the Phase 0
    default) — same real event bus/HTTP layer as the test above."""
    await create_user(migrated_session_maker, username="mailtarget2", password="right-pass")

    with caplog.at_level("INFO"):
        for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
            client.post("/auth/login", json={"username": "mailtarget2", "password": "wrong-pass"})

    assert any(
        "SMTP is not configured" in record.message for record in caplog.records
    ), "an unconfigured email channel must log clearly, not fail silently"
