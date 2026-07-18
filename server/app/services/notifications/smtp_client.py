"""Channel 5 (email) — a real SMTP client, stdlib only (`smtplib`/`email`),
per A-13 spec: this is a classic, well-solved task, no need for a third
dependency (and its license) on top of a `smtplib.SMTP` connection.

`smtplib` is synchronous/blocking; every call here runs on a worker thread
via `asyncio.to_thread` so a slow/unreachable SMTP server cannot stall the
event loop the rest of the app (including EventBus.publish) runs on.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
from email.message import EmailMessage

from app.config import Settings

logger = logging.getLogger(__name__)


def is_smtp_configured(settings: Settings) -> bool:
    """Email is only "on" when both a host and a From address are set — no
    made-up default here, unlike jwt_secret/restic_password: this is a
    third-party external service with no sane in-repo default, per the
    A-13 task spec. Username/password are optional (open relays / local
    test servers commonly need neither)."""
    return bool(settings.smtp_host and settings.smtp_from)


def _send_sync(
    *,
    host: str,
    port: int,
    username: str | None,
    password: str | None,
    from_addr: str,
    to_addrs: list[str],
    subject: str,
    body: str,
) -> None:
    message = EmailMessage()
    message["From"] = from_addr
    message["To"] = ", ".join(to_addrs)
    message["Subject"] = subject
    message.set_content(body)

    with smtplib.SMTP(host, port, timeout=10) as smtp:
        smtp.ehlo()
        if smtp.has_extn("starttls"):
            smtp.starttls()
            smtp.ehlo()
        if username and password:
            smtp.login(username, password)
        smtp.send_message(message)


async def send_email(
    *,
    host: str,
    port: int,
    username: str | None,
    password: str | None,
    from_addr: str,
    to_addrs: list[str],
    subject: str,
    body: str,
) -> None:
    await asyncio.to_thread(
        _send_sync,
        host=host,
        port=port,
        username=username,
        password=password,
        from_addr=from_addr,
        to_addrs=to_addrs,
        subject=subject,
        body=body,
    )
