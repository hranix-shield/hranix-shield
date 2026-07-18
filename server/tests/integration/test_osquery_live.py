"""A-15 DoD: a live end-to-end check against a REAL `osqueryi` binary on the
host — not the monkeypatched tests in test_osquery_connector.py /
test_security_console_network_av.py.

Deliberately opt-in and self-skipping, marked `osquery_live` (registered in
pytest.ini), same shape as A-11's `crowdsec_live` marker
(test_crowdsec_live.py): skips with a clear reason when `osqueryi` is not on
`PATH`, so a plain `server/venv/bin/python -m pytest -q` run needs no
osquery install at all. On this dev machine, `osqueryi` could not be
installed while building this task (`brew install --cask osquery` requires
an interactive sudo prompt this environment cannot supply — see the A-15
task report), so this file self-skips here; it is written to actually run
DoD's own scenario ("открой реальное TCP-соединение в тесте... убедись, что
оно видно в ответе API") on any host that does have `osqueryi` installed.

Run explicitly with:
    server/venv/bin/python -m pytest -q -m osquery_live
"""

from __future__ import annotations

import os
import shutil
import socket
import threading

import pytest

from app.services.mcp.security_connectors.osquery import fetch_network_console_data


def _osqueryi_available() -> bool:
    return shutil.which("osqueryi") is not None


@pytest.mark.osquery_live
async def test_live_osquery_shows_a_freshly_opened_tcp_connection():
    if not _osqueryi_available():
        pytest.skip("osqueryi not installed on this host — see infra/security/osquery/README.md")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    server_port = server_sock.getsockname()[1]

    accepted: dict[str, socket.socket] = {}

    def _accept() -> None:
        conn, _addr = server_sock.accept()
        accepted["conn"] = conn

    accept_thread = threading.Thread(target=_accept, daemon=True)
    accept_thread.start()

    client_sock = socket.create_connection(("127.0.0.1", server_port), timeout=5)
    accept_thread.join(timeout=5)

    try:
        result = await fetch_network_console_data()
        assert result["connector"]["status"] == "ok", (
            f"expected osquery to be reachable on this host, got: {result['connector']}"
        )

        pid = os.getpid()
        matching = [
            row
            for row in result["connections"]
            if row["pid"] == pid and row["remote_port"] == server_port
        ]
        assert matching, (
            f"expected the freshly-opened connection to 127.0.0.1:{server_port} "
            f"(pid {pid}) to show up in osquery's process_open_sockets, got: "
            f"{result['connections']}"
        )
    finally:
        client_sock.close()
        conn = accepted.get("conn")
        if conn is not None:
            conn.close()
        server_sock.close()
