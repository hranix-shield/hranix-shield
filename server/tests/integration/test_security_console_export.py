"""A-30: `POST /security/consoles/export` against the real app wiring
(client fixture — real migrated tmp SQLite DB, real HTTP layer via
TestClient). This is the universal export mechanism shared by BOTH the
`logs` and `network` consoles' "Экспорт журнала" action (see
`app.js`'s `ACTION_HANDLERS.export_log`) — the router endpoint itself is
console-agnostic (it only serializes whatever `rows` the client sends, see
`services/security_console_export.py`), so these tests exercise it directly
rather than per-console.
"""

import csv
import io

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.common.factories import create_user


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession]
) -> dict[str, str]:
    await create_user(session_maker, username="export_admin", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "export_admin", "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


_LOGS_ENTRIES = [
    {
        "timestamp": "2026-07-16T14:19:56+00:00",
        "level": "notice",
        "source": "wazuh_fim",
        "file": "/monitored/logs/assistant.log",
        "description": "Изменение файла под контролем целостности: /monitored/logs/assistant.log",
    },
    {
        "timestamp": "2026-07-16T15:00:00+00:00",
        "level": "notice",
        "source": "wazuh_fim",
        "file": "/monitored/data/seed.txt",
        "description": "Изменение файла под контролем целостности: /monitored/data/seed.txt",
    },
]

_NETWORK_CONNECTIONS = [
    {
        "process": "sshd",
        "pid": 4242,
        "local_address": "127.0.0.1",
        "local_port": 22,
        "remote_address": "10.0.0.5",
        "remote_port": 51234,
        "protocol": "tcp",
        "state": "ESTABLISHED",
    },
]


@pytest.mark.integration
async def test_export_logs_entries_as_csv_matches_the_source_rows_line_for_line(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post(
        "/security/consoles/export",
        headers=headers,
        json={"console_id": "logs", "format": "csv", "rows": _LOGS_ENTRIES},
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment" in response.headers["content-disposition"]
    assert "logs" in response.headers["content-disposition"]

    parsed = list(csv.DictReader(io.StringIO(response.text)))
    assert len(parsed) == len(_LOGS_ENTRIES)
    for expected, actual in zip(_LOGS_ENTRIES, parsed):
        assert actual["file"] == expected["file"]
        assert actual["description"] == expected["description"]
        assert actual["timestamp"] == expected["timestamp"]


@pytest.mark.integration
async def test_export_network_connections_as_csv_matches_the_source_rows(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """Same endpoint, same mechanism, a completely different console's row
    shape — pins that this export is genuinely generic/reusable, not
    `logs`-shaped under the hood."""
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post(
        "/security/consoles/export",
        headers=headers,
        json={"console_id": "network", "format": "csv", "rows": _NETWORK_CONNECTIONS},
    )

    assert response.status_code == 200
    parsed = list(csv.DictReader(io.StringIO(response.text)))
    assert len(parsed) == 1
    assert parsed[0]["process"] == "sshd"
    assert parsed[0]["remote_address"] == "10.0.0.5"
    assert parsed[0]["pid"] == "4242"


@pytest.mark.integration
async def test_export_as_json_returns_valid_json_matching_the_source_rows(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post(
        "/security/consoles/export",
        headers=headers,
        json={"console_id": "logs", "format": "json", "rows": _LOGS_ENTRIES},
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == _LOGS_ENTRIES


@pytest.mark.integration
async def test_export_defaults_to_csv_when_format_is_omitted(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post(
        "/security/consoles/export",
        headers=headers,
        json={"console_id": "logs", "rows": _LOGS_ENTRIES},
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")


@pytest.mark.integration
async def test_export_with_no_rows_succeeds_with_an_empty_body(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post(
        "/security/consoles/export",
        headers=headers,
        json={"console_id": "logs", "format": "csv", "rows": []},
    )

    assert response.status_code == 200
    assert response.text == ""


@pytest.mark.integration
async def test_export_requires_authentication(client: TestClient):
    response = client.post(
        "/security/consoles/export",
        json={"console_id": "logs", "format": "csv", "rows": []},
    )

    assert response.status_code == 401
