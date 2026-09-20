"""A-60: integration-тесты bootstrap стека защиты
(services/stack/bootstrap.py + POST /security/stack/bootstrap +
GET /security/stack/status).

Все docker-вызовы мокаются на уровне `run_local_command` — того самого
единого шлюза, через который bootstrap ходит наружу (план-спецификация:
«docker-вызовы мокаются через run_local_command-механику; полный живой
bootstrap — живой прогон, не автотест»). Порт-проверка `_host_ports_busy`
мокается отдельно, чтобы результат не зависел от того, что случится на
машинах разработки — она тестируется как «занято/свободно/наш стек».

Живая среда этой машины сознательно не используется: тесты не требуют
Docker и не поднимают контейнеров.
"""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
import app.services.stack.bootstrap as bootstrap_module
from tests.common.factories import create_user

# ---------------------------------------------------------------------------
# Фейковая docker-обстановка: диспетчер по подстрокам argv.
# ---------------------------------------------------------------------------


def _install_fake_docker(
    monkeypatch: pytest.MonkeyPatch,
    *,
    responses: dict[str, tuple[int, str, str]] | None = None,
    calls: list[tuple[str, ...]] | None = None,
    docker_missing: bool = False,
) -> None:
    """`run_local_command` -> детерминированный фейк. `responses` позволяет
    переопределить ответ по подстроке argv (проверяется первой); остальное —
    здоровая docker-обстановка: info ок, сеть создаётся, compose up ок,
    bouncers list пуст, bouncers add печатает свежий ключ, machines add ок.
    `docker_missing=True` имитирует машину без Docker (NotFound на всё)."""

    from app.services.mcp.security_connectors._local_command import LocalCommandNotFound

    default_responses = {
        "docker info": (0, "29.5.3\n", ""),
        "network create": (0, "net-id\n", ""),
        " up": (0, "", ""),
        "bouncers list": (0, "[]\n", ""),
        "bouncers add": (0, "fresh-bouncer-key\n", ""),
        "machines add": (0, "Machine 'hranix-panel' successfully added\n", ""),
        "ps": (0, "", ""),
    }
    merged = {**default_responses, **(responses or {})}

    async def fake_run(*args: str, timeout: float = 5.0):
        if calls is not None:
            calls.append(args)
        if docker_missing:
            raise LocalCommandNotFound(f"{args[0]!r} is not installed on this host")
        joined = " ".join(args)
        for needle, response in merged.items():
            if needle in joined:
                return response
        return (0, "", "")

    monkeypatch.setattr(bootstrap_module, "run_local_command", fake_run)
    # Свободные порты по умолчанию — конкретная машина разработки не должна
    # влиять на результат (реальная bind-проба тестируется отдельно).
    monkeypatch.setattr(bootstrap_module, "_host_ports_busy", lambda ports: [])


async def _run_bootstrap(tmp_path: Path, **kwargs) -> dict:
    return await bootstrap_module.run_stack_bootstrap(
        data_dir=kwargs.pop("data_dir", tmp_path / "data"),
        log_dir=kwargs.pop("log_dir", tmp_path / "logs"),
        config_env_file=kwargs.pop("config_env_file", tmp_path / "data" / ".env"),
        **kwargs,
    )


def _step(response: dict, name: str) -> dict:
    return next(step for step in response["steps"] if step["step"] == name)


# ---------------------------------------------------------------------------
# Шаги bootstrap: честный docker-missing, happy path, идемпотентность.
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_docker_missing_returns_honest_status_not_an_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from app.services.mcp.security_connectors._local_command import LocalCommandNotFound

    async def fake_run(*args: str, timeout: float = 5.0):
        raise LocalCommandNotFound(f"{args[0]!r} is not installed on this host")

    monkeypatch.setattr(bootstrap_module, "run_local_command", fake_run)

    response = await _run_bootstrap(tmp_path)

    assert response["status"] == "docker_missing"
    assert response["restart_required"] is False
    assert _step(response, "docker")["status"] == "missing"
    skipped = [s for s in response["steps"][1:]]
    assert {s["status"] for s in skipped} == {"skipped"}


@pytest.mark.integration
async def test_bootstrap_happy_path_generates_files_and_writes_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    calls: list[tuple[str, ...]] = []
    _install_fake_docker(monkeypatch, calls=calls)

    response = await _run_bootstrap(tmp_path)

    assert response["status"] == "ok"
    assert response["restart_required"] is True
    assert all(step["status"] == "ok" for step in response["steps"])

    data_dir = tmp_path / "data"
    stack_dir = data_dir / "stack"

    # Секреты stack.env: сгенерированы, пароль проходит политику образа Wazuh.
    stack_env = bootstrap_module.parse_env_file(data_dir / "stack.env")
    assert stack_env["WAZUH_API_USERNAME"] == "wazuh-wui"
    assert stack_env["CROWDSEC_MACHINE_ID"] == "hranix-panel"
    password = stack_env["WAZUH_API_PASSWORD"]
    assert len(password) >= 12
    assert any(c.isupper() for c in password)
    assert any(c.islower() for c in password)
    assert any(c.isdigit() for c in password)
    assert any(c in bootstrap_module._PASSWORD_SYMBOLS for c in password)

    # Сгенерированный compose: три сервиса, те же образы, loopback-порты,
    # external-сеть, wazuh ulimits и :ro-маунты каталогов приложения.
    compose = (stack_dir / "docker-compose.yml").read_text(encoding="utf-8")
    assert "crowdsecurity/crowdsec:latest" in compose
    assert "clamav/clamav-debian:latest" in compose
    assert "wazuh/wazuh-manager:4.14.6" in compose
    assert '127.0.0.1:8089:8080' in compose
    assert '127.0.0.1:3310:3310' in compose
    assert '127.0.0.1:55000:55000' in compose
    assert "external: true" in compose
    assert "hranix-security-net" in compose
    assert "655360" in compose
    assert "/monitored/data:ro" in compose
    assert "/monitored/logs:ro" in compose
    assert (stack_dir / "wazuh" / "ossec.conf").is_file()
    assert (stack_dir / "wazuh" / "api.yaml").is_file()

    # config.env: все десять ключей записаны (в т.ч. CLAMAV_ENABLED=True —
    # без него clamav-коннектор честно остаётся not_configured).
    config_env = bootstrap_module.parse_env_file(data_dir / ".env")
    for key in bootstrap_module._CONFIG_ENV_KEYS:
        assert config_env.get(key, ""), f"{key} must be written"
    assert config_env["CLAMAV_ENABLED"] == "True"
    assert config_env["CROWDSEC_API_KEY"] == "fresh-bouncer-key"

    # Последовательность docker-вызовов: info, network create, compose up,
    # bouncers add, machines add (--force — идемпотентность самого cscli).
    joined_calls = [" ".join(args) for args in calls]
    assert any("docker info" in c for c in joined_calls)
    assert any("network create hranix-security-net" in c for c in joined_calls)
    assert any("compose" in c and " up -d" in c for c in joined_calls)
    assert any("cscli bouncers add hranix-panel -o raw" in c for c in joined_calls)
    assert any(
        "cscli machines add hranix-panel --password" in c and " --force" in c
        for c in joined_calls
    )


@pytest.mark.integration
async def test_bootstrap_rerun_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    calls: list[tuple[str, ...]] = []
    _install_fake_docker(monkeypatch, calls=calls)

    first = await _run_bootstrap(tmp_path)
    assert first["status"] == "ok"
    config_before = (tmp_path / "data" / ".env").read_text(encoding="utf-8")
    stack_env_before = (tmp_path / "data" / "stack.env").read_text(encoding="utf-8")
    compose_before = (tmp_path / "data" / "stack" / "docker-compose.yml").read_text(
        encoding="utf-8"
    )

    calls.clear()
    second = await _run_bootstrap(tmp_path)

    assert second["status"] == "ok"
    # Секреты переиспользованы, не перегенерированы (detail несёт и выбор
    # порта Wazuh API, поэтому проверяем префикс, а не строку целиком).
    assert _step(second, "secrets")["detail"].startswith("reused")
    assert (tmp_path / "data" / "stack.env").read_text(encoding="utf-8") == stack_env_before
    assert (tmp_path / "data" / ".env").read_text(encoding="utf-8") == config_before
    # compose-файлы генерируются заново (шаблон — источник истины), но
    # содержимое идентично: пути зависят только от data_dir.
    assert (
        tmp_path / "data" / "stack" / "docker-compose.yml"
    ).read_text(encoding="utf-8") == compose_before
    # Ключ bouncer'а уже в config.env — `bouncers add` НЕ повторяется
    # (ключ прочитать обратно из CrowdSec нельзя, повторный add был бы
    # неидемпотентным); machine перерегистрируется через --force.
    joined_calls = [" ".join(args) for args in calls]
    assert not any("bouncers add" in c for c in joined_calls)
    assert any("machines add" in c and "--force" in c for c in joined_calls)
    assert _step(second, "crowdsec_credentials")["status"] == "ok"


@pytest.mark.integration
async def test_bootstrap_merge_does_not_overwrite_existing_user_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _install_fake_docker(monkeypatch)
    config_env_file = tmp_path / "data" / ".env"
    config_env_file.parent.mkdir(parents=True)
    config_env_file.write_text(
        "\n".join(
            [
                "# operator's own settings",
                "MY_CUSTOM_KEY=keep-me",
                "CROWDSEC_API_KEY=operator-existing-key",
                "CROWDSEC_LAPI_URL=http://127.0.0.1:9999",
                "CLAMAV_ENABLED=False",
                "WAZUH_API_PASSWORD=Operator-Own-7!",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    response = await _run_bootstrap(tmp_path)

    assert response["status"] == "ok"
    merged = bootstrap_module.parse_env_file(config_env_file)
    # Чужие/пользовательские ключи не затронуты.
    assert merged["MY_CUSTOM_KEY"] == "keep-me"
    assert merged["CROWDSEC_API_KEY"] == "operator-existing-key"
    assert merged["CROWDSEC_LAPI_URL"] == "http://127.0.0.1:9999"
    assert merged["CLAMAV_ENABLED"] == "False"
    # Пользовательский пароль Wazuh выигрывает и попадает в stack.env —
    # иначе контейнер поднялся бы с одним паролем, а коннектор логинился
    # бы другим.
    assert merged["WAZUH_API_PASSWORD"] == "Operator-Own-7!"
    stack_env = bootstrap_module.parse_env_file(tmp_path / "data" / "stack.env")
    assert stack_env["WAZUH_API_PASSWORD"] == "Operator-Own-7!"
    # Отсутствующие ключи дописаны.
    assert merged["CROWDSEC_MACHINE_PASSWORD"]
    assert merged["WAZUH_API_URL"] == "http://127.0.0.1:55000"


@pytest.mark.integration
async def test_bootstrap_port_busy_is_reported_honestly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _install_fake_docker(monkeypatch)  # docker ps вернёт пусто — «не наш стек»
    monkeypatch.setattr(bootstrap_module, "_host_ports_busy", lambda ports: [55000])

    response = await _run_bootstrap(tmp_path)

    assert response["status"] == "failed"
    compose_up = _step(response, "compose_up")
    assert compose_up["status"] == "port_busy"
    assert "55000" in (compose_up["detail"] or "")
    # Последующие шаги честно пропущены, не «успешны».
    assert _step(response, "crowdsec_credentials")["status"] == "skipped"
    assert _step(response, "config_env")["status"] == "skipped"
    assert response["restart_required"] is False


@pytest.mark.integration
async def test_bootstrap_skips_compose_up_when_our_stack_already_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Повторный прогон при работающем стеке: порты заняты НАШИМИ
    контейнерами — это «already running», а не port_busy, и bootstrap
    доводит до конца (например, докeregistrирует креденшелы)."""
    calls: list[tuple[str, ...]] = []
    _install_fake_docker(
        monkeypatch,
        calls=calls,
        responses={
            "ps": (
                0,
                "hranix-crowdsec\nhranix-clamav\nhranix-wazuh-manager\n",
                "",
            ),
        },
    )
    monkeypatch.setattr(bootstrap_module, "_host_ports_busy", lambda ports: [8089, 3310])

    response = await _run_bootstrap(tmp_path)

    assert response["status"] == "ok"
    assert _step(response, "compose_up")["status"] == "ok"
    assert "already running" in (_step(response, "compose_up")["detail"] or "")
    assert not any(" up -d" in " ".join(args) for args in calls)
    # Креденшелы всё равно доводятся (стек running, а ключей могло не быть).
    assert _step(response, "crowdsec_credentials")["status"] == "ok"


@pytest.mark.integration
async def test_bootstrap_recreates_bouncer_when_key_was_lost(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Bouncer с именем hranix-panel существует в CrowdSec, но ключа в
    config.env нет (например, файл потерян) — старый ключ irrecoverable,
    bootstrap пересоздаёт bouncer (delete + add) и записывает новый ключ."""
    calls: list[tuple[str, ...]] = []
    _install_fake_docker(
        monkeypatch,
        calls=calls,
        responses={
            "bouncers list": (
                0,
                json.dumps([{"name": "hranix-panel", "valid": True}]),
                "",
            ),
        },
    )

    response = await _run_bootstrap(tmp_path)

    assert response["status"] == "ok"
    joined_calls = [" ".join(args) for args in calls]
    assert any("cscli bouncers delete hranix-panel" in c for c in joined_calls)
    assert any("cscli bouncers add hranix-panel -o raw" in c for c in joined_calls)
    merged = bootstrap_module.parse_env_file(tmp_path / "data" / ".env")
    assert merged["CROWDSEC_API_KEY"] == "fresh-bouncer-key"


@pytest.mark.integration
async def test_bootstrap_selects_fallback_port_when_55000_is_os_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """winnat/Hyper-V на части Windows-машин резервирует 55000 (динамический
    диапазон 49152-65535; найдено живьём 2026-09-20 — bind И docker -p
    отвечают 10013). Bootstrap честно отступает на первый свободный порт и
    согласует compose-маппинг с WAZUH_API_URL в config.env — коннектор
    всегда попадает в фактический порт, никто не «молчит»."""
    _install_fake_docker(monkeypatch)

    def busy_except_55001(ports):
        # 55000 занята OS-резервом, всё остальное свободно.
        return [p for p in ports if p == 55000]

    monkeypatch.setattr(bootstrap_module, "_host_ports_busy", busy_except_55001)

    response = await _run_bootstrap(tmp_path)

    assert response["status"] == "ok"
    stack_env = bootstrap_module.parse_env_file(tmp_path / "data" / "stack.env")
    # Второй кандидат — 55100 (шаг 100): winnat резервирует сплошные
    # 100-портовые куски, перебор 55001, 55002... остался бы внутри того
    # же резерва (живой прогон 2026-09-20).
    assert stack_env["WAZUH_API_PORT"] == "55100"
    compose = (tmp_path / "data" / "stack" / "docker-compose.yml").read_text(
        encoding="utf-8"
    )
    assert '"127.0.0.1:55100:55000"' in compose
    assert '"127.0.0.1:55000:55000"' not in compose
    merged = bootstrap_module.parse_env_file(tmp_path / "data" / ".env")
    assert merged["WAZUH_API_URL"] == "http://127.0.0.1:55100"


@pytest.mark.integration
async def test_bootstrap_reuses_user_wazuh_api_url_port(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Непустой пользовательский WAZUH_API_URL в config.env выигрывает:
    compose слушает его порт, merge его не перезатирает."""
    _install_fake_docker(monkeypatch)
    config_env_file = tmp_path / "data" / ".env"
    config_env_file.parent.mkdir(parents=True)
    config_env_file.write_text(
        "WAZUH_API_URL=http://127.0.0.1:55999\n", encoding="utf-8"
    )

    response = await _run_bootstrap(tmp_path)

    assert response["status"] == "ok"
    stack_env = bootstrap_module.parse_env_file(tmp_path / "data" / "stack.env")
    assert stack_env["WAZUH_API_PORT"] == "55999"
    compose = (tmp_path / "data" / "stack" / "docker-compose.yml").read_text(
        encoding="utf-8"
    )
    assert '"127.0.0.1:55999:55000"' in compose
    assert (
        bootstrap_module.parse_env_file(config_env_file)["WAZUH_API_URL"]
        == "http://127.0.0.1:55999"
    )


# ---------------------------------------------------------------------------
# stack_status: docker missing / здоровый ответ без изменений состояния.
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_stack_status_reports_missing_docker_honestly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from app.services.mcp.security_connectors._local_command import LocalCommandNotFound

    async def fake_run(*args: str, timeout: float = 5.0):
        raise LocalCommandNotFound(f"{args[0]!r} is not installed on this host")

    monkeypatch.setattr(bootstrap_module, "run_local_command", fake_run)

    status = await bootstrap_module.stack_status(config_env_file=tmp_path / "absent.env")

    assert status["docker"]["status"] == "missing"
    assert status["containers"]["status"] == "absent"
    assert status["credentials"]["status"] == "missing"
    assert set(status["credentials"]["missing"]) == set(bootstrap_module._CREDENTIAL_ENV_KEYS)


# ---------------------------------------------------------------------------
# HTTP-слой: admin-only POST, честные коды, GET доступен viewer'у.
# ---------------------------------------------------------------------------


async def _token_for(
    client: TestClient,
    maker: async_sessionmaker[AsyncSession],
    *,
    username: str,
    role: str,
) -> str:
    await create_user(maker, username=username, password="pw", role=role)
    response = client.post("/auth/login", json={"username": username, "password": "pw"})
    return response.json()["access_token"]


@pytest.mark.integration
async def test_bootstrap_endpoint_is_admin_only(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    admin_token = await _token_for(
        client, migrated_session_maker, username="stack-admin", role="admin"
    )
    viewer_token = await _token_for(
        client, migrated_session_maker, username="stack-viewer", role="viewer"
    )

    # Viewer: 403, и bootstrap-функция при этом НЕ вызывается.
    viewer_response = client.post(
        "/security/stack/bootstrap",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert viewer_response.status_code == 403
    assert viewer_response.json()["detail"]["error"] == "insufficient_role"

    # Без токена — 401, как у всех остальных эндпоинтов панели.
    anonymous = client.post("/security/stack/bootstrap")
    assert anonymous.status_code == 401

    # Admin: 200 с пошаговым статусом (bootstrap-функция фейковая — HTTP-слой
    # проверяет только RBAC и форму ответа; сами шаги покрыты выше).
    async def fake_bootstrap() -> dict:
        return {
            "status": "ok",
            "steps": [{"step": "docker", "status": "ok", "detail": None}],
            "restart_required": True,
        }

    monkeypatch.setattr(security_console_module, "run_stack_bootstrap", fake_bootstrap)
    admin_response = client.post(
        "/security/stack/bootstrap",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert admin_response.status_code == 200
    body = admin_response.json()
    assert body["status"] == "ok"
    assert body["restart_required"] is True
    assert body["steps"][0]["step"] == "docker"


@pytest.mark.integration
async def test_status_endpoint_is_available_to_any_authenticated_user(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def fake_status() -> dict:
        return {
            "docker": {"status": "ok", "detail": None},
            "containers": {"status": "absent", "running": [], "expected": []},
            "credentials": {"status": "missing", "missing": ["CROWDSEC_API_KEY"], "expected": []},
        }

    monkeypatch.setattr(security_console_module, "stack_status", fake_status)
    viewer_token = await _token_for(
        client, migrated_session_maker, username="status-viewer", role="viewer"
    )
    response = client.get(
        "/security/stack/status", headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert response.status_code == 200
    assert response.json()["docker"]["status"] == "ok"
