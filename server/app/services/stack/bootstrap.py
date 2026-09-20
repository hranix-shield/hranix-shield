"""A-60: идемпотентный bootstrap стека защиты (CrowdSec + ClamAV + Wazuh)
прямо из приложения — автоматизация тех самых ручных DevOps-шагов, которые
раньше описывали только `infra/security/*/README.md`: `docker compose up`,
`cscli bouncers add`, `cscli machines add`, пароль Wazuh API, ручная запись
`.env`. План-спецификация:
docs/план-спецификация-фаза-0-A60-A61-автостек-2026-09-20.md.

Ключевое ограничение плана: **packaged-бандл не содержит `infra/`** (datas
spec: static, alembic, vendor/osqueryi, vendor/geoip) — поэтому compose-файлы
и конфиги Wazuh (ossec.conf/api.yaml) **генерируются кодом** из шаблонов ниже
в data dir (`<data>/stack/`), а не копируются из репозитория. По существу это
те же три сервиса, что в `infra/security/*/docker-compose.yml`: те же образы
(crowdsecurity/crowdsec:latest, clamav/clamav-debian:latest,
wazuh/wazuh-manager:4.14.6), те же 127.0.0.1-порты 8089/3310/55000 (+1514/1515
Wazuh agent-каналы, A-25), та же external-сеть `hranix-security-net`, тот же
wazuh ulimits/nofile-блок и host-safety-чеклист (изолированная bridge-сеть,
никогда не `privileged`, только loopback-порты, никаких bind-маунтов
пользовательских каталогов — только два каталога самого приложения
`<data>`/`<logs>` :ro).

Docker Desktop **молча не ставится**: его отсутствие/незапущенность — это
честный шаг-статус `{step: "docker", status: "missing"}` в ответе, не
исключение. Исключения наружу из `run_stack_bootstrap()` вообще не
пролетают — каждый шаг ловит своё и возвращает статус.

Все внешние вызовы (docker, cscli) идут через
`run_local_command` из `_local_command` — argv-списком, никогда не
shell-строкой; именно эту функцию мокают тесты. Docker резолвится через PATH
процесса — тот же принцип, что у osquery/restic: packaged-процесс наследует
пользовательский PATH (Docker Desktop прописывает себя в системный PATH при
установке), ничего не изобретается.
"""

from __future__ import annotations

import json
import logging
import secrets
import socket
from pathlib import Path
from typing import Any

from app.config import REPO_ROOT, _packaged_data_dir, _packaged_log_dir, is_packaged
from app.services.mcp.security_connectors._local_command import (
    LocalCommandNotFound,
    LocalCommandTimedOut,
    run_local_command,
)

logger = logging.getLogger(__name__)

# Имена/порты — ровно те же, что инфраструктурные compose-файлы уже
# закрепили (infra/security/*); менять их означает ломать и .env.example,
# и коннекторы, и эту генерацию одновременно.
CROWDSEC_BOUNCER_NAME = "hranix-panel"
CROWDSEC_MACHINE_ID_DEFAULT = "hranix-panel"
NETWORK_NAME = "hranix-security-net"
CROWDSEC_CONTAINER = "hranix-crowdsec"
CLAMAV_CONTAINER = "hranix-clamav"
WAZUH_CONTAINER = "hranix-wazuh-manager"
EXPECTED_CONTAINERS = (CROWDSEC_CONTAINER, CLAMAV_CONTAINER, WAZUH_CONTAINER)

# Порядок и имена шагов фиксированы (ответ всегда перечисляет все семь —
# недошедшие честно skipped).
_STEP_SEQUENCE = (
    "docker",
    "secrets",
    "compose_files",
    "network",
    "compose_up",
    "crowdsec_credentials",
    "config_env",
)

# Все 127.0.0.1-маппинги сгенерированного compose-файла, КРОМЕ Wazuh API —
# проверяются на занятость ДО `docker compose up` (план-спечный риск
# `port_busy`). Порт Wazuh API выбирается отдельно (см.
# _resolve_wazuh_api_port): дефолт 55000, но этот порт попадает в
# динамический диапазон Windows (49152-65535), который winnat/Hyper-V
# резервирует случайными кусками на части машин — найдено живьём на машине
# разработки 2026-09-20 (10013 на bind И на docker -p; README-раздел
# «Расхождения» отчёта A-60/A-61), поэтому первый свободный из 55001+ —
# честный отступ с записью фактического WAZUH_API_URL в config.env.
STACK_PORTS = (8089, 3310, 1514, 1515)
WAZUH_API_DEFAULT_PORT = 55000
# Кандидаты после дефолта идут ШАГОМ 100: живой прогон 2026-09-20 показал,
# что winnat резервирует Сплошные 100-портовые куски (54568-55267 на этой
# машине) — перебор 55001, 55002... остаётся внутри того же резерва, а шаг
# 100 перепрыгивает в соседний блок. Первый bind-удачный кандидат
# фиксируется в stack.env/config.env, так что порт стабилен между прогонами.
WAZUH_API_PORT_CANDIDATES = (WAZUH_API_DEFAULT_PORT, *range(55100, 59600, 100))

# Шаговые таймауты (план-спецификация: docker info 10с, compose up 300с).
_DOCKER_INFO_TIMEOUT = 10.0
_NETWORK_TIMEOUT = 10.0
_COMPOSE_UP_TIMEOUT = 300.0
_CSCLI_TIMEOUT = 60.0

# Ключи config.env, которыми bootstrap владеет/проверяет (план-спецификация,
# шаг 7; CLAMAV_ENABLED добавлен, потому что без него DoD «все три коннектора
# ok» недостижим — clamav_enabled=False по умолчанию честно даёт
# not_configured даже при поднятом контейнере).
_CONFIG_ENV_KEYS = (
    "CROWDSEC_LAPI_URL",
    "CROWDSEC_API_KEY",
    "CROWDSEC_MACHINE_ID",
    "CROWDSEC_MACHINE_PASSWORD",
    "CLAMAV_ENABLED",
    "CLAMAV_HOST",
    "CLAMAV_PORT",
    "WAZUH_API_URL",
    "WAZUH_API_USERNAME",
    "WAZUH_API_PASSWORD",
)
_CREDENTIAL_ENV_KEYS = (
    "CROWDSEC_LAPI_URL",
    "CROWDSEC_API_KEY",
    "CROWDSEC_MACHINE_ID",
    "CROWDSEC_MACHINE_PASSWORD",
    "WAZUH_API_URL",
    "WAZUH_API_USERNAME",
    "WAZUH_API_PASSWORD",
)

# Алфавит генерируемых паролей без `$`, `#`, кавычек и обратных слэшей:
# значения попадают в stack.env (docker compose env-file), в argv cscli и в
# config.env (pydantic-settings dotenv) — ни один из этих форматов не требует
# экранирования для выбранных символов, а `$`/кавычки в compose env-file как
# раз требуют.
_PASSWORD_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
_PASSWORD_LOWER = "abcdefghijkmnopqrstuvwxyz"
_PASSWORD_DIGITS = "23456789"
_PASSWORD_SYMBOLS = "!@%^*-_=+?"
_PASSWORD_ALPHABET = _PASSWORD_UPPER + _PASSWORD_LOWER + _PASSWORD_DIGITS + _PASSWORD_SYMBOLS


def _generate_password(length: int = 20) -> str:
    """Случайный пароль, проходящий политику сложности образа Wazuh
    (минимум 8 символов, верхний/нижний регистр, цифра, символ — отклонение
    слабого пароля подтверждено образом на старте контейнера), с символьным
    алфавитом, безопасным для compose env-file / dotenv / argv (см. выше)."""
    alphabet = _PASSWORD_ALPHABET
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c in _PASSWORD_UPPER for c in password)
            and any(c in _PASSWORD_LOWER for c in password)
            and any(c in _PASSWORD_DIGITS for c in password)
            and any(c in _PASSWORD_SYMBOLS for c in password)
        ):
            return password


# ---------------------------------------------------------------------------
# Пути. Паттерн «_packaged_data_dir() if is_packaged() else REPO_ROOT» — тот
# же, что config.jwt_secret_file()/resolve_env_file(); приватные функции
# config импортируются явно (вместо дублирования platformdirs-вызова), чтобы
# при смене A-19-раскладки менять одно место, а не два. Параметры data_dir/
# log_dir/config_env_file у публичных функций — точка тестовой изоляции:
# тесты передают tmp_path и не трогают ни окружение, ни реальный REPO_ROOT.
# ---------------------------------------------------------------------------


def _default_data_dir() -> Path:
    """Базовый data dir приложения: `<repo>/data` в dev/Docker/pytest
    (gitignored), platformdirs data dir в packaged-режиме — тот же каталог,
    где живут .jwt_secret/.restic_password и config.env."""
    if is_packaged():
        return _packaged_data_dir()
    return REPO_ROOT / "data"


def _default_log_dir() -> Path:
    """Каталог логов для wazuh-маунта `/monitored/logs` — platformdirs log
    dir в packaged-режиме (config._packaged_log_dir), `<repo>/logs` в dev."""
    if is_packaged():
        return _packaged_log_dir()
    return REPO_ROOT / "logs"


def _stack_env_path(data_dir: Path) -> Path:
    return data_dir / "stack.env"


def _stack_dir(data_dir: Path) -> Path:
    return data_dir / "stack"


# ---------------------------------------------------------------------------
# Простейший dotenv-парсер/мерджер. Достаточно для config.env и stack.env:
# KEY=VALUE, `#`-комментарии, пустые строки. Пустое значение считается
# «не настроено» (та же семантика, что у Settings: pydantic-settings отдаёт
# пустую строку, коннекторы честно отвечают not_configured).
# ---------------------------------------------------------------------------


def parse_env_file(path: Path) -> dict[str, str]:
    """Читает KEY=VALUE-файл. Отсутствующий файл = пустой словарь, не
    ошибка — «ещё ничего не настроено» нормальный статус."""
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        values[key.strip()] = value.strip()
    return values


def _merge_env_file(path: Path, updates: dict[str, str]) -> list[str]:
    """Домержит `updates` в KEY=VALUE-файл, НЕ затирая существующие непустые
    значения (план-спецификация шаг 7: «существующие пользовательские ключи
    не затирать»). Ключ с пустым значением считается ненастроенным и
    заполняется. Возвращает список реально дописанных/заполненных ключей
    (для detail-текста шага). Файл перезаписывается целиком только когда
    есть что менять."""
    lines = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
    filled: list[str] = []
    seen: set[str] = set()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            value = stripped.split("=", 1)[1].strip()
            seen.add(key)
            if key in updates and value:
                continue
            if key in updates and not value:
                # Пустое значение = не настроено — заполняем.
                lines[index] = f"{key}={updates[key]}"
                filled.append(key)
    missing = [key for key in updates if key not in seen]
    if missing:
        lines.extend(f"{key}={updates[key]}" for key in missing)
        filled.extend(missing)
    if filled:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return filled


# ---------------------------------------------------------------------------
# Шаблоны генерируемого compose-проекта. Содержание — из infra/security/*,
# «без изменений по существу» (план-спецификация): те же образы, порты,
# тома, host-safety-чеклисты. Комментарии-первоисточники — в infra-файлах,
# здесь только шапка-ссылка.
# ---------------------------------------------------------------------------


def _render_compose(stack_dir: Path, data_dir: Path, log_dir: Path, wazuh_api_port: int) -> str:
    """Текст docker-compose.yml с абсолютными путями и фактическим
    host-портом Wazuh API этого экземпляра установки. Пути — через
    as_posix(): docker compose на всех трёх ОС принимает прямые слэши, а
    backslash-вариант с двоеточием буквы диска Windows неоднозначен для
    парсера volume-строк."""
    wazuh_conf = (stack_dir / "wazuh" / "ossec.conf").as_posix()
    wazuh_api = (stack_dir / "wazuh" / "api.yaml").as_posix()
    monitored_data = data_dir.as_posix()
    monitored_logs = log_dir.as_posix()
    return f"""\
# A-60: сгенерировано приложением (services/stack/bootstrap.py) из шаблонов
# в коде — packaged-бандл не содержит infra/. По существу это
# infra/security/crowdsec/docker-compose.yml + clamav + wazuh, собранные в
# один проект: те же образы, 127.0.0.1-порты (8089 LAPI / 3310 clamd /
# 55000 Wazuh API + 1514/1515 agent-каналы, A-25), external-сеть
# hranix-security-net и host-safety-чеклист (изолированная bridge-сеть, не
# privileged, никаких пользовательских bind-маунтов — только каталоги самого
# приложения :ro). Полные обоснования каждого поля — в infra/security/*.
#
# Переменные API_USERNAME/API_PASSWORD резолвятся из <data>/stack.env
# (передаётся через --env-file при каждом docker compose вызове bootstrap'а).
#
# Секреты Wazuh: сложность пароля проверяет сам образ при старте (слабый
# отклоняется громкой ошибкой, не молча).

services:
  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: {CROWDSEC_CONTAINER}
    restart: unless-stopped
    networks:
      - hranix-security-net
    ports:
      # Только 127.0.0.1 — та же конвенция «localhost by default», что в
      # .env.example/SECURITY.md; 8089 не пересекается с SERVER_PORT=8080.
      - "127.0.0.1:8089:8080"
    volumes:
      # Собственная БД + hub-контент CrowdSec — named volume, не bind-маунт;
      # host /var/log не монтируется (реальный сбор логов не настроен —
      # осознанное решение A-11).
      - crowdsec-data:/var/lib/crowdsec/data

  clamav:
    image: clamav/clamav-debian:latest
    container_name: {CLAMAV_CONTAINER}
    restart: unless-stopped
    networks:
      - hranix-security-net
    ports:
      # 3310 — документированный дефолт clamd; CLAMAV_PORT совпадает.
      - "127.0.0.1:3310:3310"
    environment:
      # Свежесозданный контейнер не делает ни одного сетевого вызова сам
      # (та же «safe default» политика, что CLAMAV_ENABLED/BACKUP_ENABLED);
      # подписи, вшитые в образ, работают, обновление — явный opt-in
      # (docker compose exec clamav freshclam).
      - CLAMAV_NO_FRESHCLAMD=true
    volumes:
      # Собственная база подписей clamd — named volume, не bind-маунт.
      - clamav-db:/var/lib/clamav

  wazuh-manager:
    image: wazuh/wazuh-manager:4.14.6
    container_name: {WAZUH_CONTAINER}
    restart: unless-stopped
    # Обязательно для realtime (inotify) FIM — без этого wazuh-syscheckd
    # падает с «Select failed» (см. infra/security/wazuh/docker-compose.yml).
    ulimits:
      nofile:
        soft: 655360
        hard: 655360
      memlock:
        soft: -1
        hard: -1
    networks:
      - hranix-security-net
    ports:
      # API + agent-каналы (1514/1515, A-25) — всё только на 127.0.0.1;
      # 514/1516 намеренно не публикуются (host-safety-чеклист A-16).
      # Host-порт API — дефолт 55000; на машинах, где winnat/Hyper-V
      # зарезервировал этот порт, bootstrap выбирает первый свободный
      # (55001+) и записывает фактический WAZUH_API_URL в config.env.
      - "127.0.0.1:{wazuh_api_port}:55000"
      - "127.0.0.1:1514:1514"
      - "127.0.0.1:1515:1515"
    environment:
      # Образ сам создаёт/обновляет REST API пользователя при старте.
      - API_USERNAME=${{WAZUH_API_USERNAME:-wazuh-wui}}
      - API_PASSWORD=${{WAZUH_API_PASSWORD:?WAZUH_API_PASSWORD is required in stack.env}}
    volumes:
      # Собственное FIM/agent-состояние менеджера — named volume.
      - wazuh-var:/var/ossec/queue
      # Конфиги, генерируемые рядом с этим файлом (перечитываются образом
      # при каждом старте контейнера — WAZUH_CONFIG_MOUNT-механизм).
      - {wazuh_conf}:/wazuh-config-mount/etc/ossec.conf:ro
      - {wazuh_api}:/wazuh-config-mount/api/configuration/api.yaml:ro
      # Единственные bind-маунты — два каталога самого приложения, только
      # чтение (решение #2 в infra/security/wazuh/docker-compose.yml).
      - {monitored_data}:/monitored/data:ro
      - {monitored_logs}:/monitored/logs:ro

networks:
  # Внешняя сеть — создаётся bootstrap'ом идемпотентно до compose up;
  # compose-проект её не владеет (external: true), как и в infra/*.
  hranix-security-net:
    external: true

volumes:
  crowdsec-data:
  clamav-db:
  wazuh-var:
"""


# ossec.conf — урезанная копия infra/security/wazuh/config/ossec.conf (те же
# блоки и значения: indexer/vulnerability-detection выключены — Decision #1;
# syscheck смотрит только два :ro-маунта приложения — Decision #2; правило
# игнорирования .log$ убрано, .swp$ оставлен). Полные комментарии решений —
# в infra-оригинале; здесь шапка-ссылка, чтобы генерат не дрейфовал молча.
_WAZUH_OSSEC_CONF = """\
<!-- A-60: сгенерировано services/stack/bootstrap.py из шаблона в коде —
     по существу то же, что infra/security/wazuh/config/ossec.conf (Decision
     #1: manager-only, indexer/vulnerability-detection выключены; Decision
     #2: FIM смотрит только /monitored/data и /monitored/logs — два :ro-маунта
     каталогов самого приложения; realtime="yes" + report_changes="yes";
     правило игнорирования .log$ убрано, .swp$ оставлен). Полные обоснования
     — в infra/security/wazuh/config/ossec.conf. -->
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <agents_disconnection_time>10m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <logging>
    <log_format>plain</log_format>
  </logging>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
    <rootkit_files>etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>
    <skip_nfs>yes</skip_nfs>
  </rootcheck>

  <wodle name="cis-cat">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>
    <java_path>wodles/java</java_path>
    <ciscat_path>wodles/ciscat</ciscat_path>
  </wodle>

  <wodle name="osquery">
    <disabled>yes</disabled>
  </wodle>

  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
    <synchronization>
      <max_eps>10</max_eps>
    </synchronization>
  </wodle>

  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
  </sca>

  <indexer>
    <enabled>no</enabled>
  </indexer>

  <vulnerability-detection>
    <enabled>no</enabled>
  </vulnerability-detection>

  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>

    <directories realtime="yes" report_changes="yes" check_all="yes">/monitored/data</directories>
    <directories realtime="yes" report_changes="yes" check_all="yes">/monitored/logs</directories>

    <ignore type="sregex">.swp$</ignore>

    <skip_nfs>yes</skip_nfs>
    <skip_dev>yes</skip_dev>
    <skip_proc>yes</skip_proc>
    <skip_sys>yes</skip_sys>
    <process_priority>10</process_priority>
    <max_eps>100</max_eps>

    <synchronization>
      <enabled>yes</enabled>
      <interval>5m</interval>
      <max_interval>1h</max_interval>
      <max_eps>10</max_eps>
    </synchronization>
  </syscheck>

  <global>
    <white_list>127.0.0.1</white_list>
    <white_list>^localhost.localdomain$</white_list>
  </global>

  <command>
    <name>disable-account</name>
    <executable>disable-account</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>restart-wazuh</name>
    <executable>restart-wazuh</executable>
  </command>

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>host-deny</name>
    <executable>host-deny</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>route-null</name>
    <executable>route-null</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>

  <rule_test>
    <enabled>yes</enabled>
    <threads>1</threads>
    <max_sessions>64</max_sessions>
    <session_timeout>15m</session_timeout>
  </rule_test>

  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <purge>yes</purge>
    <use_password>no</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>

  <cluster>
    <name>wazuh</name>
    <node_name>node01</node_name>
    <node_type>master</node_type>
    <key>aa093264ef885029653eea20dfcf51ae</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>wazuh.manager</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>yes</disabled>
  </cluster>

</ossec_config>
"""

_WAZUH_API_YAML = """\
# A-60: сгенерировано services/stack/bootstrap.py — то же, что
# infra/security/wazuh/config/api.yaml: TLS на API выключен у источника,
# потому что порт 127.0.0.1-only (тот же «plain HTTP over loopback»
# прецедент, что LAPI CrowdSec); коннектору не нужен verify=False.
https:
  enabled: no
"""


# ---------------------------------------------------------------------------
# Шаги bootstrap. Каждый шаг — функция, возвращающая StepResult; исключения
# не выходят из run_stack_bootstrap.
# ---------------------------------------------------------------------------


class StepResult:
    """Итог одного шага: машина-читаемый статус + detail-строка. Статусы:
    ok | missing | skipped | port_busy | timeout | error. Ключи response —
    машиночитаемые коды, текст локализует клиент (API-контракт RU/EN).
    `data` — служебные значения между шагами (в response не попадают):
    например свежевыданный bouncer-ключ, который шаг config_env должен
    записать ровно в том виде, в каком шаг credentials его получил."""

    def __init__(self, step: str, status: str, detail: str | None = None,
                 data: dict[str, str] | None = None):
        self.step = step
        self.status = status
        self.detail = detail
        self.data = data or {}

    def to_dict(self) -> dict[str, Any]:
        return {"step": self.step, "status": self.status, "detail": self.detail}


def _truncate(text: str, limit: int = 400) -> str:
    """Одна строка, обрезанная до limit символов — stderr docker может быть
    многострочным и длинным, в пошаговый статус попадает только суть."""
    collapsed = " ".join(text.split())
    if len(collapsed) > limit:
        return collapsed[: limit - 3] + "..."
    return collapsed


async def _step_docker() -> StepResult:
    try:
        code, stdout, stderr = await run_local_command(
            "docker", "info", "--format", "{{.ServerVersion}}", timeout=_DOCKER_INFO_TIMEOUT
        )
    except LocalCommandNotFound:
        return StepResult("docker", "missing", "docker_not_installed")
    except LocalCommandTimedOut:
        return StepResult("docker", "missing", "docker_info_timed_out")
    if code != 0:
        # Бинарь есть, но демон не отвечает (Docker Desktop не запущен) —
        # для оператора это тот же честный «Docker недоступен», с деталью.
        return StepResult("docker", "missing", "docker_daemon_unreachable")
    return StepResult("docker", "ok", _truncate(stdout))


def _write_stack_env(
    stack_env_path: Path, config_env: dict[str, str], wazuh_api_port: int
) -> tuple[dict[str, str], str]:
    """Собирает и записывает <data>/stack.env — источник секретов compose.
    Непустые пользовательские значения из config.env имеют приоритет (иначе
    после перезапуска контейнер поднялся бы с паролем stack.env, а коннектор
    логинился старым из config.env). Возвращает (значения, режим)."""
    values = parse_env_file(stack_env_path)
    mode = "reused" if values else "created"

    def _resolve(key: str, generator) -> str:
        # Пользовательское непустое значение > существующее stack.env > новое.
        user_value = config_env.get(key, "").strip()
        if user_value:
            return user_value
        existing = values.get(key, "").strip()
        if existing:
            return existing
        return generator()

    resolved = {
        "WAZUH_API_USERNAME": _resolve(
            "WAZUH_API_USERNAME", lambda: "wazuh-wui"
        ),
        "WAZUH_API_PASSWORD": _resolve("WAZUH_API_PASSWORD", _generate_password),
        "WAZUH_API_PORT": str(wazuh_api_port),
        "CROWDSEC_MACHINE_ID": _resolve(
            "CROWDSEC_MACHINE_ID", lambda: CROWDSEC_MACHINE_ID_DEFAULT
        ),
        "CROWDSEC_MACHINE_PASSWORD": _resolve(
            "CROWDSEC_MACHINE_PASSWORD", _generate_password
        ),
        "CROWDSEC_BOUNCER_NAME": CROWDSEC_BOUNCER_NAME,
    }
    stack_env_path.parent.mkdir(parents=True, exist_ok=True)
    stack_env_path.write_text(
        "".join(f"{key}={value}\n" for key, value in resolved.items()),
        encoding="utf-8",
    )
    return resolved, mode


def _step_compose_files(
    stack_dir: Path, data_dir: Path, log_dir: Path, wazuh_api_port: int
) -> StepResult:
    try:
        # Каталоги data/logs должны существовать ДО `docker compose up` —
        # bind-маунты :ro несуществующего каталога Docker Desktop создаёт
        # пустыми сам, но лучше не полагаться на это поведение.
        data_dir.mkdir(parents=True, exist_ok=True)
        log_dir.mkdir(parents=True, exist_ok=True)
        (stack_dir / "wazuh").mkdir(parents=True, exist_ok=True)
        (stack_dir / "docker-compose.yml").write_text(
            _render_compose(stack_dir, data_dir, log_dir, wazuh_api_port),
            encoding="utf-8",
        )
        (stack_dir / "wazuh" / "ossec.conf").write_text(
            _WAZUH_OSSEC_CONF, encoding="utf-8"
        )
        (stack_dir / "wazuh" / "api.yaml").write_text(
            _WAZUH_API_YAML, encoding="utf-8"
        )
    except OSError as exc:
        return StepResult("compose_files", "error", f"write_failed: {exc}")
    return StepResult("compose_files", "ok", str(stack_dir))


async def _step_network(compose_file: Path, stack_env: Path) -> StepResult:
    try:
        code, _stdout, stderr = await run_local_command(
            "docker", "network", "create", NETWORK_NAME, timeout=_NETWORK_TIMEOUT
        )
    except LocalCommandNotFound:
        return StepResult("network", "missing", "docker_not_installed")
    except LocalCommandTimedOut:
        return StepResult("network", "timeout", "docker network create timed out")
    if code == 0:
        return StepResult("network", "ok", NETWORK_NAME)
    # Идемпотентность: сеть уже существует — это успех повторного прогона.
    if "already exists" in stderr.lower():
        return StepResult("network", "ok", f"{NETWORK_NAME} already exists")
    return StepResult("network", "error", _truncate(stderr))


def _host_ports_busy(ports) -> list[int]:
    """Какие из 127.0.0.1-портов уже заняты (bind-проба без SO_REUSEADDR —
    занятый кем-то порт даёт OSError). Чисто локальная проверка до compose
    up, чтобы чужой сервис на порту дал честный `port_busy`, а не сырое
    падение docker."""
    busy: list[int] = []
    for port in ports:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            busy.append(port)
        finally:
            probe.close()
    return busy


async def _resolve_wazuh_api_port(stack_env_path: Path, config_env: dict[str, str]) -> tuple[int, str]:
    """Фактический host-порт Wazuh API для этого прогона, с источником
    решения (попадает в detail шага secrets). Порядок приоритета:
      1. пользовательский WAZUH_API_URL из config.env (если он указан и
         bootstrap им не владеет — compose обязан слушать именно его);
      2. WAZUH_API_PORT прошлого прогона из stack.env — но ТОЛЬКО если
         порт до сих пор пригоден (bind-свободен либо занят нашим же
         running-стеком): неудавшийся прогон мог закрепить мёртвый порт
         (OS-резерв/чужой процесс), упорное переиспользование сделало бы
         failure вечным;
      3. первый свободный из кандидатов (шаг 100) — на «здоровой» машине
         это всегда дефолт 55000; на машине с winnat-резервом — честный
         отступ вместо необъяснимого port_busy.
    """
    user_url = config_env.get("WAZUH_API_URL", "").strip()
    if user_url:
        _, _, port_part = user_url.rpartition(":")
        if port_part.isdigit():
            return int(port_part), f"from config.env WAZUH_API_URL (port {port_part})"
    existing_port = parse_env_file(stack_env_path).get("WAZUH_API_PORT", "").strip()
    if existing_port.isdigit():
        port = int(existing_port)
        if not _host_ports_busy((port,)):
            return port, f"reused from stack.env (port {port})"
        running = await _running_stack_containers()
        if running is not None and len(running) == len(EXPECTED_CONTAINERS):
            return port, f"reused from stack.env (port {port}; held by the running stack)"
        # Порт мёртв — продолжаем к перебору кандидатов ниже.
    busy = _host_ports_busy(WAZUH_API_PORT_CANDIDATES)
    for port in WAZUH_API_PORT_CANDIDATES:
        if port not in busy:
            if port != WAZUH_API_DEFAULT_PORT:
                detail = (
                    f"port {WAZUH_API_DEFAULT_PORT} is blocked by the OS "
                    "(Hyper-V/winnat reservation) — selected first free port"
                )
                return port, detail
            return port, "default"
    return (
        WAZUH_API_DEFAULT_PORT,
        "no free port among the 55000..59500 candidates — compose up will fail honestly",
    )


async def _running_stack_containers() -> list[str] | None:
    """Имена НАШИХ контейнеров из `docker ps` (только запущенные). None =
    сам вызов docker не удался (не найден/таймаут) — вызывающий код в этом
    случае не может отличить «наш стек» от «чужой», трактуется как занятость
    чужим (честнее остановиться, чем переподнять поверх чужого сервиса)."""
    filters: list[str] = []
    for name in EXPECTED_CONTAINERS:
        filters += ["--filter", f"name={name}"]
    try:
        code, stdout, _stderr = await run_local_command(
            "docker", "ps", "--format", "{{.Names}}", *filters, timeout=_NETWORK_TIMEOUT
        )
    except (LocalCommandNotFound, LocalCommandTimedOut):
        return None
    if code != 0:
        return None
    names = {line.strip() for line in stdout.splitlines() if line.strip()}
    return [name for name in EXPECTED_CONTAINERS if name in names]


async def _step_compose_up(
    compose_file: Path, stack_env: Path, data_dir: Path, log_dir: Path, wazuh_api_port: int
) -> StepResult:
    busy = _host_ports_busy((*STACK_PORTS, wazuh_api_port))
    if busy:
        running = await _running_stack_containers()
        if running is not None and len(running) == len(EXPECTED_CONTAINERS):
            # Порты заняты нашим же запущенным стеком — `up -d` здесь
            # всё равно no-op; честный «already running», не port_busy.
            return StepResult("compose_up", "ok", "stack already running")
        return StepResult(
            "compose_up", "port_busy", "ports_busy: " + ",".join(str(p) for p in busy)
        )
    try:
        code, _stdout, stderr = await run_local_command(
            "docker", "compose",
            "-f", str(compose_file),
            "--env-file", str(stack_env),
            "up", "-d",
            timeout=_COMPOSE_UP_TIMEOUT,
        )
    except LocalCommandNotFound:
        return StepResult("compose_up", "missing", "docker_not_installed")
    except LocalCommandTimedOut:
        return StepResult(
            "compose_up", "timeout",
            "docker compose up timed out after 300s (image pull can be slow — retry)",
        )
    if code != 0:
        return StepResult("compose_up", "error", _truncate(stderr))
    return StepResult("compose_up", "ok", str(data_dir / "stack"))


async def _cscli(compose_file: Path, stack_env: Path, *args: str) -> tuple[int, str, str]:
    return await run_local_command(
        "docker", "compose",
        "-f", str(compose_file),
        "--env-file", str(stack_env),
        "exec", "-T", "crowdsec",
        *args,
        timeout=_CSCLI_TIMEOUT,
    )


async def _step_crowdsec_credentials(
    compose_file: Path, stack_env: Path, secrets_values: dict[str, str], config_env: dict[str, str]
) -> StepResult:
    """Bouncer key + machine login. Переиспользование: непустой
    CROWDSEC_API_KEY из config.env означает, что ключ уже выдавался и
    сохранён — сам ключ прочитать обратно из CrowdSec нельзя (`bouncers list`
    показывает только хэш), поэтому повторный `bouncers add` был бы
    НЕидемпотентен. Новый ключ выдаётся только когда записанного нет; если
    bouncer с этим именем уже существует (а ключа у нас нет) — он
    пересоздаётся (delete + add), потому что старый ключ irrecoverable."""
    machine_id = secrets_values["CROWDSEC_MACHINE_ID"]
    machine_password = secrets_values["CROWDSEC_MACHINE_PASSWORD"]
    bouncer_name = secrets_values.get("CROWDSEC_BOUNCER_NAME", CROWDSEC_BOUNCER_NAME)

    existing_key = config_env.get("CROWDSEC_API_KEY", "").strip()
    if existing_key:
        api_key = existing_key
        bouncer_note = "reused from config.env"
        step_data: dict[str, str] = {"api_key": api_key, "api_key_source": "reused"}
    else:
        try:
            code, stdout, stderr = await _cscli(
                compose_file, stack_env, "cscli", "bouncers", "list", "-o", "json"
            )
            if code != 0:
                return StepResult("crowdsec_credentials", "error", _truncate(stderr))
            try:
                bouncers = json.loads(stdout)
            except json.JSONDecodeError:
                return StepResult("crowdsec_credentials", "error", "unparseable cscli bouncers list output")
            names = {entry.get("name") for entry in bouncers if isinstance(entry, dict)}
            if bouncer_name in names:
                code, _stdout, stderr = await _cscli(
                    compose_file, stack_env, "cscli", "bouncers", "delete", bouncer_name
                )
                if code != 0:
                    return StepResult("crowdsec_credentials", "error", _truncate(stderr))
            code, stdout, stderr = await _cscli(
                compose_file, stack_env, "cscli", "bouncers", "add", bouncer_name, "-o", "raw"
            )
            if code != 0:
                return StepResult("crowdsec_credentials", "error", _truncate(stderr))
        except LocalCommandNotFound:
            return StepResult("crowdsec_credentials", "missing", "docker_not_installed")
        except LocalCommandTimedOut:
            return StepResult("crowdsec_credentials", "timeout", "cscli timed out")
        api_key = stdout.strip()
        if not api_key:
            return StepResult("crowdsec_credentials", "error", "cscli bouncers add printed no key")
        bouncer_note = "created"
        step_data = {"api_key": api_key, "api_key_source": "created"}

    try:
        code, _stdout, stderr = await _cscli(
            compose_file, stack_env,
            "cscli", "machines", "add", machine_id,
            "--password", machine_password, "--force",
        )
    except LocalCommandNotFound:
        return StepResult("crowdsec_credentials", "missing", "docker_not_installed")
    except LocalCommandTimedOut:
        return StepResult("crowdsec_credentials", "timeout", "cscli timed out")
    if code != 0:
        return StepResult("crowdsec_credentials", "error", _truncate(stderr))
    return StepResult(
        "crowdsec_credentials", "ok",
        f"bouncer: {bouncer_note}; machine: {machine_id}", data=step_data,
    )


def _step_config_env(
    config_env_file: Path, secrets_values: dict[str, str], api_key: str, wazuh_api_port: int
) -> StepResult:
    """Домерж config.env. CROWDSEC_API_KEY берётся ровно тот, что реально
    используется этим прогоном (переиспользованный или свежий); остальные
    значения — из stack.env, который, в свою очередь, уже учёл пользовательские
    приоритеты; WAZUH_API_URL — фактический host-порт этого экземпляра
    (см. _resolve_wazuh_api_port). Непустые существующие значения не
    затираются (_merge_env_file) — в т.ч. пользовательский WAZUH_API_URL,
    чей порт _resolve_wazuh_api_port в таком случае и берёт, так что
    compose и коннектор всегда согласованы."""
    updates = {
        "CROWDSEC_LAPI_URL": "http://127.0.0.1:8089",
        "CROWDSEC_API_KEY": api_key,
        "CROWDSEC_MACHINE_ID": secrets_values["CROWDSEC_MACHINE_ID"],
        "CROWDSEC_MACHINE_PASSWORD": secrets_values["CROWDSEC_MACHINE_PASSWORD"],
        "CLAMAV_ENABLED": "True",
        "CLAMAV_HOST": "127.0.0.1",
        "CLAMAV_PORT": "3310",
        "WAZUH_API_URL": f"http://127.0.0.1:{wazuh_api_port}",
        "WAZUH_API_USERNAME": secrets_values["WAZUH_API_USERNAME"],
        "WAZUH_API_PASSWORD": secrets_values["WAZUH_API_PASSWORD"],
    }
    try:
        filled = _merge_env_file(config_env_file, updates)
    except OSError as exc:
        return StepResult("config_env", "error", f"write_failed: {exc}")
    return StepResult("config_env", "ok", f"written: {','.join(filled)}" if filled else "no changes")


async def run_stack_bootstrap(
    *,
    data_dir: Path | None = None,
    log_dir: Path | None = None,
    config_env_file: Path | None = None,
) -> dict[str, Any]:
    """Идемпотентный bootstrap всего стека. Возвращает пошаговый статус,
    НИКОГДА не бросает исключений наружу (каждый шаг ловит своё —
    plan-spec: «никаких исключений наружу»). Параметры путей — точка
    тестовой изоляции; в продакшене вызывается без аргументов.

    Response shape (машиночитаемый, текст локализует клиент):
      {"status": "ok"|"docker_missing"|"failed",
       "steps": [{"step", "status", "detail"}, ...],
       "restart_required": bool}
    """
    data_dir = data_dir or _default_data_dir()
    log_dir = log_dir or _default_log_dir()
    config_env_file = config_env_file or (
        _packaged_data_dir() / "config.env" if is_packaged() else REPO_ROOT / ".env"
    )
    stack_dir = _stack_dir(data_dir)
    stack_env = _stack_env_path(data_dir)
    compose_file = stack_dir / "docker-compose.yml"

    steps: list[StepResult] = []

    def _finish(status: str, restart_required: bool) -> dict[str, Any]:
        # Форма ответа всегда полная: шаги, до которых дело не дошло,
        # честно помечены skipped, а не отсутствуют в списке.
        done = {step.step for step in steps}
        steps.extend(
            StepResult(name, "skipped", "earlier step failed")
            for name in _STEP_SEQUENCE
            if name not in done
        )
        return {
            "status": status,
            "steps": [step.to_dict() for step in steps],
            "restart_required": restart_required,
        }

    # Шаг 1: Docker доступен? Нет → честный статус, остальные шаги skipped.
    docker_step = await _step_docker()
    steps.append(docker_step)
    if docker_step.status != "ok":
        return _finish("docker_missing", False)

    config_env = parse_env_file(config_env_file)

    # Host-порт Wazuh API (дефолт 55000; выбор с учётом пользовательского
    # WAZUH_API_URL и OS-резервов — см. _resolve_wazuh_api_port).
    wazuh_api_port, port_source = await _resolve_wazuh_api_port(stack_env, config_env)

    # Шаг 2: секреты <data>/stack.env (создать или переиспользовать).
    try:
        secrets_values, secrets_mode = _write_stack_env(
            stack_env, config_env, wazuh_api_port
        )
        steps.append(
            StepResult("secrets", "ok", f"{secrets_mode}; wazuh api {port_source}")
        )
    except OSError as exc:
        steps.append(StepResult("secrets", "error", f"write_failed: {exc}"))
        return _finish("failed", False)

    # Шаг 3: compose-проект <data>/stack/.
    compose_step = _step_compose_files(stack_dir, data_dir, log_dir, wazuh_api_port)
    steps.append(compose_step)
    if compose_step.status != "ok":
        return _finish("failed", False)

    # Шаг 4: сеть (идемпотентно).
    network_step = await _step_network(compose_file, stack_env)
    steps.append(network_step)
    if network_step.status != "ok":
        return _finish("failed", False)

    # Шаг 5: docker compose up -d (с port_busy-проверкой до него).
    compose_up_step = await _step_compose_up(
        compose_file, stack_env, data_dir, log_dir, wazuh_api_port
    )
    steps.append(compose_up_step)
    if compose_up_step.status != "ok":
        return _finish("failed", False)

    # Шаг 6: креденшелы CrowdSec.
    credentials_step = await _step_crowdsec_credentials(
        compose_file, stack_env, secrets_values, config_env
    )
    steps.append(credentials_step)
    if credentials_step.status != "ok":
        return _finish("failed", False)

    # Шаг 7: merge config.env. Ключ bouncer'а — ровно тот, что реально
    # используется этим прогоном (переиспользованный из config.env либо
    # свежевыданный шагом credentials).
    config_step = _step_config_env(
        config_env_file, secrets_values, credentials_step.data["api_key"], wazuh_api_port
    )
    steps.append(config_step)
    if config_step.status != "ok":
        return _finish("failed", False)

    return _finish("ok", True)


# ---------------------------------------------------------------------------
# Чтение статуса (GET /security/stack/status): docker / контейнеры /
# креденшellы — ничего не меняет, все вызовы через run_local_command.
# ---------------------------------------------------------------------------


async def stack_status(
    *, config_env_file: Path | None = None
) -> dict[str, Any]:
    """Честный статус стека без изменения состояния. Каждый блок независим:
    docker недоступен не мешает увидеть, что креденшелы уже записаны."""
    config_env_file = config_env_file or (
        _packaged_data_dir() / "config.env" if is_packaged() else REPO_ROOT / ".env"
    )

    try:
        code, _stdout, _stderr = await run_local_command(
            "docker", "info", "--format", "{{.ServerVersion}}", timeout=_DOCKER_INFO_TIMEOUT
        )
        if code == 0:
            docker = {"status": "ok", "detail": None}
        else:
            docker = {"status": "missing", "detail": "docker_daemon_unreachable"}
    except LocalCommandNotFound:
        docker = {"status": "missing", "detail": "docker_not_installed"}
    except LocalCommandTimedOut:
        docker = {"status": "missing", "detail": "docker_info_timed_out"}

    running: list[str] = []
    if docker["status"] == "ok":
        names = await _running_stack_containers()
        running = names or []
    if running:
        containers = {
            "status": "running" if len(running) == len(EXPECTED_CONTAINERS) else "partial",
            "running": running,
            "expected": list(EXPECTED_CONTAINERS),
        }
    else:
        containers = {"status": "absent", "running": [], "expected": list(EXPECTED_CONTAINERS)}

    config_env = parse_env_file(config_env_file)
    missing = [key for key in _CREDENTIAL_ENV_KEYS if not config_env.get(key, "").strip()]
    credentials = {
        "status": "ok" if not missing else "missing",
        "missing": missing,
        "expected": list(_CREDENTIAL_ENV_KEYS),
    }

    return {"docker": docker, "containers": containers, "credentials": credentials}
