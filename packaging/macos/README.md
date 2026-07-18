# Hranix Shield — сборка и установка на macOS (A-20)

Нативный установщик macOS для Hranix Shield («Панель безопасности», Фаза 0) — решает
архитектурный разрыв, из-за которого Docker-развёртывание никогда не видит настоящий хост
пользователя для консоли «Периметр» (`os_firewall`/`os_disk_encryption` внутри контейнера всегда
видят Linux-контейнер, не macOS/Windows хост — см.
[план-спецификацию](../../docs/план-спецификация-фаза-0-нативные-установщики-2026-07-17.md)).

## Что тут есть

- `hranix_shield_app.py` — точка входа: `rumps`-обвязка (иконка в строке меню, без окна/Dock).
- `hranix-shield.spec` — PyInstaller-спека, собирающая `.app` (onedir).
- `dist/Hranix Shield.app` / `dist/Hranix Shield.dmg` — результат сборки (не коммитятся в git —
  собираются локально, см. ниже).

Бизнес-логика запуска (миграции → uvicorn в фоновом потоке → ожидание `/health` → открытие
браузера) живёт в `server/launcher.py`, общем для всех трёх ОС (A-20 macOS, будущие A-21 Windows/
A-22 Linux переиспользуют его без изменений) — этот каталог содержит только macOS-специфичную
упаковку вокруг него.

## Сборка

Нужен **отдельный, лёгкий** build-venv — не общий dev-`server/venv` (тот тянет
`server/requirements.txt` целиком, включая Фаза-2/голос-зависимости, torch и так далее, ненужные
и нежелательные в поставляемом бинарнике):

```bash
python3.12 -m venv /tmp/hranix-build-venv
/tmp/hranix-build-venv/bin/pip install -r server/requirements-packaged.txt

/tmp/hranix-build-venv/bin/pyinstaller packaging/macos/hranix-shield.spec \
    --distpath packaging/macos/dist --workpath packaging/macos/build --noconfirm
```

Результат: `packaging/macos/dist/Hranix Shield.app`.

**Собрано и проверено на:** macOS 26.5.2, Apple Silicon (arm64), Python 3.12.13, PyInstaller
6.21.0. Кросс-архитектурная сборка (Intel/x86_64 или `universal2`) не производилась и не
проверялась — PyInstaller не кросс-компилирует между архитектурами так же, как не
кросс-компилирует между ОС; для Intel-Mac нужна отдельная сборка на Intel-машине (или `arch -x86_64`
на Apple Silicon с Rosetta — не опробовано в этой задаче).

### `.dmg`

```bash
mkdir -p /tmp/dmg-staging
cp -R "packaging/macos/dist/Hranix Shield.app" /tmp/dmg-staging/
ln -s /Applications /tmp/dmg-staging/Applications
hdiutil create -volname "Hranix Shield" -srcfolder /tmp/dmg-staging -ov -format UDZO \
    "packaging/macos/dist/Hranix Shield.dmg"
rm -rf /tmp/dmg-staging
```

Стандартный drag-to-`Applications` образ (иконка `.app` + симлинк на `/Applications` в корне
смонтированного тома). Собран и проверен (`hdiutil attach -readonly`, содержимое подтверждено) —
без кастомного фона/расположения иконок (не в скоупе DoD этой задачи).

## onedir vs onefile — решение и почему

**Выбран onedir** (`COLLECT` + `BUNDLE` в `.spec`), не onefile. Изначально план оставлял это на
усмотрение реализации с оговоркой «эмпирически сравнить, зафиксировать выбор» — сравнение
проведено, и результат оказался однозначным сразу по двум независимым основаниям:

1. **Сам PyInstaller 6.21.0 явно предупреждает при попытке собрать onefile + `.app`-бандл
   (windowed-режим для macOS):**
   ```
   DEPRECATION: Onefile mode in combination with macOS .app bundles (windowed mode) don't make
   sense (a .app bundle can not be a single file) and clashes with macOS's security. Please
   migrate to onedir mode. This will become an error in v7.0.
   ```
   Это не домысел архитектора — дословный вывод инструмента сборки, авторитетнее любого
   стороннего рассуждения об onedir-vs-onefile trade-off.

2. **Эмпирически onefile-вариант реально не запустился.** Собран experimental onefile-`.spec`
   (тот же entry point/datas/hiddenimports, `exclude_binaries=False`, `BUNDLE(exe, ...)` напрямую
   без `COLLECT`) — при запуске:
   ```
   [PYI-98250:ERROR] Failed to load Python shared library '/tmp/_MEITZllAQ/Python': dlopen(...):
   tried: '/tmp/_MEITZllAQ/Python' (no such file), ...
   ```
   Самораспаковка во временный каталог при каждом запуске (главный практический минус onefile,
   упомянутый в задании — задержка старта у сервера, который и так поднимает БД/миграции) здесь
   даже не успела стать проблемой: связка onefile+`.app`+PyObjC/`rumps` не находит собственную
   распакованную `Python`-библиотеку и падает на старте. onedir-сборка запускалась и проходила
   полный DoD-прогон (см. ниже) без единой похожей ошибки.

Экспериментальные onefile-артефакты (spec/build/dist) удалены после проверки — не входят в
финальную поставку, в репозитории остаётся только onedir-путь.

## Первый запуск / конфигурация

Первый запуск создаёт каталог данных через `platformdirs` (см. `server/app/config.py`'s A-19
`is_packaged()`/`_packaged_data_dir()`):

```
~/Library/Application Support/Hranix Shield/   # data/, .jwt_secret, .restic_password, config.env
~/Library/Logs/Hranix Shield/                  # assistant.log
```

Перед первым запуском (или после — но `BOOTSTRAP_ADMIN_*` читается один раз, пока в `users` нет ни
одной записи) положите `config.env` в первый из путей выше — тот же формат `KEY=VALUE`, что и
корневой `.env.example` проекта:

```bash
mkdir -p "$HOME/Library/Application Support/Hranix Shield"
cat > "$HOME/Library/Application Support/Hranix Shield/config.env" << 'EOF'
SERVER_PORT=8080
BOOTSTRAP_ADMIN_USERNAME=admin
BOOTSTRAP_ADMIN_PASSWORD=<замените>

# Docker-компаньоны (CrowdSec/ClamAV/Wazuh) — те же контейнеры, что в
# infra/security/*/docker-compose.yml, опубликованные на 127.0.0.1 — .app
# запущен нативно на хосте, поэтому видит их так же, как venv-режим (не
# `hranix-crowdsec`/`hranix-clamav` по имени контейнера — это для случая,
# когда САМ Hranix Shield тоже в Docker, что не относится к этой сборке).
CROWDSEC_LAPI_URL=http://127.0.0.1:8089
CROWDSEC_API_KEY=<см. cscli bouncers add>
CLAMAV_ENABLED=True
WAZUH_API_URL=http://127.0.0.1:55000
WAZUH_API_USERNAME=wazuh-wui
WAZUH_API_PASSWORD=<из infra/security/wazuh/.env>
EOF
```

Без `config.env` сервер стартует с дефолтами `Settings` (см. `server/app/config.py`) — панель и
`/health` работают, но `BOOTSTRAP_ADMIN_*` не заданы (никакого администратора создано не будет —
вход будет невозможен, пока пользователь не задаст эти переменные и не перезапустит) и коннекторы
CrowdSec/ClamAV/Wazuh честно показывают `not_configured`/выключены.

## Gatekeeper: «неизвестный разработчик»

Бинарник **не подписан и не нотаризован** — осознанное решение этой фазы (подпись кода вне
скоупа A-20, см. план-спецификацию). При первом запуске (двойной клик, или открытие `.app` из
смонтированного `.dmg`) macOS Gatekeeper покажет предупреждение о неизвестном разработчике и
не даст открыть приложение обычным двойным кликом.

**Обход (стандартный для несигнированных `.app` на macOS):**
1. Правый клик (или Control+клик) на `Hranix Shield.app` → **Открыть**.
2. В появившемся диалоге снова нажать **Открыть** (в этот раз с опцией "всё равно открыть").
3. Дальше приложение запускается обычным двойным кликом без повторных предупреждений.

Это трение реально существует и не скрывается: пользователю придётся сделать этот шаг один раз
при первой установке.

## Лицензии (сверено по первоисточникам, не по памяти, 2026-07-17)

| Зависимость | Версия | Лицензия | Где сверено |
|---|---|---|---|
| PyInstaller | 6.21.0 | GPLv2-or-later **+ bootloader exception**, разрешающее распространять собранный бинарник под любой лицензией | `pyinstaller-6.21.0-*.whl`'s `METADATA`/`COPYING.txt`, скачано с PyPI |
| rumps | 0.4.0 | BSD-3-Clause ("Modified BSD License"), OSI-одобрено | `rumps-0.4.0.tar.gz`'s собственный `LICENSE`, скачано с PyPI |
| platformdirs | 4.10.0 | MIT | сверено в A-19 (см. `server/requirements.txt`'s комментарий) |

PyInstaller и `rumps` используются **только для сборки/упаковки на macOS** — ни один из них не
линкуется в проприетарный/AGPL-код продукта иначе, чем как build-time инструмент (PyInstaller) или
runtime-зависимость самой упаковки (`rumps`, нужен только внутри `.app`, никогда не в
`server/requirements.txt` обычного dev/Docker-режима).

## Известные ограничения / что честно не проверено

- **Только Apple Silicon (arm64).** Не собрано и не проверено на Intel Mac.
- **Консоль «Сеть» (`osquery`)** на этой машине разработки честно показывает
  `connector.status == "not_configured"` — на ней не установлен `osqueryi` (см.
  `infra/security/osquery/README.md`). Это **не регрессия A-20 и не ограничение
  Docker-vs-native**: то же самое было бы верно и в venv-режиме без `osqueryi`. Основная цель этой
  задачи — консоль «Периметр» (см. DoD ниже) — подтверждена полностью.
- Код-подпись/нотаризация не делались (осознанно, вне скоупа).
