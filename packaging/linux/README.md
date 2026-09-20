# Hranix Shield — сборка и установка на Linux (A-22)

Нативный установщик Linux для Hranix Shield («Панель безопасности», Фаза 0) — решает тот же
архитектурный разрыв, что и [macOS-установщик (A-20)](../macos/README.md): Docker-развёртывание
никогда не видит настоящий хост пользователя для консоли «Периметр»
(`os_firewall`/`os_disk_encryption` внутри контейнера всегда видят Linux-контейнер, не хост — см.
[план-спецификацию](../../docs/план-спецификация-фаза-0-нативные-установщики-2026-07-17.md)).

## Что тут есть

- `hranix_shield_service.py` — точка входа: SIGTERM/SIGINT-обвязка, без GUI/браузера (см. её
  собственный докстринг для архитекторских решений #2/#3, зафиксированных заранее).
- `hranix-shield.spec` — PyInstaller-спека, собирающая onedir-бандл (без `.app`-специфики — Linux
  onedir — это просто каталог, `COLLECT`'а достаточно, никакого `BUNDLE`).
- `hranix-shield.service` — systemd system-unit (не `--user`, архитекторское решение #1).
- `debian/control`, `debian/postinst`, `debian/prerm`, `debian/postrm` — исходники `.deb`-пакета.
- `build-in-docker.sh` — собирает `dist/hranix-shield/` (onedir) внутри Linux-контейнера.
- `build-deb.sh` — собирает `.deb` вокруг уже готового onedir-бандла.
- `test/Dockerfile.systemd` — вспомогательный образ (Ubuntu 22.04 + реальный systemd как PID 1)
  для проверки установки — не часть поставки, только для локальной живой проверки (см. ниже).
- `dist/` / `build/` / `deb-staging/` — результат сборки (не коммитятся, см. `.gitignore`).

Бизнес-логика запуска (миграции → uvicorn в фоновом потоке → ожидание `/health`) живёт в
`server/launcher.py`, общем для всех трёх ОС (A-20 macOS уже использует его без изменений, эта
задача переиспользует его как есть, не переписывая) — этот каталог содержит только
Linux-специфичную упаковку вокруг него.

## Сборка

PyInstaller **не кросс-компилирует** Linux-бинарник с macOS — та же причина, что и для Windows
(см. план-спецификацию A-22). Практический обход: собрать **внутри настоящего Linux
Docker-контейнера** на этой же машине.

```bash
./packaging/linux/vendor-osquery.sh     # A-24: -> packaging/linux/vendor/osquery/osqueryi (run once first)
./packaging/linux/build-in-docker.sh    # -> packaging/linux/dist/hranix-shield/ (onedir)
./packaging/linux/build-deb.sh          # -> packaging/linux/dist/hranix-shield_0.1.0_amd64.deb
```

**Собрано и проверено на:** macOS-хост (Apple Silicon, Docker Desktop), сборочный контейнер —
`python:3.12-slim-bullseye`, `--platform linux/amd64` (см. ниже "Найденная в процессе проблема:
glibc" — почему именно этот тег, не более свежий `python:3.12-slim`), PyInstaller 6.21.0.

### Почему `--platform linux/amd64`, а не архитектура хоста

Эта задача выполнялась на Apple Silicon (arm64) хосте. Без явного `--platform` Docker молча тянет
arm64-образ, и PyInstaller собирает `aarch64`-бинарник — подтверждено эмпирически (первая попытка
сборки, до того как в скрипт был добавлен `--platform linux/amd64`, дала именно это: `file`
показал `ELF 64-bit LSB executable, ARM aarch64`). Целевая аудитория (self-hosted Debian/Ubuntu
серверы) — преимущественно amd64, поэтому `debian/control`'s `Architecture: amd64` должен быть
правдой, а не совпадением с архитектурой сборочной машины. `build-in-docker.sh`/`build-deb.sh`
оба явно фиксируют `--platform linux/amd64`; Docker Desktop на Apple Silicon прозрачно запускает
amd64-образы под QEMU (подтверждено: `docker run --rm --platform linux/amd64 python:3.12-slim-bullseye
uname -m` → `x86_64`) — медленнее нативной сборки, но приемлемо для сценария «собрал один раз,
ставишь много раз». Сборка arm64-варианта тоже возможна (убрать `--platform` или передать
`linux/arm64` явно + поменять `Architecture: arm64` в `debian/control`), но вне скоупа этой задачи.

### Найденная в процессе проблема: glibc-несовместимость (реальный баг, не гипотетический)

Первая полная сборка (`python:3.12-slim`, без суффикса) прошла PyInstaller без единой ошибки — но
собранный бинарник **не запустился** в чистом `ubuntu:22.04`-контейнере:

```
[PYI-328:ERROR] Failed to load Python shared library '/opt/hranix-shield/_internal/libpython3.12.so.1.0':
/lib/x86_64-linux-gnu/libm.so.6: version `GLIBC_2.38' not found (required by .../libpython3.12.so.1.0)
```

Причина: тег `python:3.12-slim` сейчас указывает на Debian 13 "trixie" (glibc 2.41) — заметно
новее, чем glibc Ubuntu 22.04 (2.35). glibc **обратно совместим только в одну сторону** (бинарник,
слинкованный со старым glibc, работает на новом; наоборот — нет), поэтому исправление — собирать
на **самом старом** доступном образе с Python 3.12: `python:3.12-slim-bullseye` (Debian 11, glibc
2.31 — подтверждено `ldd --version` внутри образа), что безопасно старше Ubuntu 22.04 (2.35),
Ubuntu 24.04 (2.39) и Debian 12/13 (2.36/2.41) одновременно. `build-in-docker.sh`/`build-deb.sh`
оба зафиксированы на этом теге — не на голом `python:3.12-slim`, который со временем продолжит
уезжать на всё более новый Debian. Это правка, найденная и исправленная в процессе выполнения
именно этой задачи (A-22), не A-19/A-20 — `server/launcher.py`/`config.py` не тронуты.

## `.deb`: `dpkg-deb`, не `fpm` — и почему

Оба варианта были рассмотрены (план-спецификация оставляет выбор разработчику). Выбран
**`dpkg-deb`**:

- часть самого `dpkg`, уже присутствует в `python:3.12-slim-bullseye`/`ubuntu:22.04` (подтверждено
  `which dpkg-deb` внутри обоих образов) — не нужно ставить ничего дополнительного;
- `fpm` — Ruby-гем со своей цепочкой зависимостей (Ruby-рантайм), лишняя сущность ради инструмента,
  который в основном экономит время на *генерации* `control`/структуры каталогов из флагов — а этот
  пакет достаточно простой (один onedir-каталог + один systemd-unit + три maintainer-скрипта), и
  `debian/control`/`postinst`/`prerm`/`postrm` в любом случае писались вручную, чтобы точно
  соблюсти debian-конвенцию (upgrade vs remove vs purge — см. комментарии в самих файлах), так что
  экономить генерацией было особо нечего.

`build-deb.sh` стейджит файловое дерево на хосте (обычные `cp`/`mkdir`/`chmod`, всё переносимо), а
сам `dpkg-deb --build --root-owner-group` запускает внутри того же контейнера, что и
`build-in-docker.sh` (на macOS-хосте `dpkg-deb` в PATH нет вообще — подтверждено).

## systemd: system-service, не `--user` — архитекторское решение (не переоткрывалось)

`hranix-shield.service` — **system**-unit (`/lib/systemd/system/`, `WantedBy=multi-user.target`),
запускается от отдельного непривилегированного системного пользователя `hranix-shield`
(`User=`/`Group=` в unit-файле), а не через `systemctl --user`. Обоснование (см. промпт задачи):
целевая аудитория Linux-сборки — часто headless self-hosted сервер без гарантированной
desktop-сессии; `systemctl --user` требует `loginctl enable-linger` и активной пользовательской
сессии, лишняя хрупкость для этой аудитории.

`Environment=HOME=/var/lib/hranix-shield` прописан в unit-файле явно (не оставлен на неявное
поведение systemd, которое современные версии действительно умеют выводить из passwd-записи
самостоятельно) — `platformdirs.user_data_dir()`/`user_log_dir()` (A-19, `app/config.py`) резолвят
относительно `$HOME` на Linux, и живая проверка (см. ниже) подтвердила, что данные реально легли
именно туда: `/var/lib/hranix-shield/.local/share/Hranix Shield/data` и
`/var/lib/hranix-shield/.local/state/Hranix Shield/log`.

Юнит также включает базовое hardening (`NoNewPrivileges`, `ProtectSystem=strict`,
`ReadWritePaths=/var/lib/hranix-shield`, `PrivateTmp`) — не входит в DoD этой задачи как таковой,
но дёшево и стандартно для системного сервиса под выделенным непривилегированным пользователем.

## `postinst`/`prerm`/`postrm` — debian-конвенция upgrade/remove/purge

- **`postinst configure`** — идемпотентно создаёт пользователя `hranix-shield`
  (`useradd --system --home-dir /var/lib/hranix-shield --create-home --shell /usr/sbin/nologin`;
  `--create-home` обязателен — `platformdirs` резолвит пути от `$HOME`, без реального домашнего
  каталога первый запуск не найдёт, куда писать), выставляет владельца на `/opt/hranix-shield` и
  `/var/lib/hranix-shield`, `daemon-reload`, затем **`restart`** (если уже enabled — путь апгрейда)
  либо **`enable --now`** (свежая установка) — не наоборот, потому что `enable --now` на уже
  активном юните не перезапускает его на свежераспакованном бинарнике.
- **НЕ вызывает Alembic** — архитекторское решение #4: `launcher.launch()` уже идемпотентно
  накатывает миграции при каждом старте, дублировать эту логику в постинсталле означало бы два
  места, которые могут разъехаться.
- **`prerm remove`** — `systemctl disable --now` (стоп+отключение) только при полном удалении, не
  при апгрейде (тогда `prerm` вызывается с `upgrade`, и этот шаг сознательно пропускается — сервис
  остаётся жить до `postinst`'s `restart` на новой версии).
- **`postrm purge`** — удаляет пользователя/группу `hranix-shield`, `daemon-reload`. **Каталог
  `/var/lib/hranix-shield` (БД, секреты, карантин ClamAV, репозиторий restic) НЕ удаляется** —
  тот же принцип «не уничтожать пользовательские данные неявно», что уже применён в проекте для
  backup/restore (A-12); оператор, которому реально нужен чистый лист, удаляет его вручную.

## Проверка — честно, по каждому пункту DoD отдельно (принцип 8)

### 1. «Собирается» — ПОЛНОСТЬЮ ПОДТВЕРЖДЕНО

`build-in-docker.sh` завершается без единой ошибки PyInstaller, `packaging/linux/dist/hranix-shield/`
существует, `hranix-shield` — реальный ELF x86-64 бинарник (подтверждено `file`). `build-deb.sh`
собирает `hranix-shield_0.1.0_amd64.deb`, `dpkg-deb --info`/`--contents` подтверждают корректные
метаданные (`Architecture: amd64`, `Installed-Size`, три maintainer-скрипта, все файлы
`root/root`) и корректную раскладку (`/opt/hranix-shield/...`, `/lib/systemd/system/...`).

### 2. «Ставится и работает» — ПОЛНОСТЬЮ ПОДТВЕРЖДЕНО, включая реальный `systemctl`

В отличие от честной оговорки, которую допускал план («если `systemctl status` внутри голого
контейнера не завести — зафиксировать частичную проверку»), в этой сессии **реальный systemd как
PID 1 внутри тестового контейнера завёлся и заработал** — не пришлось идти на компромисс с ручным
запуском бинарника. Рецепт (`test/Dockerfile.systemd` + флаги ниже) — стандартный из нескольких
гуляющих по интернету, сработавший с первой попытки на этой связке Docker Desktop/хоста:

```bash
docker build --platform linux/amd64 -t hranix-systemd-test \
    -f packaging/linux/test/Dockerfile.systemd packaging/linux/test

docker run -d --name hranix-shield-systest \
    --platform linux/amd64 --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "$(pwd)/packaging/linux/dist:/dist:ro" \
    hranix-systemd-test
```

Полная последовательность, реально прогнанная и подтверждённая живьём в этой чистой,
предварительно ничего не знавшей об Hranix Shield машине (Ubuntu 22.04 + systemd 249):

1. `systemctl is-system-running` → `running` (систем инициализирован полностью, не просто "процесс
   жив").
2. `apt install ./hranix-shield_0.1.0_amd64.deb` → `postinst` отработал: пользователь создан,
   `Created symlink .../hranix-shield.service`.
3. `systemctl status hranix-shield.service` → **`Active: active (running)`**, реальный PID,
   `journalctl -u hranix-shield.service` показывает полную цепочку: применение миграций Alembic →
   `Uvicorn running on http://127.0.0.1:8080` → `GET /health` 200 (внутренний поллинг
   `launcher.py`'s `_wait_for_health`).
4. `ps -o user,cmd -C hranix-shield` → процесс реально работает **от `hranix-shield`, не root**
   (`id hranix-shield` → `uid=999(hranix-shield) gid=999(hranix-shield)`).
5. `curl http://127.0.0.1:8080/health` (изнутри контейнера, curl доставлен туда только для теста —
   не входит в сам пакет) → `{"status":"ok"}`.
6. Проверка входа под bootstrap-админом: остановлен сервис, от имени `hranix-shield` записан
   `config.env` (`BOOTSTRAP_ADMIN_USERNAME=admin`, `BOOTSTRAP_ADMIN_PASSWORD=...`) по пути, который
   реально зарезолвил `platformdirs` на Linux с `HOME=/var/lib/hranix-shield` —
   `/var/lib/hranix-shield/.local/share/Hranix Shield/config.env` — сервис перезапущен,
   `POST /auth/login` с этими учётными данными → реальный JWT в ответе. Подтверждает не только
   «сервис жив», а весь путь A-19 (platformdirs) + A-1 (auth) внутри пакованного Linux-сервиса.
7. **Graceful shutdown (архитекторское решение #3) подтверждён живьём:** `systemctl stop
   hranix-shield.service` завершился за **0.355s** с `code=exited, status=0/SUCCESS`,
   `Deactivated successfully` — журнал показывает точную цепочку `received SIGTERM` →
   uvicorn's `Shutting down` → `Application shutdown complete` → `service: stopped cleanly`. Ни
   разу не понадобился SIGKILL/`TimeoutStopSec` — обработчик в `hranix_shield_service.py`
   отработал ровно так, как спроектирован.
8. **`apt remove` (не purge):** `prerm remove` отключил+остановил юнит до удаления файлов
   (`systemctl is-enabled` после — "No such file", юнит-файл уже удалён dpkg); процесс сервиса не
   остался висеть orphan'ом (`ps aux | grep hranix-shield` — пусто); пользователь и
   `/var/lib/hranix-shield` **сохранены** (правильно — не purge).
9. **`apt purge`:** пользователь/группа `hranix-shield` удалены (`getent passwd` — пусто);
   `/var/lib/hranix-shield` (данные) **сохранены на диске** (правильно, см. `postrm`'s
   комментарий — сознательно не удаляется даже при purge).

Все девять шагов выполнены на реальном, только что собранном пакете внутри контейнера, который
никогда прежде не видел этот проект — не на `python -m uvicorn` из исходников.

### 3. «Видит настоящий хост» — ЧЕСТНО НЕ ПОДТВЕРЖДЕНО (архитектурная граница, не недоработка)

Тестовый Docker-контейнер (даже с настоящим systemd как PID 1) — сам по себе не хост
пользователя: `platform.system()` внутри него по-прежнему видит контейнеризированное Linux-ядро
хоста Docker Desktop (тот же принцип, по которому Docker-развёртывание самого продукта никогда не
видит хост — см. план-спецификацию). Для проверки, что `os_firewall`/Osquery реально видят
физическую/виртуальную Linux-машину (не контейнер), нужна установка `.deb` на настоящую
Linux-машину или полноценную VM — недоступно в этой сессии. Не имитировалось и не заявлялось как
подтверждённое.

### 4. Regression-сьют — см. отчёт задачи (не файл README)

A-22 не трогает `server/app/`, `server/launcher.py` или `server/config.py` — только добавляет
`packaging/linux/*` и `.gitignore`'s запись для `deb-staging/`. Полный сьют
(`server/venv/bin/python -m pytest -q`) прогнан после всех изменений — результат зафиксирован в
отчёте задачи, не здесь.

## osquery включён в установку из коробки (A-24)

Консоли **«Сеть»** и **«Вирусная активность»** (osquery-часть) теперь работают сразу после
установки `.deb` — конечному пользователю НЕ нужно самому добавлять официальный apt-репозиторий
osquery и ставить пакет вручную (`infra/security/osquery/README.md`'s инструкция остаётся
fallback-документацией для Docker/venv-режима разработки).

**Выбор: вшитый бинарник, а не `apt-get install` в `postinst`.** План-спецификация оставляла оба
варианта на усмотрение разработчика с честной оговоркой про trade-off — оба реально
рассмотрены:

- **Вшитый бинарник (выбрано):** `.deb` — полностью самодостаточная установка, не требует сети
  и не добавляет постороннего apt-репозитория/GPG-ключа на машину пользователя ни на этапе
  установки, ни когда-либо позже — тот же принцип «никогда не поднимать сетевую/привилегированную
  активность у уже работающего приложения», который этот проект уже применяет к
  `brew install --cask` на macOS (A-15, A-24). Цена — версия osquery фиксируется на момент сборки
  `.deb` (обновление требует пересборки), тот же trade-off, что уже принят для версий
  PyInstaller/rumps/infi.systray в этом же наборе README.
- **`apt-get install osquery` в `postinst` (рассмотрено, отклонено):** проще поддерживать
  актуальность версии (`apt upgrade` на машине пользователя обновил бы и osquery), но добавляет
  РЕАЛЬНУЮ сетевую зависимость на этапе установки и постоянно прописанный сторонний
  apt-репозиторий (`pkg.osquery.io`) — это расходится с локальностью/приватностью продукта
  (CLAUDE.md), которую весь смысл A-19…A-22 в том и заключается защитить, и добавило бы
  Linux-сборке единственной из трёх ОС постоянную внешнюю сетевую зависимость, которой ни macOS,
  ни Windows не имеют после A-24. Выбор в пользу вшитого бинарника сделан ради архитектурной
  однородности всех трёх ОС, а не потому что apt-путь плох сам по себе.

**Как это устроено:** `packaging/linux/vendor-osquery.sh` скачивает официальный `.deb` osquery
(amd64, https://github.com/osquery/osquery/releases — см. лицензии ниже для точной версии/
ссылки/sha256), извлекает его без установки в систему (`dpkg-deb -x`, внутри того же
`python:3.12-slim-bullseye`/`linux/amd64`-контейнера, что и `build-in-docker.sh` — не на голом
macOS-хосте, где `dpkg-deb` не установлен) и копирует реальный ELF-бинарник
(`opt/osquery/bin/osqueryd` — `usr/bin/osqueryi` в самом `.deb` тоже всего лишь символическая
ссылка на тот же файл, тот же паттерн, что и в macOS's `.pkg`, подтверждено эмпирически) под
именем `osqueryi` в `packaging/linux/vendor/osquery/` (не коммитится в git, см. `.gitignore` —
воспроизводимый скриптом бинарный артефакт). В отличие от macOS, ELF-бинарнику не нужна
переподпись, чтобы запускаться самостоятельно под новым именем — скрипт сам проверяет это,
реально запуская переименованную копию (`--version` + тестовый JSON-запрос) внутри того же
контейнера перед тем, как считать шаг успешным.

`hranix-shield.spec` подключает вшитый бинарник через `datas=[...]` (та же логика/комментарий,
что и в macOS-спеке) — Linux onedir-сборка не имеет `BUNDLE`-специфичного разделения
Frameworks/Resources, поэтому файл ложится прямо под `sys._MEIPASS/vendor/osquery/osqueryi`
(на практике — `<install root>/_internal/vendor/osquery/osqueryi`, PyInstaller 6.x кладёт
`datas`/`binaries` под собственный `_internal/`; неважно для кода — `sys._MEIPASS` разрешается
корректно в любом случае). `osquery.py`'s `_resolve_osqueryi()` (A-24) в упакованном режиме
сначала проверяет этот путь, и только если бинарника там нет — падает обратно на `osqueryi` через
системный `PATH`, ровно как раньше.

**Живая проверка (2026-07-18) — честная граница тестового контейнера, тот же принцип, что и в
остальной части этого README:** собранный `.deb` (с вшитым osquery) установлен внутри чистого
`hranix-systemd-test`-контейнера (см. выше), сервис реально запущен под пользователем
`hranix-shield`. `GET /security/consoles/network` и `GET /security/consoles/av` внутри контейнера
оба вернули `connector`/`connectors.osquery` со `status: "ok"` (с реальными, но
контейнер-масштабными данными — например, `process_count` в единицы, а не тысячи, потому что
контейнер видит только свой собственный PID-namespace). Прямой запуск вшитого бинарника от имени
того же непривилегированного пользователя (`docker exec --user hranix-shield ... osqueryi
--version`) тоже подтверждён. Это доказывает, что вшитый бинарник реально работает внутри
установленного пакета — **не** доказывает видимость реального хоста конечного пользователя (тот
же архитектурный лимит раздела "«Видит настоящий хост»" выше).

## A-25: официальный агент Wazuh (GPLv2) — устанавливается через `postinst`

Тот же архитектурный разрыв, что решают A-20 (macOS)/A-21 (Windows): консоль «Журналы ОС» видела
только файлы Manager-контейнера (`infra/security/wazuh/docker-compose.yml`'s Decision #2), а не
реальный хост нативной установки. `debian/postinst`'s `configure`-шаг (см. этот файл) теперь
best-effort (сетевая ошибка не валит установку самого `hranix-shield` — обёрнуто `|| echo
WARNING`) добавляет официальный apt-репозиторий Wazuh (`packages.wazuh.com/4.x/apt`, GPG-ключ
проверен) и ставит `wazuh-agent` (та же версия `4.14.6`, что и Manager-образ/macOS-агент — Wazuh
сам рекомендует совпадение версий), настраивая его через `WAZUH_MANAGER=127.0.0.1` (переопределяемо
`HRANIX_WAZUH_MANAGER=...`; порты 1514/1515 теперь опубликованы на `127.0.0.1` —
`infra/security/wazuh/docker-compose.yml`'s Decision #3, 2026-07-18). Затем правит СОБСТВЕННЫЙ
`ossec.conf` агента (`/var/ossec/etc/ossec.conf` — НЕ manager'а) через `sed`, направляя
`<syscheck><directories>` на реальный platformdirs-каталог данных этой установки
(`/var/lib/hranix-shield/.local/share/Hranix Shield`/`.../.local/state/Hranix Shield/log` — те же
пути, что подтверждены живьём в разделе "systemd" выше). `HRANIX_SKIP_WAZUH_AGENT=1` — escape
hatch для оператора, не желающего ставить эту системную службу вообще.

**Не добавлено в `debian/control`'s `Depends:`** намеренно: жёсткая apt-зависимость требовала бы,
чтобы Wazuh-репозиторий уже был настроен на машине ДО `apt install ./hranix-shield_*.deb` — нельзя
рассчитывать на это на чистой машине, поэтому репозиторий добавляется прямо в `postinst`.

**Реально проверено живьём в этой сессии** (не на этом README-файле, воспроизведено заново, не
пересказано из более раннего теста): тот же тестовый контейнер с настоящим systemd
(`test/Dockerfile.systemd`), что и раздел "2. «Ставится и работает»" выше — именно ЭТОТ блок кода
`postinst` (извлечён и прогнан как есть) реально добавил apt-репозиторий, поставил `wazuh-agent`,
включил systemd-юнит `wazuh-agent.service` (`Active: active (running)`), энролился против настоящего
Wazuh Manager (`hranix-wazuh-manager`) с новым agent id (не `"000"`), и FIM реально сработал на
файле внутри симулированного platformdirs-каталога — точные команды/вывод в отчёте задачи A-25.
Честная граница: контейнер — не «настоящий хост» пользователя (тот же архитектурный лимит, что во
всём разделе "3." выше) — это подтверждает МЕХАНИЗМ, не видимость реального хоста.

## Известные ограничения

- Собран и проверен только для `amd64` — `arm64`-сборка (например для Raspberry Pi/Linux-хостов
  на Apple Silicon-эквивалентной архитектуре) не производилась. Вшитый `osqueryi` (A-24) тоже
  скачан только в amd64-варианте — то же ограничение распространяется и на него.
- AppImage — опционально по плану, не сделан (не в DoD, время ушло на `.deb`+systemd-проверку).
- Код-подпись/GPG-подпись `.deb`-репозитория не делались (не в скоупе этой задачи, как и на
  macOS/A-20 не делались code signing/notarization).
- `Architecture: amd64` в `debian/control` зафиксирован вручную (не читается из окружения сборки) —
  если когда-нибудь понадобится arm64-вариант, оба скрипта и `debian/control` нужно обновить
  синхронно (задокументировано, не автоматизировано в этой задаче).

## Лицензии (сверено по первоисточникам, не по памяти, 2026-07-17)

| Инструмент/зависимость | Версия | Лицензия | Где сверено |
|---|---|---|---|
| PyInstaller | 6.21.0 | GPLv2-or-later **+ bootloader exception** (разрешает распространять собранный бинарник под любой лицензией) | уже зафиксировано в A-20 (`packaging/macos/README.md`, `server/requirements-packaged.txt`) — используется здесь тот же пин версии, не переоткрывалось |
| platformdirs | 4.10.0 | MIT | уже зафиксировано в A-19 |
| dpkg / dpkg-deb | 1.20.13 (внутри `python:3.12-slim-bullseye`) | GPL-2.0-or-later | используется **только как build-time инструмент упаковки** (внешний процесс, вызываемый скриптом сборки), не линкуется ни в собранный бинарник, ни в исходники продукта — тот же принцип лицензионного гейта CLAUDE.md, что уже применён к PyInstaller/restic (внешние GPL-инструменты как отдельные процессы, не зависимости кода) |
| systemd | 249.11 (Ubuntu 22.04, тестовый образ) / версия целевой системы в проде | LGPL-2.1-or-later (ядро) | используется только как системный менеджер сервисов **на машине пользователя** — не линкуется в проект, стандартный способ запуска демонов на Linux, тот же принцип, что применяется к любому системному компоненту ОС |
| **osquery** (вшитый `osqueryi`, A-24) | **5.23.1** | Dual-licensed **Apache-2.0 OR GPL-2.0-only** (`SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only`) — проект выбирает **Apache-2.0** | `https://github.com/osquery/osquery/blob/5.23.1/LICENSE` (сверено 2026-07-18); скачано с `https://github.com/osquery/osquery/releases/download/5.23.1/osquery_5.23.1-1.linux_amd64.deb`, `sha256:1431a9a6394657eba3cdd3476a462a6fe9721fc3664a70f23efcf7e37816787a` — точная версия/ссылка/сумма зафиксированы в `packaging/linux/vendor-osquery.sh` |
| Wazuh agent (`.deb`, apt) | 4.14.6 | GPLv2 (тот же класс, что уже принят для Wazuh Manager/ClamAV/macOS-Windows-агентов, CLAUDE.md's лицензионный гейт) | documentation.wazuh.com, сверено 2026-07-18 (A-25) — внешняя, отдельно работающая systemd-служба (`wazuh-agent.service`), никогда не линкуется в `hranix-shield`'s собственный AGPLv3+CLA код — `postinst` устанавливает её через официальный apt-репозиторий Wazuh, как есть |

`dpkg-deb`/`systemd` не распространяются ВМЕСТЕ с продуктом (не входят в `.deb`) — это
инструменты, уже присутствующие на любой Debian/Ubuntu-системе (systemd — по умолчанию с 15+ или
16.04+ Ubuntu), тот же принцип, по которому restic (внешний бинарник, вызываемый как subprocess)
не требует отдельной лицензионной оговорки о линковке.
