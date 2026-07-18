# osquery — установка (A-15)

Питает две консоли панели «Hranix Shield»: **«Сеть»** (список активных
соединений/прослушиваемых портов) и **«Вирусная активность»** (телеметрия
процессов, опционально — FIM/контроль целостности файлов).

## Почему не Docker

В отличие от CrowdSec (A-11) или будущего Wazuh (A-16), osquery по своей
природе читает состояние **самого хоста** — запущенные процессы, открытые
сокеты, файловую систему. Контейнеризация имела бы смысл только для
видимости хоста *изнутри* контейнера, что усложнило бы задачу без пользы
(нужны были бы privileged-контейнер/bind-mount `/proc`, `/dev` и т.п. —
прямое нарушение host-safety принципа проекта). Поэтому `osqueryd`/`osqueryi`
устанавливаются **как обычный процесс прямо на хост**, а коннектор
(`server/app/services/mcp/security_connectors/osquery.py`) обращается к нему
только через subprocess — никогда не линкуется в процесс `server` (тот же
лицензионный/архитектурный принцип §0.1, что и у остальных коннекторов
стека безопасности).

## Что реально нужно этому коннектору

Коннектор использует **пакетные запросы `osqueryi --json "SELECT ..."`**
(подробное обоснование выбора между этим и Thrift-сокетом — в docstring
`osquery.py`). Это значит:

- Нужен только бинарник **`osqueryi`** на `PATH` — постоянно запущенный
  демон `osqueryd` **не обязателен** для этого коннектора (каждый опрос —
  самостоятельный короткоживущий процесс).
- Для FIM (`file_events`, опционально) — see «FIM» ниже: она требует, чтобы
  `osqueryd` (демон, не `osqueryi`) был запущен отдельно, с
  `--enable_file_events` и настроенными `file_paths` в конфиге.

## Установка по ОС

Установлены три разных пути — не скрываем, что они отличаются:

### macOS

```sh
brew install --cask osquery
```

Ставит `osqueryd`/`osqueryi`/`osqueryctl` через официальный `.pkg`-инсталлятор
Homebrew cask. **Важно:** этот `.pkg` запускается через `sudo` и требует
интерактивного ввода пароля — `brew install --cask osquery` **не
отрабатывает в неинтерактивной среде** (CI, автоматизированный агент без
TTY): попытка установки при разработке этой задачи именно так и упала —
`sudo: a terminal is required to read the password; ... sudo: a password is
required`. В интерактивном терминале разработчика это не проблема (просто
запросит пароль), но для CI-пайплайна нужен отдельный неинтерактивный
механизм установки (например, `installer -pkg ... -target /` с
предварительно поднятыми правами в самом раннере) — не решено этой задачей,
зафиксировано как открытый вопрос для будущей CI-обвязки.

После установки бинарники обычно оказываются в `/usr/local/bin/osqueryi` —
добавьте эту директорию в `PATH`, если её там нет.

### Linux (Debian/Ubuntu — официальный репозиторий)

```sh
export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys "$OSQUERY_KEY"
sudo add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'
sudo apt-get update
sudo apt-get install osquery
```

(RHEL/CentOS/Fedora — аналогичный официальный yum-репозиторий, см.
https://www.osquery.io/downloads/official/). Ставит `osqueryd`/`osqueryi` в
`/usr/bin/`. Требует `sudo` только на этапе установки пакета, сами вызовы
`osqueryi` из этого коннектора работают от обычного пользователя.

### Windows

Официальный MSI-инсталлятор с https://www.osquery.io/downloads/official/ —
ставит `osqueryd.exe`/`osqueryi.exe` в
`C:\Program Files\osquery\`. Требует запуска инсталлятора с правами
администратора (стандартный Windows UAC-запрос, не заранее настроенный
`sudo`-эквивалент). **Не проверено вживую** при разработке этой задачи
(машина разработки — macOS, см. отчёт о задаче A-15) — этот путь описан по
официальной документации osquery, не подтверждён эмпирически, тот же
дисциплинированный disclaimer, что и у Windows-путей коннекторов A-18
(`os_firewall.py`/`os_disk_encryption.py`).

## Права доступа

На одиночном ноутбуке одного пользователя (целевой сценарий продукта, см.
CLAUDE.md: граница открыто/закрыто — «по локальности/однопользовательности»)
`osqueryi`, запущенный обычным пользователем, как правило видит собственные
процессы/сокеты. Видимость сокетов/процессов **других** пользователей на
некоторых платформах требует повышенных прав — коннектор никогда не
запрашивает их сам (не поднимает весь процесс `server` до root/administrator,
тот же принцип, что и у A-18), а честно репортует `permission_denied`, если
конкретный запрос отказал по правам.

## FIM (`file_events`) — опционально, обычно выключено по умолчанию

Таблица `file_events` **всегда присутствует** в схеме osquery, но остаётся
пустой до тех пор, пока `osqueryd` не запущен с `--enable_file_events` и
списком отслеживаемых путей (`file_paths` в конфиге демона,
`/etc/osquery/osquery.conf` на Linux/macOS,
`C:\Program Files\osquery\osquery.conf` на Windows) — см. официальную
документацию: https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/.
Коннектор сам проверяет флаг `enable_file_events` через таблицу
`osquery_flags` перед тем, как доверять `file_events`, и честно возвращает
`file_events.status: "not_configured"` для этой конкретной метрики, если FIM
не включён — не роняя весь коннектор (остальная телеметрия — процессы,
сетевые сокеты — продолжает работать независимо).

Пример минимального фрагмента `osquery.conf` для включения FIM по
домашней директории пользователя (пример, не готовая продовая конфигурация):

```json
{
  "options": {
    "enable_file_events": "true"
  },
  "file_paths": {
    "home": ["/Users/%/Documents/%%"]
  }
}
```

## Живая проверка

```sh
osqueryi --json "SELECT pid, port, protocol, address FROM listening_ports LIMIT 5;"
osqueryi --json "SELECT pid, local_port, remote_address, remote_port, state FROM process_open_sockets WHERE remote_port > 0 LIMIT 5;"
osqueryi --json "SELECT count(*) AS process_count FROM processes;"
```

Сравните вывод с ответом `GET /security/consoles/network` /
`GET /security/consoles/av` панели (см. `server/tests/integration/test_osquery_live.py`,
маркер `osquery_live`, самопропускается, если `osqueryi` не установлен).
