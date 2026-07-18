# Hranix Shield

**Бесплатная опенсорсная панель безопасности для вашего компьютера.** Локальная, приватная,
работает офлайн. Часть зонтичного бренда **Hranix** — платформы-ассистента для руководителей
(полный коммерческий продукт развивается отдельно и в этот репозиторий не входит).

Лицензия — **AGPLv3 + CLA** (см. [`LICENSE`](LICENSE), [`CLA.md`](CLA.md), [`SECURITY.md`](SECURITY.md)).

## Что это

Веб-панель (localhost), показывающая шесть консолей реальной защиты хоста:

| Консоль | Источник данных |
|---|---|
| Обнаружение вторжений | CrowdSec (MIT) |
| Резервные копии | restic |
| Периметр (фаервол/шифрование диска) | штатные средства ОС + CrowdSec-bouncer |
| Вирусная активность | osquery (Apache-2.0, телеметрия процессов) + ClamAV (GPLv2, сигнатурный сканер) |
| Сеть | osquery |
| Журналы ОС | Wazuh Manager, FIM (GPLv2) |

Никакого ИИ/аватара в этой части продукта — ядро и веб-панель работают полностью автономно и
автоматически. Бэкенд — только машиночитаемые коды ошибок в API, вся локализация (RU/EN) — на
стороне клиента.

## Лицензионная гигиена

Ядро платформы — только OSI-совместимое, коммерчески-свободное (MIT/Apache-2.0/BSD). GPL/AGPL
security-инструменты (ClamAV, Wazuh) подключены **только как отдельные сетевые Docker-сервисы**
(`infra/security/{clamav,wazuh}/`) — их код никогда не линкуется в процесс `server`
(коннекторы — `server/app/services/mcp/security_connectors/`, общаются по TCP-сокету/HTTP).

## Установка

**Docker (любая ОС с Docker Desktop/Engine):**
```bash
cp .env.example .env
# отредактируйте .env: задайте BOOTSTRAP_ADMIN_USERNAME/BOOTSTRAP_ADMIN_PASSWORD —
# без них панель поднимется, но войти будет некем (публичной регистрации нет)
docker compose up -d
open http://127.0.0.1:8080/panel/   # Linux: xdg-open, Windows: start
```
Простой путь, но консоли «Периметр»/«Сеть» внутри Docker-контейнера видят состояние самого
контейнера, а не реального хоста — архитектурное ограничение Docker, не баг.

**Нативные установщики (видят реальный хост):**
- **macOS** — `packaging/macos/` (PyInstaller `.app`/`.dmg`, иконка в строке меню).
- **Linux** — `packaging/linux/` (`.deb` + systemd system-service).
- **Windows** — `packaging/windows/` (PyInstaller + Inno Setup, иконка в трее); собирается
  через `.github/workflows/windows-build.yml` на `windows-latest` — сборка на macOS/Linux
  невозможна (PyInstaller не кросс-компилирует).

Подробности сборки/лицензий/честного статуса проверки каждой ОС — в README каждого каталога
`packaging/<os>/`.

**Разработка (venv):**
```bash
cp .env.example .env
cd server && python -m venv venv && venv/bin/pip install -r requirements.txt
venv/bin/python -m alembic upgrade head
venv/bin/uvicorn app.main:app --port 8080
```

## Структура

| Каталог | Назначение |
|---|---|
| `server/` | Платформенное ядро (FastAPI): `app/{routers,services,db,infra}`, `Dockerfile`, `launcher.py` |
| `packaging/` | Нативные установщики: `macos/`, `linux/`, `windows/` |
| `infra/security/` | Компаньон-сервисы безопасности (CrowdSec/ClamAV/Wazuh — отдельные Docker-контейнеры) |
| `docker-compose.yml` | Развёртывание Hranix Shield (`docker compose up`) |
| `.github/workflows/` | CI (сборка Windows-установщика на `windows-latest`) |

## Тесты
```bash
cd server && venv/bin/python -m pytest -q
```

## Вклад в проект

Открытая часть Hranix (эта панель + каркас модулей) распространяется под AGPLv3. Каждый
контрибьютор подписывает CLA (см. [`CLA.md`](CLA.md)) — ваш вклад остаётся доступным всем под
AGPLv3, при этом позволяя проекту иметь и отдельную коммерческую версию.

Уязвимости — см. [`SECURITY.md`](SECURITY.md) (не создавайте публичный Issue).
