# ClamAV / clamd (A-17)

Компаньон «Вирусной активности»: официальный `clamav/clamav-debian` как
отдельный сетевой сервис (GPLv2 — только по TCP-протоколу clamd, ничего не
линкуется в наш процесс, см. лицензионный гейт `CLAUDE.md`). Комментарии в
`docker-compose.yml` — часть контракта (политика freshclam, безопасность
сети, тома): не редактировать их одновременно с конфигурацией, не обновив
этот README.

```bash
docker compose -f infra/security/clamav/docker-compose.yml up -d
# затем в .env: CLAMAV_ENABLED=True (CLAMAV_HOST=127.0.0.1 / CLAMAV_PORT=3310 уже совпадают)
```

## Лимит размера потока — StreamMaxLength (A-63-4)

clamd принимает `INSTREAM`-потоки не больше `StreamMaxLength` (по умолчанию
**25 MiB**); при превышении он отвечает `INSTREAM size limit exceeded.
ERROR` и обрывает соединение, не дочитав выгрузку. Клиентский коннектор
(`server/app/services/mcp/security_connectors/clamav.py`) заранее
пропускает файлы больше этого же лимита (`_MAX_STREAM_BYTES`), поэтому в
штатном режиме очередь до clamd они не доходят; начиная с A-63-4 и такой
ответ clamd больше не теряется — он распознаётся и попадает в логи скана
как честная причина (`…: INSTREAM size limit exceeded. ERROR`), а не как
пустая «clamd INSTREAM failed: ».

Если нужно сканировать файлы БОЛЬШЕ 25 MiB (например, крупные архивы в
Downloads), поднимите лимит на стороне clamd. Образ `clamav/clamav-debian`
генерирует `/etc/clamav/clamd.conf` при старте, поэтому самый надёжный
способ — переопределить две строки конфига командой внутрь запущенного
контейнера и перезапустить его:

```bash
cd infra/security/clamav
docker compose exec clamav sh -c \
  "sed -i 's/^#?\\?MaxFileSize .*/MaxFileSize 200M/; s/^#?\\?StreamMaxLength .*/StreamMaxLength 200M/' /etc/clamav/clamd.conf"
docker compose restart clamav
```

Учтите: `docker compose down` + пересоздание контейнера вернёт стоковый
конфиг (том `clamav-db` хранит только базы сигнатур, не конфиг) — при
смене лимита зафиксируйте его и в своём развёртывании (например,
собственным override-файлом compose с монтированием готового
`clamd.conf`). Лимит клиента (`_MAX_STREAM_BYTES` в clamav.py) при
поднятии серверного лимита поднимите тем же значением — иначе большие
файлы по-прежнему будут молча пропускаться до отправки.
