#!/bin/sh
# Безопасная ЭМУЛЯЦИЯ вторжений для отладки консоли «Обнаружение вторжений».
#
# ВАЖНО, что этот скрипт НЕ делает: не отправляет ни одного реального сетевого
# пакета, не трогает никакой реальный хост (свой или чужой) — просто создаёт
# записи-решения (decisions) напрямую в CrowdSec через cscli, тем же способом,
# что уже задокументирован в README этого каталога («Живая проверка»). Реальная
# автоматическая детекция по логам в этом проекте сейчас не подключена вообще
# (см. docker-compose.yml в этом каталоге — acquis.yaml намеренно смотрит на
# несуществующий файл, host /var/log не bind-mount'ится, отдельное архитектурное
# решение A-11) — этот скрипт не эмулирует детекцию, он эмулирует РЕЗУЛЬТАТ
# детекции (уже принятое решение о бане), чтобы посмотреть, как панель его
# отображает/даёт разбанить.
#
# Используются ТОЛЬКО адреса из RFC 5737 (TEST-NET-1/2/3) — зарезервированы
# специально для документации/тестов, никогда не маршрутизируются в реальном
# интернете, никогда не принадлежат реальному хосту.
#
# Запуск:  sh infra/security/crowdsec/simulate_test_bans.sh
# Откат:   sh infra/security/crowdsec/simulate_test_bans.sh cleanup

set -e
COMPOSE="docker compose -f infra/security/crowdsec/docker-compose.yml exec crowdsec cscli"

TEST_IPS="192.0.2.10 192.0.2.11 198.51.100.20 203.0.113.30"

if [ "$1" = "cleanup" ]; then
  echo "Убираю тестовые баны..."
  for ip in $TEST_IPS; do
    $COMPOSE decisions delete --ip "$ip" 2>&1 || true
  done
  echo "Готово. Текущие решения:"
  $COMPOSE decisions list
  exit 0
fi

echo "Добавляю тестовые баны (RFC 5737, реального трафика нет)..."
$COMPOSE decisions add --ip 192.0.2.10   --duration 10m --reason "crowdsecurity/ssh-bf"
$COMPOSE decisions add --ip 192.0.2.11   --duration 10m --reason "crowdsecurity/ssh-bf"
$COMPOSE decisions add --ip 198.51.100.20 --duration 10m --reason "crowdsecurity/ssh-cve-2024-6387"
$COMPOSE decisions add --ip 203.0.113.30 --duration 10m --reason "crowdsecurity/ssh-slow-bf"

echo
echo "Готово. Проверьте консоль «Обнаружение вторжений» в панели — должны появиться"
echo "4 новые строки в «Последних попытках» с реальными кнопками «Разбанить»."
echo
echo "Текущие решения:"
$COMPOSE decisions list
echo
echo "Откат:  sh infra/security/crowdsec/simulate_test_bans.sh cleanup"
