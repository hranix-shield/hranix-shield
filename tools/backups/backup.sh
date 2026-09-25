#!/usr/bin/env bash
# AGPLv3+CLA. © Hranix — часть открытого каркаса (Фаза 0).
#
# Бэкапы проекта по требованию (правило CLAUDE.md «Git»: страховка перед
# рискованными git-операциями; push при этом — только по прямой просьбе
# пользователя). Паттерн перенесён из практики ISKIN AI (2026-09-20).
#
# Использование:
#   tools/backups/backup.sh          # архив проекта в /c/work/backups
# Переменные: BACKUP_DEST (куда класть, по умолчанию /c/work/backups).
#
# Результат: <DEST>/hranix-project-<ГГГГММДД-ЧЧММ>.tar.gz + .sha256.
#
# ЧТО ВХОДИТ / ИСКЛЮЧЕНО:
#   ВХОДИТ: рабочее дерево + .git (полная история), docs, prototypes.
#   ИСКЛЮЧЕНО (регенерируемое/секреты): data/ (БД + .jwt_secret +
#   .restic_password + локальный restic-репозиторий), logs/, server/venv/,
#   .pytest_cache, __pycache__, .env (секреты), models/,
#   packaging/*/build|dist|vendor, packaging/linux/deb-staging,
#   gui-test-screenshots/.
#
# Обновлено 2026-09-23 (ревью бэкапа: в архив 0034 попали build-venv и
# .env.bak-a60 с реальными секретами — вычищено, грязный архив удалён):
#   - build-venv/ (локальное окружение Windows-сборки) исключён явно;
#   - .env.bak-* (секретные бэкапы мерджа config) исключены явно;
#   - .claude/ (машинно-локальные настройки агента) исключены.

set -euo pipefail

verify_archive() {
  # Проверка после упаковки: не пуст, читается целиком, разумное число записей.
  local f="$1" min_entries="${2:-300}"
  [ -s "$f" ] || { echo "ОШИБКА: архив пуст: $f"; exit 1; }
  local n
  n=$(tar -tzf "$f" | wc -l)
  [ "$n" -ge "$min_entries" ] || { echo "ОШИБКА: в архиве $n записей (< $min_entries): $f"; exit 1; }
  echo "проверено: $n записей, $(du -h "$f" | cut -f1)"
}

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PARENT="$(dirname "$ROOT")"
PROJ="$(basename "$ROOT")"
DEST="${BACKUP_DEST:-/c/work/backups}"
STAMP="$(date +%Y%m%d-%H%M)"
mkdir -p "$DEST"

out="$DEST/hranix-project-$STAMP.tar.gz"
echo "=== проект: $out"
(cd "$PARENT" && tar -czf "$out" \
  --exclude="$PROJ/data" \
  --exclude="$PROJ/logs" \
  --exclude="$PROJ/server/venv" \
  --exclude="$PROJ/server/data" \
  --exclude="$PROJ/server/.pytest_cache" \
  --exclude="$PROJ/.env" \
  --exclude="$PROJ/.env.bak-*" \
  --exclude="$PROJ/.claude" \
  --exclude="$PROJ/build-venv" \
  --exclude="$PROJ/.venv" \
  --exclude='*.pyc' \
  --exclude='__pycache__' \
  --exclude='*.log' \
  --exclude="$PROJ/models" \
  --exclude="$PROJ/packaging/linux/build" \
  --exclude="$PROJ/packaging/linux/dist" \
  --exclude="$PROJ/packaging/linux/deb-staging" \
  --exclude="$PROJ/packaging/linux/vendor" \
  --exclude="$PROJ/packaging/macos/build" \
  --exclude="$PROJ/packaging/macos/dist" \
  --exclude="$PROJ/packaging/macos/vendor" \
  --exclude="$PROJ/packaging/windows/build" \
  --exclude="$PROJ/packaging/windows/dist" \
  --exclude="$PROJ/packaging/windows/vendor" \
  --exclude="$PROJ/gui-test-screenshots" \
  "$PROJ")
sha256sum "$out" > "$out.sha256"
verify_archive "$out" 500
echo "sha256: $(cut -d' ' -f1 "$out.sha256")"
echo "=== готово: $DEST"
