#!/usr/bin/env bash
# A-62: живой selftest [Code]-логики инсталлятора (генерация bootstrap-админа)
# на реальном Windows + Inno Setup — БЕЗ elevation и без UAC-кликов.
#
# Что делает: компилирует test/a62-admin-selftest.iss (per-user инсталлятор,
# инклюдящий РОВНО тот же installer-admin.iss, что и прод-installer.iss,
# только с scratch-каталогом данных {localappdata}\Hranix-A62-Selftest вместо
# {localappdata}\Hranix\Hranix Shield) и прогоняет 4 сценария:
#   1. чистый профиль          → config.env создан, пароль 20×[A-Za-z0-9],
#                                admin-credentials.txt содержит ту же пару;
#   2. апгрейд поверх          → config.env и admin-credentials.txt
#                                байт-в-байт не изменились;
#   3. пустые ключи + чужие    → заполнены пустые BOOTSTRAP_ADMIN_*,
#                                чужие ключи/комментарий целы, пароль новый;
#   4. username уже задан (CI) → config.env байт-в-байт не изменился,
#                                admin-credentials.txt не создаётся.
# После — деинсталляция и удаление scratch-каталога (в т.ч. по ошибке).
#
# Почему это не заменяет прод-приёмку: интерактивную финальную страницу и
# UAC-установку в Program Files этот прогон не трогает (PrivilegesRequired=lowest).
# Он проверяет саму генерирующую логику; прод-инсталлятор при этом также
# компилируется тем же ISCC (проверка сборки прод-конфигурации) — см. флаг
# --with-prod ниже. Запуск:  ./run-a62-selftest.sh [--with-prod]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGING_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

LOCALAPPDATA_UNIX="$(cygpath -u "${LOCALAPPDATA:-$HOME/AppData/Local}")"
SCRATCH="$LOCALAPPDATA_UNIX/Hranix-A62-Selftest"
APP_DIR="$LOCALAPPDATA_UNIX/Programs/HranixA62Selftest"
SELFTEST_EXE="$SCRIPT_DIR/dist/a62-selftest/hranix-a62-admin-selftest.exe"

ISCC=""
for candidate in \
  "$LOCALAPPDATA_UNIX/Programs/Inno Setup 6/ISCC.exe" \
  "/c/Program Files (x86)/Inno Setup 6/ISCC.exe" \
  "/c/Program Files/Inno Setup 6/ISCC.exe"; do
  if [ -f "$candidate" ]; then
    ISCC="$candidate"
    break
  fi
done
if [ -z "$ISCC" ]; then
  echo "FAIL: ISCC.exe not found (checked per-user and Program Files locations)" >&2
  exit 1
fi

CLEANED=0
cleanup() {
  if [ "$CLEANED" -eq 1 ]; then
    return
  fi
  CLEANED=1
  if [ -f "$APP_DIR/unins000.exe" ]; then
    "$APP_DIR/unins000.exe" //VERYSILENT //SUPPRESSMSGBOXES //NORESTART || true
    sleep 3
  fi
  rm -rf "$APP_DIR" "$SCRATCH"
}
trap cleanup EXIT

run_selftest_install() {
  # Двойные слэши — обязательны: Git Bash/MSYS молча конвертирует
  # одиночный /VERYSILENT в путь "C:/Program Files/Git/VERYSILENT"
  # (инсталлятор получает мусорные аргументы и виснет, показывая
  # интерактивный мастер). //VERYSILENT доходит до Inno как /VERYSILENT.
  "$SELFTEST_EXE" //VERYSILENT //SUPPRESSMSGBOXES //NORESTART >/dev/null
}

expect_env_value() {
  local file="$1" key="$2" pattern="$3" name="$4"
  local actual
  actual="$(tr -d '\r' < "$file" | grep -E "^${key}=" | tail -n 1 | cut -d= -f2-)"
  if ! printf '%s' "$actual" | grep -qE "^${pattern}$"; then
    echo "FAIL: $name: $key='${actual}' does not match /${pattern}/" >&2
    exit 1
  fi
}

echo "== A-62 selftest: compile =="
rm -rf "$SCRIPT_DIR/dist/a62-selftest"
mkdir -p "$SCRIPT_DIR/dist/a62-selftest"
"$ISCC" "$SCRIPT_DIR\\a62-admin-selftest.iss" >/dev/null
[ -f "$SELFTEST_EXE" ] || { echo "FAIL: selftest exe was not produced" >&2; exit 1; }
echo "compiled: $SELFTEST_EXE"

if [ "${1:-}" = "--with-prod" ]; then
  echo "== A-62 selftest: compile production installer.iss too =="
  "$ISCC" "$PACKAGING_DIR\\installer.iss" >/dev/null
  echo "compiled: $PACKAGING_DIR/dist/installer/hranix-shield-setup.exe"
fi

CONFIG="$SCRATCH/config.env"
CREDTXT="$SCRATCH/admin-credentials.txt"

echo "== Scenario 1: clean profile =="
rm -rf "$SCRATCH"
run_selftest_install
[ -f "$CONFIG" ] || { echo "FAIL: config.env was not created" >&2; exit 1; }
[ -f "$CREDTXT" ] || { echo "FAIL: admin-credentials.txt was not created" >&2; exit 1; }
expect_env_value "$CONFIG" "BOOTSTRAP_ADMIN_USERNAME" "admin" "scenario 1"
expect_env_value "$CONFIG" "BOOTSTRAP_ADMIN_PASSWORD" "[A-Za-z0-9]{20}" "scenario 1"
PASS1="$(tr -d '\r' < "$CONFIG" | grep -E '^BOOTSTRAP_ADMIN_PASSWORD=' | cut -d= -f2-)"
grep -q "BOOTSTRAP_ADMIN_PASSWORD=$PASS1" "$(cygpath -w "$CREDTXT")" \
  || { echo "FAIL: admin-credentials.txt password differs from config.env" >&2; exit 1; }
echo "ok: generated admin/password (password kept secret, 20 alnum chars)"

echo "== Scenario 2: reinstall over configured profile =="
H_CONFIG="$(sha256sum "$CONFIG")"
H_CREDTXT="$(sha256sum "$CREDTXT")"
run_selftest_install
[ "$(sha256sum "$CONFIG")" = "$H_CONFIG" ] \
  || { echo "FAIL: config.env changed on reinstall (admin already configured)" >&2; exit 1; }
[ "$(sha256sum "$CREDTXT")" = "$H_CREDTXT" ] \
  || { echo "FAIL: admin-credentials.txt was rewritten on reinstall" >&2; exit 1; }
echo "ok: existing admin untouched, credentials file not rewritten"

echo "== Scenario 3: empty bootstrap keys + foreign keys =="
mkdir -p "$SCRATCH"
printf 'SERVER_PORT=8080\r\n# пользовательский комментарий\r\nBOOTSTRAP_ADMIN_USERNAME=\r\nBOOTSTRAP_ADMIN_PASSWORD=\r\n' > "$CONFIG"
rm -f "$CREDTXT"
run_selftest_install
expect_env_value "$CONFIG" "SERVER_PORT" "8080" "scenario 3"
grep -q '^# пользовательский комментарий' "$(cygpath -w "$CONFIG")" \
  || { echo "FAIL: foreign comment was lost" >&2; exit 1; }
expect_env_value "$CONFIG" "BOOTSTRAP_ADMIN_USERNAME" "admin" "scenario 3"
expect_env_value "$CONFIG" "BOOTSTRAP_ADMIN_PASSWORD" "[A-Za-z0-9]{20}" "scenario 3"
PASS3="$(tr -d '\r' < "$CONFIG" | grep -E '^BOOTSTRAP_ADMIN_PASSWORD=' | cut -d= -f2-)"
[ "$PASS3" != "$PASS1" ] || { echo "FAIL: password reuse across installs" >&2; exit 1; }
[ -f "$CREDTXT" ] \
  || { echo "FAIL: silent install generated a new password but wrote no admin-credentials.txt" >&2; exit 1; }
grep -q "BOOTSTRAP_ADMIN_PASSWORD=$PASS3" "$(cygpath -w "$CREDTXT")" \
  || { echo "FAIL: admin-credentials.txt password differs from config.env (scenario 3)" >&2; exit 1; }
echo "ok: empty keys filled, foreign keys/comment intact, fresh password + fresh credentials file"

echo "== Scenario 4: username already set (CI windows-build.yml path) =="
printf 'SERVER_PORT=8080\nBOOTSTRAP_ADMIN_USERNAME=ci-smoke-admin\nBOOTSTRAP_ADMIN_PASSWORD=ci-smoke-test-only\n' > "$CONFIG"
rm -f "$CREDTXT"
H_CONFIG="$(sha256sum "$CONFIG")"
run_selftest_install
[ "$(sha256sum "$CONFIG")" = "$H_CONFIG" ] \
  || { echo "FAIL: preconfigured config.env was modified by the installer" >&2; exit 1; }
[ ! -f "$CREDTXT" ] \
  || { echo "FAIL: admin-credentials.txt created despite preconfigured admin" >&2; exit 1; }
echo "ok: preconfigured config.env untouched, no credentials file"

echo "== A-62 selftest: PASS (4 scenarios) =="
