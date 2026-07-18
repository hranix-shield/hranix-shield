#!/bin/sh
# Runs once per container start, before the app itself (see Dockerfile's
# ENTRYPOINT/CMD split): applies pending Alembic migrations, then execs
# whatever CMD was given (normally uvicorn) as PID 1, so it still receives
# SIGTERM directly for a clean shutdown — nothing stays running as a wrapper
# process after this point.
#
# `alembic upgrade head` is idempotent: a fresh DB gets created+migrated on
# first run, an already-current DB is a fast no-op on every restart after
# that. Runs from /app/server (this image's WORKDIR) so alembic.ini's
# relative `script_location = %(here)s/alembic` resolves the same way it
# does for the project's own `server/venv/bin/python -m alembic` convention.
set -e

echo "[entrypoint] applying database migrations..."
python -m alembic upgrade head
echo "[entrypoint] migrations up to date"

exec "$@"
