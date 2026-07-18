# Hranix Shield — server image.
#
# Cross-platform by construction: this is a Linux container, so it runs
# identically under Docker Desktop (Windows/macOS) or Docker Engine (Linux) —
# "any OS" here means "any OS that can run Docker", not that this Dockerfile
# does anything OS-specific.
#
# Build context is the REPO ROOT (see ../docker-compose.yml build.context),
# not server/ — app/config.py resolves REPO_ROOT as 3 parents above itself
# (server/app/config.py -> server/app -> server/ -> REPO_ROOT), so this image
# reproduces that same server/ nesting under /app, keeping database_url,
# log_file, backup_dir, JWT_SECRET_FILE and RESTIC_PASSWORD_FILE resolution
# (all REPO_ROOT-relative, see app/config.py) correct with zero code changes.

# ---- Stage 1: builder — compile wheels, nothing else ships from here ----
FROM python:3.12-slim AS builder

# gcc/build-essential: passlib[bcrypt] and a couple of other deps in
# requirements.txt need a C compiler for their native extensions.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY server/requirements.txt .

# CPU-only torch/torchaudio explicitly: requirements.txt lists them for a
# future phase (ASR — Фаза 3+, §4.2 плана), nothing in Фаза 0 imports them
# (A-7's InferenceBackend is not wired into any router). Left to pip's
# default resolution on Linux, `torch` pulls multi-GB CUDA wheels for a GPU
# this container will never use — the extra index below makes pip prefer the
# small CPU-only build instead, without changing requirements.txt itself or
# what version gets installed anywhere else (venv/tests keep using whatever
# PyPI resolves there; this is a Docker-image-only optimization).
RUN pip install --no-cache-dir --upgrade pip && \
    pip wheel --no-cache-dir --wheel-dir /wheels \
        --extra-index-url https://download.pytorch.org/whl/cpu \
        -r requirements.txt

# ---- Stage 2: runtime — slim, non-root, only what's needed to run ----
FROM python:3.12-slim AS runtime

# curl: HEALTHCHECK below. restic (BSD-2, see CLAUDE.md's licence gate — an
# external tool invoked as a subprocess, never linked into this process, same
# principle as CrowdSec in infra/security/crowdsec/): A-12's backup service
# shells out to a plain `restic` on PATH (see
# app/services/backup/restic_client.py) — installing it here is what makes
# BACKUP_ENABLED=true actually work out of the box instead of failing at the
# first snapshot attempt.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        restic \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --upgrade pip

COPY server/requirements.txt /tmp/requirements.txt
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels -r /tmp/requirements.txt \
    && rm -rf /wheels /tmp/requirements.txt

# Fixed UID/GID (not just `useradd -m`) so a named volume's ownership,
# chowned below at build time, matches this exact user every rebuild —
# Docker seeds a fresh named volume from the image directory's contents
# *including ownership* the first time it's mounted, which is what makes
# data/, logs/, infra/backups/ writable by `hranix` with zero entrypoint-time
# chown/gosu dance (see docker-compose.yml's volumes for the corresponding
# named-volume mounts).
RUN groupadd --gid 1000 hranix && \
    useradd --uid 1000 --gid hranix --create-home --shell /usr/sbin/nologin hranix

# Mirror the repo's server/ nesting under /app so REPO_ROOT resolves to /app
# (see the top-of-file comment) — WORKDIR is /app/server, matching how
# alembic.ini's `script_location = %(here)s/alembic` and this project's own
# `server/venv/bin/python -m pytest` convention already assume server/ as cwd.
WORKDIR /app/server
COPY --chown=hranix:hranix server/ .
COPY --chown=hranix:hranix server/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# REPO_ROOT-relative runtime directories (config.py: data/, logs/,
# infra/backups/ — same convention as the non-Docker deployment). Created and
# chowned at build time so the ownership-seeding behavior above applies to
# all three; docker-compose.yml mounts a named volume at each so they persist
# across `docker compose down`/`up` (JWT secret, restic password, the SQLite
# DB itself, and the restic repository all live under these).
RUN mkdir -p /app/data /app/logs /app/infra/backups && \
    chown -R hranix:hranix /app/data /app/logs /app/infra/backups

USER hranix

EXPOSE 8080

# Uses the app's own /health endpoint (A-1) — matches the same "is the
# process actually serving requests" bar the architect used for live
# verification throughout Фаза 0, not just "is the container running".
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl --fail --silent http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
