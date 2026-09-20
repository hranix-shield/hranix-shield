# Contributing / Руководство по разработке

Thanks for contributing to **Hranix Shield**! This file covers the environment and
typical commands; the product principles live in the
[README](README.md) (honesty-by-design, privacy, licensing).

Спасибо за вклад в **Hranix Shield**! Здесь — окружение и типовые команды; продуктовые
принципы — в [README](README.ru.md) (честность интерфейса, приватность, лицензии).

## Environment / Окружение

| Tool | Version | Notes |
|---|---|---|
| Python | **3.12** | pins (e.g. `pydantic==2.10.4`) have no wheels for newer versions |
| Docker Desktop | optional | needed only for the CrowdSec/ClamAV/Wazuh companions |
| restic | bundled in release builds; or install locally | backups console |

- Line endings are enforced by `.gitattributes` (`*.sh`/`*.py` are always LF).
- On Windows clones: `git config core.fileMode false` is acceptable (executable bits are
  fixed in the index).

## Commands / Команды

```bash
python -m venv .venv
.venv/Scripts/pip install -r server/requirements-packaged.txt   # lean runtime set
cd server && ../.venv/Scripts/python -m pytest -q               # full offline suite
../.venv/Scripts/python -m uvicorn app.main:app --port 8080     # run the panel
```

- The suite is fully offline: live-integration markers (`crowdsec_live`, `clamav_live`,
  `wazuh_live`, `osquery_live`, `crowdsec_write_live`) self-skip without the companion
  services.
- CI runs the same suite on every push/PR (see `.github/workflows/`).

## Ground rules / Базовые правила

1. **Honesty by design.** Never fabricate values: an unknown metric is `null` (the UI shows
   an em dash), an unconfigured integration returns a machine-readable
   `not_configured` reason, a disabled button carries a tooltip explaining why.
2. **API contract:** the backend returns machine-readable error codes only
   (`{"error": "invalid_credentials"}`); all user-facing text is translated on the client
   (RU/EN).
3. **Least privilege:** the app never caches elevated rights; every privileged action goes
   through a visible OS prompt, and status reads (PowerShell CIM, structured data) must not
   parse localized text.
4. **License gate:** dependencies must be MIT/Apache-2.0/BSD/ISC/OFL. GPL/AGPL components
   run as separate services/containers, never linked into this codebase. Verify every new
   dependency's license from its actual metadata and record it in the PR.
5. **Commits:** one logical step per commit, imperative subject
   (`fix(backup): ...`, `feat(ids): ...`), tests green before you commit.

## Tests

- Layout: `server/tests/{unit,integration,regression,e2e}`; the regression suite grows
  monotonically — never delete older tests.
- Aim for ≥80% unit coverage of new code; add integration tests for every endpoint you
  touch.
- Anything non-trivial is also verified with a live run against a really started server.
