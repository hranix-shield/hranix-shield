"""Post-merge user request (2026-08-02): the real, DB-persisted daily
full-scan schedule for `av` — replaces the old hardcoded, never-enforced
`scan_schedule` string (see `AvSettings`'s own docstring in
app/db/models.py).

Public surface re-exported here (router, app_factory, tests):
  - settings: the DB read/write side (`get_av_settings`/`update_av_settings`).
  - scheduler: the background task that actually fires a full scan.
  - wiring: `create_default_av_scan_scheduler`, wired to real Settings/DB.
"""

from app.services.av.scheduler import AvScanScheduler
from app.services.av.settings import (
    AvScheduleSettings,
    get_av_settings,
    update_av_settings,
)
from app.services.av.wiring import create_default_av_scan_scheduler

__all__ = [
    "AvScanScheduler",
    "AvScheduleSettings",
    "create_default_av_scan_scheduler",
    "get_av_settings",
    "update_av_settings",
]
