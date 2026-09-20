"""A-26: the metric-history mechanism this project never had (see
sampler.py's module docstring for the full "why" — every console's
`chart.values` used to be a hardcoded `[]`).

Public surface re-exported here for callers (router, app_factory, tests):
  - chart: the read side — `chart_values_7d()`, last-7-days bucketing.
  - sampler: the write side — one round of connector reads -> MetricSample
    rows, plus the periodic background scheduler.
"""

from __future__ import annotations

from app.services.metrics.chart import CHART_DAYS, MIN_HISTORY_DAYS, chart_values_7d
from app.services.metrics.sampler import (
    AV_CONSOLE_ID,
    IDS_CONSOLE_ID,
    LOGS_CONSOLE_ID,
    METRIC_ACTIVE_BANS_COMMUNITY,
    METRIC_ACTIVE_BANS_LOCAL,
    METRIC_ACTIVE_CONNECTIONS,
    METRIC_EVENTS_24H,
    METRIC_QUARANTINE_COUNT,
    NETWORK_CONSOLE_ID,
    PERIMETER_CONSOLE_ID,
    MetricsSampleScheduler,
    collect_current_metric_samples,
    create_default_metrics_scheduler,
    run_metrics_sample_sweep,
)

__all__ = [
    "CHART_DAYS",
    "MIN_HISTORY_DAYS",
    "chart_values_7d",
    "AV_CONSOLE_ID",
    "IDS_CONSOLE_ID",
    "LOGS_CONSOLE_ID",
    "METRIC_ACTIVE_BANS_COMMUNITY",
    "METRIC_ACTIVE_BANS_LOCAL",
    "METRIC_ACTIVE_CONNECTIONS",
    "METRIC_EVENTS_24H",
    "METRIC_QUARANTINE_COUNT",
    "NETWORK_CONSOLE_ID",
    "PERIMETER_CONSOLE_ID",
    "MetricsSampleScheduler",
    "collect_current_metric_samples",
    "create_default_metrics_scheduler",
    "run_metrics_sample_sweep",
]
