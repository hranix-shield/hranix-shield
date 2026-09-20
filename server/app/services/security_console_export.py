"""A-30: universal console-list export (CSV/JSON) — the "Экспорт журнала"
action on BOTH the `logs` and `network` consoles shares this ONE
serialization mechanism (see `routers/security_console.py`'s
`/consoles/export` endpoint), instead of each console growing its own
bespoke export code (the A-30 task brief's explicit "не дублируй логику"
requirement).

Deliberately generic over row shape: a console's list payload (`logs`'s
`entries`, `network`'s `connections`, and any future console list) is just
"a list of flat `dict[str, Any]` rows" from this module's point of view — it
never needs to know which console/connector produced them, or import
anything from security_connectors/.

No external tool involved — pure stdlib `csv`/`json`, exactly the "clean
client+server function, without an external tool" shape the A-30 task brief
asked for.
"""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Any, Literal

ExportFormat = Literal["csv", "json"]


def rows_to_csv(rows: list[dict[str, Any]]) -> str:
    """Serializes `rows` to CSV text. Column order is the union of every
    row's own keys, in first-seen order (not alphabetical) — for this
    project's homogeneous per-console rows (every `logs` entry has the same
    shape, every `network` connection has the same shape) this is simply
    "that row's own key order", but staying union-based (not just the first
    row's keys) is one honest step more robust if a future console's rows
    are ever heterogeneous.

    An empty `rows` list produces an empty string — an honest "nothing to
    export" rather than a header-only file implying columns that were never
    actually observed.
    """
    if not rows:
        return ""
    fieldnames: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row:
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        # `None` -> "" (not the literal text "None" `csv.writer` would
        # otherwise stringify it to) — a blank cell is the honest
        # spreadsheet-native way to say "no value here".
        writer.writerow({key: ("" if value is None else value) for key, value in row.items()})
    return buffer.getvalue()


def rows_to_json(rows: list[dict[str, Any]]) -> str:
    """Serializes `rows` to pretty-printed JSON text — `ensure_ascii=False`
    so Cyrillic text (e.g. a `logs` entry's `description` field) round-trips
    human-readably, not as `\\uXXXX` escapes."""
    return json.dumps(rows, ensure_ascii=False, indent=2)


def export_rows(rows: list[dict[str, Any]], *, fmt: ExportFormat) -> tuple[str, str]:
    """Returns `(content, media_type)` for `fmt` — the one place that maps a
    format name to both its serializer and its MIME type, so the router
    endpoint never has to know either detail."""
    if fmt == "json":
        return rows_to_json(rows), "application/json"
    return rows_to_csv(rows), "text/csv"


_UNSAFE_ID_CHARS = re.compile(r"[^a-zA-Z0-9_-]")


def export_filename(console_id: str, *, fmt: ExportFormat) -> str:
    """A stable, filesystem/header-safe download filename — `console_id`
    comes straight from the request body (see `ConsoleExportRequest`), so it
    is sanitized before being interpolated into a `Content-Disposition`
    header value, same defensive spirit as every other user-influenced value
    this project puts into a response header/path."""
    safe_id = _UNSAFE_ID_CHARS.sub("_", console_id) or "console"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"hranix-shield-{safe_id}-export-{timestamp}.{fmt}"
