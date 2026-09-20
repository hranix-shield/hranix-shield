"""A-30: `services/security_console_export.py` — the universal CSV/JSON
serialization mechanism shared by the `logs` and `network` consoles'
"Экспорт журнала" action (see `routers/security_console.py`'s
`/consoles/export` endpoint). Pure functions, no FastAPI/DB involved — the
router-level wiring is covered separately in
tests/integration/test_security_console_export.py.
"""

import csv
import io

import pytest

from app.services.security_console_export import (
    export_filename,
    export_rows,
    rows_to_csv,
    rows_to_json,
)


@pytest.mark.unit
def test_rows_to_csv_empty_list_is_an_empty_string():
    assert rows_to_csv([]) == ""


@pytest.mark.unit
def test_rows_to_csv_round_trips_through_the_stdlib_csv_reader():
    rows = [
        {
            "timestamp": "2026-07-16T14:19:56+00:00",
            "level": "notice",
            "source": "wazuh_fim",
            "file": "/monitored/logs/assistant.log",
            "description": "Изменение файла под контролем целостности: /monitored/logs/assistant.log",
        },
        {
            "timestamp": "2026-07-16T15:00:00+00:00",
            "level": "notice",
            "source": "wazuh_fim",
            "file": "/monitored/data/seed.txt",
            "description": "Изменение, содержащее запятую, и \"кавычки\"",
        },
    ]

    csv_text = rows_to_csv(rows)
    parsed = list(csv.DictReader(io.StringIO(csv_text)))

    assert len(parsed) == 2
    assert parsed[0]["file"] == "/monitored/logs/assistant.log"
    assert parsed[1]["description"] == 'Изменение, содержащее запятую, и "кавычки"'


@pytest.mark.unit
def test_rows_to_csv_none_values_become_blank_not_the_literal_text_none():
    rows = [{"process": None, "pid": 123, "state": "ESTABLISHED"}]

    parsed = list(csv.DictReader(io.StringIO(rows_to_csv(rows))))

    assert parsed[0]["process"] == ""
    assert parsed[0]["pid"] == "123"


@pytest.mark.unit
def test_rows_to_csv_column_order_is_first_seen_union_of_keys():
    rows = [{"a": 1, "b": 2}, {"b": 3, "c": 4}]

    csv_text = rows_to_csv(rows)

    header = csv_text.splitlines()[0]
    assert header == "a,b,c"


@pytest.mark.unit
def test_rows_to_json_is_valid_json_and_preserves_cyrillic_readably():
    rows = [{"file": "/x", "description": "Русский текст"}]

    json_text = rows_to_json(rows)

    assert "Русский текст" in json_text  # ensure_ascii=False, not \uXXXX-escaped
    import json as _json

    assert _json.loads(json_text) == rows


@pytest.mark.unit
def test_export_rows_csv_returns_csv_media_type():
    content, media_type = export_rows([{"a": 1}], fmt="csv")

    assert media_type == "text/csv"
    assert "a" in content


@pytest.mark.unit
def test_export_rows_json_returns_json_media_type():
    content, media_type = export_rows([{"a": 1}], fmt="json")

    assert media_type == "application/json"
    assert '"a"' in content


@pytest.mark.unit
def test_export_filename_is_sanitized_and_ends_with_the_format_extension():
    filename = export_filename("logs", fmt="csv")

    assert filename.startswith("hranix-shield-logs-export-")
    assert filename.endswith(".csv")


@pytest.mark.unit
def test_export_filename_sanitizes_unsafe_characters_in_console_id():
    filename = export_filename('logs"; rm -rf /', fmt="json")

    assert '"' not in filename
    assert ";" not in filename
    assert " " not in filename
    assert filename.endswith(".json")
