"""A-44: elevated docker-exec write of CrowdSec's allowlist ("Добавить в
белый список"/"Удалить") — fully offline: `elevated_run` AND `fetch_
allowlists` are both monkeypatched here (same "inject a fake transport"
technique test_crowdsec_scenario_thresholds.py already uses for A-43), so
none of this ever pops a real OS dialog or touches a real container/LAPI.

`_ALLOWLIST_ALREADY_EXISTS_TEXT`/the exact `cscli allowlists create`
already-exists wording below is a byte-for-byte match of this task's own
live investigation against the real `hranix-crowdsec` container (create,
add, remove, including the "add/remove an already-present/-absent value is
itself a silent RC=0 no-op" discovery) — see crowdsec.py's "A-44 addendum"
docstring section and this task's own report for the transcript.

Live-container coverage (the real DoD click-and-verify loop, including the
mandatory cleanup afterward) is this task's own report, not an automated
test — there is no way to pop a real Touch ID prompt from CI, same
disclosure as test_crowdsec_scenario_thresholds.py's own docstring.
"""

from __future__ import annotations

import pytest

import app.services.mcp.security_connectors.crowdsec as crowdsec_module
from app.services.mcp.security_connectors.crowdsec import (
    CrowdSecAllowlistError,
    add_to_allowlist,
    remove_from_allowlist,
)
from app.services.mcp.security_connectors.elevated import ElevatedRunResult


def _fake_elevated_run(result: ElevatedRunResult, *, captured: dict | None = None):
    async def _run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        if captured is not None:
            captured["command"] = command
            captured["reason_ru"] = reason_ru
            captured["reason_en"] = reason_en
        return result

    return _run


def _fake_fetch_allowlists(payload: dict, *, calls: list | None = None):
    async def _fetch(settings=None):
        if calls is not None:
            calls.append(settings)
        return payload

    return _fetch


def _allowlist_payload(*items: dict) -> dict:
    return {"connector": {"status": "ok"}, "allowlists": list(items)}


def _item(value: str, comment: str | None = "test") -> dict:
    return {
        "allowlist_name": "hranix_manual",
        "value": value,
        "comment": comment,
        "expiration": None,
        "created_at": "2026-07-25T08:00:00Z",
    }


@pytest.fixture(autouse=True)
def _fixed_docker_binary(monkeypatch: pytest.MonkeyPatch):
    """Same reasoning as test_crowdsec_scenario_thresholds.py's own fixture
    — assertions on the elevated command's shape must not depend on which
    `docker` binary this particular CI machine happens to have on PATH."""
    monkeypatch.setattr(crowdsec_module, "_resolve_docker_binary", lambda: "/usr/local/bin/docker")


# ---------------------------------------------------------------------------
# _validate_allowlist_value
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("value", ["203.0.113.5", "203.0.113.0/24", "2001:db8::1", "192.0.2.0/24"])
def test_validate_allowlist_value_accepts_real_ips_and_cidrs(value):
    crowdsec_module._validate_allowlist_value(value)  # must not raise


@pytest.mark.unit
@pytest.mark.parametrize("value", ["", "not-an-ip", "999.999.999.999", "203.0.113.5/99", "; rm -rf /"])
def test_validate_allowlist_value_rejects_garbage(value):
    with pytest.raises(CrowdSecAllowlistError) as exc_info:
        crowdsec_module._validate_allowlist_value(value)
    assert exc_info.value.reason == "invalid_value"


# ---------------------------------------------------------------------------
# _allowlist_values_match / _find_allowlist_item
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_allowlist_values_match_same_ip():
    assert crowdsec_module._allowlist_values_match("203.0.113.5", "203.0.113.5") is True


@pytest.mark.unit
def test_allowlist_values_match_falls_back_to_string_equality_on_unparsable_input():
    assert crowdsec_module._allowlist_values_match("not-an-ip", "not-an-ip") is True
    assert crowdsec_module._allowlist_values_match("not-an-ip", "also-not") is False


@pytest.mark.unit
def test_find_allowlist_item_locates_by_value():
    items = [_item("203.0.113.5"), _item("203.0.113.9")]
    found = crowdsec_module._find_allowlist_item(items, "203.0.113.9")
    assert found is not None
    assert found["value"] == "203.0.113.9"
    assert crowdsec_module._find_allowlist_item(items, "203.0.113.1") is None


# ---------------------------------------------------------------------------
# _build_allowlist_add_script / _build_allowlist_remove_script
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_build_allowlist_add_script_creates_then_adds_and_ignores_already_exists():
    script = crowdsec_module._build_allowlist_add_script("203.0.113.5", comment="a comment")

    assert "cscli allowlists create hranix_manual" in script
    assert "already exists" in script
    assert "cscli allowlists add hranix_manual 203.0.113.5 -d 'a comment'" in script
    assert "HRANIX_ALLOWLIST_ADD_OK" in script
    assert "HRANIX_ALLOWLIST_CREATE_FAILED" in script


@pytest.mark.unit
def test_build_allowlist_add_script_omits_dash_d_when_no_comment():
    script = crowdsec_module._build_allowlist_add_script("203.0.113.5", comment=None)

    assert "cscli allowlists add hranix_manual 203.0.113.5 2>&1" in script
    assert "-d" not in script.split("ADD_OUT=$(")[1].split(")")[0]


@pytest.mark.unit
def test_build_allowlist_add_script_shell_quotes_a_comment_with_special_characters():
    """A real operator comment can contain single quotes/semicolons — must
    be shell-quoted via shlex, never hand-interpolated (the same
    discipline A-43's `_build_write_scenario_script` already documents)."""
    script = crowdsec_module._build_allowlist_add_script("203.0.113.5", comment="it's a test; rm -rf /")

    # shlex.join's own single-quote escaping: 'it'"'"'s a test; rm -rf /'
    assert "'\"'\"'s a test; rm -rf /'" in script


@pytest.mark.unit
def test_build_allowlist_remove_script_has_no_already_exists_special_case():
    script = crowdsec_module._build_allowlist_remove_script("203.0.113.5")

    assert "cscli allowlists remove hranix_manual 203.0.113.5" in script
    assert "already exists" not in script
    assert "HRANIX_ALLOWLIST_REMOVE_OK" in script
    assert "HRANIX_ALLOWLIST_REMOVE_FAILED" in script


# ---------------------------------------------------------------------------
# _parse_allowlist_marker
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_parse_allowlist_marker_splits_marker_and_detail():
    marker, detail = crowdsec_module._parse_allowlist_marker(
        "HRANIX_ALLOWLIST_ADD_FAILED\nError: value rejected\nsecond line\n"
    )
    assert marker == "HRANIX_ALLOWLIST_ADD_FAILED"
    assert detail == "Error: value rejected\nsecond line"


@pytest.mark.unit
def test_parse_allowlist_marker_handles_marker_only_output():
    marker, detail = crowdsec_module._parse_allowlist_marker("HRANIX_ALLOWLIST_ADD_OK\n")
    assert marker == "HRANIX_ALLOWLIST_ADD_OK"
    assert detail == ""


# ---------------------------------------------------------------------------
# add_to_allowlist()
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_add_to_allowlist_validates_before_ever_calling_elevated_run(monkeypatch: pytest.MonkeyPatch):
    calls: list = []
    monkeypatch.setattr(crowdsec_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="ok")))
    monkeypatch.setattr(crowdsec_module, "fetch_allowlists", _fake_fetch_allowlists({}, calls=calls))

    with pytest.raises(CrowdSecAllowlistError) as exc_info:
        await add_to_allowlist("not-an-ip")

    assert exc_info.value.reason == "invalid_value"
    assert calls == []  # never even reached the readback, let alone elevated_run


@pytest.mark.unit
async def test_add_to_allowlist_ok_returns_the_readback_item(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}
    monkeypatch.setattr(
        crowdsec_module,
        "elevated_run",
        _fake_elevated_run(
            ElevatedRunResult(status="ok", stdout="HRANIX_ALLOWLIST_ADD_OK\nadded 1 values"), captured=captured
        ),
    )
    monkeypatch.setattr(
        crowdsec_module, "fetch_allowlists", _fake_fetch_allowlists(_allowlist_payload(_item("203.0.113.5")))
    )

    result = await add_to_allowlist("203.0.113.5", comment="a comment")

    assert result == {"status": "ok", "item": _item("203.0.113.5")}
    assert captured["command"][:3] == ["/usr/local/bin/docker", "exec", crowdsec_module.CROWDSEC_CONTAINER_NAME]
    assert "203.0.113.5" in captured["reason_ru"]


@pytest.mark.unit
async def test_add_to_allowlist_create_failed_raises_without_a_readback(monkeypatch: pytest.MonkeyPatch):
    calls: list = []
    monkeypatch.setattr(
        crowdsec_module,
        "elevated_run",
        _fake_elevated_run(
            ElevatedRunResult(status="ok", stdout="HRANIX_ALLOWLIST_CREATE_FAILED\nsome real cscli error")
        ),
    )
    monkeypatch.setattr(crowdsec_module, "fetch_allowlists", _fake_fetch_allowlists({}, calls=calls))

    with pytest.raises(CrowdSecAllowlistError) as exc_info:
        await add_to_allowlist("203.0.113.5")

    assert exc_info.value.reason == "allowlist_write_failed"
    assert calls == []  # nothing was written — no point reading back


@pytest.mark.unit
async def test_add_to_allowlist_add_failed_still_succeeds_if_the_readback_shows_it_present(
    monkeypatch: pytest.MonkeyPatch,
):
    """The DoD-shaped idempotency case, confirmed live: re-adding a value
    already in the allowlist is a no-op from the operator's point of view
    (the value ending up present IS the goal) — must report success, never
    a spurious error just because `cscli`'s own marker was `ADD_FAILED`."""
    monkeypatch.setattr(
        crowdsec_module,
        "elevated_run",
        _fake_elevated_run(
            ElevatedRunResult(
                status="ok", stdout="HRANIX_ALLOWLIST_ADD_FAILED\nvalue already in allowlist"
            )
        ),
    )
    monkeypatch.setattr(
        crowdsec_module, "fetch_allowlists", _fake_fetch_allowlists(_allowlist_payload(_item("203.0.113.5")))
    )

    result = await add_to_allowlist("203.0.113.5")

    assert result == {"status": "ok", "item": _item("203.0.113.5")}


@pytest.mark.unit
async def test_add_to_allowlist_readback_mismatch_never_reports_a_fake_success(
    monkeypatch: pytest.MonkeyPatch,
):
    """The DoD's own core discipline (same as A-43's write_scenario_
    threshold): a script that reports success is NOT proof the value is
    genuinely in the allowlist now — a fresh read that disagrees must
    raise, never be reported as success."""
    monkeypatch.setattr(
        crowdsec_module,
        "elevated_run",
        _fake_elevated_run(ElevatedRunResult(status="ok", stdout="HRANIX_ALLOWLIST_ADD_OK\nadded 1 values")),
    )
    monkeypatch.setattr(crowdsec_module, "fetch_allowlists", _fake_fetch_allowlists(_allowlist_payload()))

    with pytest.raises(CrowdSecAllowlistError) as exc_info:
        await add_to_allowlist("203.0.113.5")

    assert exc_info.value.reason == "allowlist_readback_mismatch"


@pytest.mark.unit
async def test_add_to_allowlist_readback_unavailable_is_distinct_from_mismatch(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        crowdsec_module,
        "elevated_run",
        _fake_elevated_run(ElevatedRunResult(status="ok", stdout="HRANIX_ALLOWLIST_ADD_OK\nadded 1 values")),
    )
    monkeypatch.setattr(
        crowdsec_module,
        "fetch_allowlists",
        _fake_fetch_allowlists({"connector": {"status": "unreachable"}, "allowlists": []}),
    )

    with pytest.raises(CrowdSecAllowlistError) as exc_info:
        await add_to_allowlist("203.0.113.5")

    assert exc_info.value.reason == "allowlist_readback_unavailable"


@pytest.mark.unit
async def test_add_to_allowlist_cancelled_raises_elevation_cancelled(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(crowdsec_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="cancelled")))

    with pytest.raises(CrowdSecAllowlistError) as exc_info:
        await add_to_allowlist("203.0.113.5")

    assert exc_info.value.reason == "elevation_cancelled"


@pytest.mark.unit
async def test_add_to_allowlist_failed_raises_elevation_failed(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        crowdsec_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="failed", stderr="boom"))
    )

    with pytest.raises(CrowdSecAllowlistError) as exc_info:
        await add_to_allowlist("203.0.113.5")

    assert exc_info.value.reason == "elevation_failed"


# ---------------------------------------------------------------------------
# remove_from_allowlist()
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_remove_from_allowlist_validates_before_ever_calling_elevated_run(
    monkeypatch: pytest.MonkeyPatch,
):
    calls: list = []
    monkeypatch.setattr(crowdsec_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="ok")))
    monkeypatch.setattr(crowdsec_module, "fetch_allowlists", _fake_fetch_allowlists({}, calls=calls))

    with pytest.raises(CrowdSecAllowlistError) as exc_info:
        await remove_from_allowlist("garbage")

    assert exc_info.value.reason == "invalid_value"
    assert calls == []


@pytest.mark.unit
async def test_remove_from_allowlist_ok_when_readback_confirms_absence(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        crowdsec_module,
        "elevated_run",
        _fake_elevated_run(ElevatedRunResult(status="ok", stdout="HRANIX_ALLOWLIST_REMOVE_OK\nremoved 1 values")),
    )
    monkeypatch.setattr(crowdsec_module, "fetch_allowlists", _fake_fetch_allowlists(_allowlist_payload()))

    result = await remove_from_allowlist("203.0.113.5")

    assert result == {"status": "ok", "value": "203.0.113.5"}


@pytest.mark.unit
async def test_remove_from_allowlist_failed_marker_still_succeeds_if_readback_confirms_absence(
    monkeypatch: pytest.MonkeyPatch,
):
    """Live-confirmed idempotency: removing an already-absent value is a
    silent RC=0 no-op in real `cscli` (see this file's own docstring) — but
    even if some future `cscli` version DID exit non-zero for that case,
    the readback (not the marker) must be what decides success, since the
    operator's actual goal — the value is not in the allowlist — already
    holds."""
    monkeypatch.setattr(
        crowdsec_module,
        "elevated_run",
        _fake_elevated_run(
            ElevatedRunResult(status="ok", stdout="HRANIX_ALLOWLIST_REMOVE_FAILED\nno value to remove")
        ),
    )
    monkeypatch.setattr(crowdsec_module, "fetch_allowlists", _fake_fetch_allowlists(_allowlist_payload()))

    result = await remove_from_allowlist("203.0.113.5")

    assert result == {"status": "ok", "value": "203.0.113.5"}


@pytest.mark.unit
async def test_remove_from_allowlist_readback_mismatch_never_reports_a_fake_success(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        crowdsec_module,
        "elevated_run",
        _fake_elevated_run(ElevatedRunResult(status="ok", stdout="HRANIX_ALLOWLIST_REMOVE_OK\nremoved 1 values")),
    )
    monkeypatch.setattr(
        crowdsec_module, "fetch_allowlists", _fake_fetch_allowlists(_allowlist_payload(_item("203.0.113.5")))
    )

    with pytest.raises(CrowdSecAllowlistError) as exc_info:
        await remove_from_allowlist("203.0.113.5")

    assert exc_info.value.reason == "allowlist_readback_mismatch"


@pytest.mark.unit
async def test_remove_from_allowlist_readback_unavailable_is_distinct_from_mismatch(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        crowdsec_module,
        "elevated_run",
        _fake_elevated_run(ElevatedRunResult(status="ok", stdout="HRANIX_ALLOWLIST_REMOVE_OK\nremoved 1 values")),
    )
    monkeypatch.setattr(
        crowdsec_module,
        "fetch_allowlists",
        _fake_fetch_allowlists({"connector": {"status": "unauthorized"}, "allowlists": []}),
    )

    with pytest.raises(CrowdSecAllowlistError) as exc_info:
        await remove_from_allowlist("203.0.113.5")

    assert exc_info.value.reason == "allowlist_readback_unavailable"


@pytest.mark.unit
async def test_remove_from_allowlist_cancelled_raises_elevation_cancelled(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(crowdsec_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="cancelled")))

    with pytest.raises(CrowdSecAllowlistError) as exc_info:
        await remove_from_allowlist("203.0.113.5")

    assert exc_info.value.reason == "elevation_cancelled"


@pytest.mark.unit
async def test_remove_from_allowlist_failed_raises_elevation_failed(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        crowdsec_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="failed", stderr="boom"))
    )

    with pytest.raises(CrowdSecAllowlistError) as exc_info:
        await remove_from_allowlist("203.0.113.5")

    assert exc_info.value.reason == "elevation_failed"
