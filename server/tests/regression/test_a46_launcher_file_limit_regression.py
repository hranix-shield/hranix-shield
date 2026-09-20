"""A-46 regression anchor.

Pins the core A-46 contract a later refactor of `launcher.launch()` must
not silently drop: `_raise_open_file_limit()` (see
docs/план-спецификация-фаза-0-лимит-открытых-файлов-2026-08-16.md — a real
bug found live, 2026-08-03, a `launchd`-launched packaged `.app` running a
scan into its own 256-descriptor default ceiling froze the WHOLE server,
not just that request) is called BEFORE `_start_server()` — raising the
limit after the server (and its sockets) already started would be too
late for the very first requests that could exhaust it.
"""

from __future__ import annotations

import pytest

import launcher


@pytest.mark.integration
def test_launch_raises_the_file_descriptor_limit_before_starting_the_server(
    monkeypatch: pytest.MonkeyPatch,
):
    calls: list[str] = []

    monkeypatch.setattr(launcher, "_raise_open_file_limit", lambda: calls.append("raise_limit"))
    monkeypatch.setattr(launcher, "_ensure_data_directories", lambda settings: calls.append("ensure_dirs"))
    monkeypatch.setattr(launcher, "run_migrations", lambda: calls.append("migrations"))

    class _FakeServer:
        should_exit = False

    class _FakeThread:
        def is_alive(self):
            return True

    def _fake_start_server(settings):
        calls.append("start_server")
        return _FakeServer(), _FakeThread()

    monkeypatch.setattr(launcher, "_start_server", _fake_start_server)
    monkeypatch.setattr(
        launcher, "_wait_for_health", lambda base_url, *, timeout: calls.append("wait_health") or True
    )

    handle = launcher.launch(open_browser=False)

    assert calls == ["raise_limit", "ensure_dirs", "migrations", "start_server", "wait_health"]
    assert handle.healthy is True
