"""A-25: real, automated tests for `packaging/macos/wazuh_agent_setup.py`'s
pure logic (architecture selection, marker persistence, config.env upsert,
manager-host parsing, and — most importantly — the generated bash
script's actual correctness), with the two pieces that genuinely require a
physically-present human (`rumps`' GUI alert and macOS's own admin-password
authorization dialog) replaced by plain injected callables/subprocess
fakes. See that module's own docstring for why this split exists and what
it can/cannot prove.

Not part of `server/venv/bin/python -m pytest -q`'s collection root
(`server/`) — same convention as `packaging/windows/test/
check_tray_locale.py` (a real, runnable script, exercised manually/in CI,
not folded into the main regression suite) and
`packaging/linux/test/Dockerfile.systemd` (a real but non-pytest
verification aid). Run directly:

    <build-venv-or-any-python3.12>/bin/python -m pytest -q \
        packaging/macos/test/test_wazuh_agent_setup.py

Requires `server/` on `sys.path` (see the `sys.path` shim below, mirroring
`hranix_shield_app.py`'s own dev-mode shim) and `platformdirs` installed
(already a `server/requirements.txt` dependency, A-19).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_SERVER_DIR = Path(__file__).resolve().parents[3] / "server"
if str(_SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(_SERVER_DIR))
_MACOS_DIR = Path(__file__).resolve().parents[1]
if str(_MACOS_DIR) not in sys.path:
    sys.path.insert(0, str(_MACOS_DIR))

import wazuh_agent_setup as was  # noqa: E402 (see sys.path shim above)


def test_agent_pkg_arch_maps_apple_silicon_to_arm64():
    with patch("platform.machine", return_value="arm64"):
        assert was._agent_pkg_arch() == "arm64"
        assert was.agent_pkg_filename() == f"wazuh-agent-{was.AGENT_VERSION}-1.arm64.pkg"
        assert was.agent_pkg_url() == (
            f"https://packages.wazuh.com/4.x/macos/wazuh-agent-{was.AGENT_VERSION}-1.arm64.pkg"
        )


def test_agent_pkg_arch_maps_intel_to_intel64():
    with patch("platform.machine", return_value="x86_64"):
        assert was._agent_pkg_arch() == "intel64"
        assert was.agent_pkg_filename() == f"wazuh-agent-{was.AGENT_VERSION}-1.intel64.pkg"


def test_marker_lifecycle(tmp_path):
    with patch("wazuh_agent_setup._data_dir", return_value=tmp_path):
        assert was.already_prompted() is False
        was.mark_prompted()
        assert was.already_prompted() is True
        assert (tmp_path / ".wazuh_agent_prompted").exists()


def test_agent_display_name_is_deterministic_per_host():
    with patch("socket.gethostname", return_value="executives-macbook"):
        assert was.agent_display_name() == "hranix-shield-executives-macbook"


def test_write_wazuh_envs_file_matches_the_official_documented_format(tmp_path):
    envs_path = tmp_path / "wazuh_envs"

    was.write_wazuh_envs_file(manager_host="127.0.0.1", agent_name="hranix-shield-mac1", path=envs_path)

    content = envs_path.read_text(encoding="utf-8")
    assert "WAZUH_MANAGER='127.0.0.1'" in content
    assert "WAZUH_REGISTRATION_SERVER='127.0.0.1'" in content
    assert "WAZUH_AGENT_NAME='hranix-shield-mac1'" in content


class TestUpsertConfigEnv:
    def test_appends_when_file_absent(self, tmp_path):
        env_path = tmp_path / "config.env"

        was.upsert_config_env("WAZUH_AGENT_ID", "042", env_path=env_path)

        assert env_path.read_text(encoding="utf-8") == "WAZUH_AGENT_ID=042\n"

    def test_appends_preserving_existing_lines(self, tmp_path):
        env_path = tmp_path / "config.env"
        env_path.write_text("SERVER_PORT=8080\nBOOTSTRAP_ADMIN_USERNAME=admin\n", encoding="utf-8")

        was.upsert_config_env("WAZUH_AGENT_ID", "042", env_path=env_path)

        lines = env_path.read_text(encoding="utf-8").splitlines()
        assert lines == ["SERVER_PORT=8080", "BOOTSTRAP_ADMIN_USERNAME=admin", "WAZUH_AGENT_ID=042"]

    def test_replaces_an_existing_value_in_place(self, tmp_path):
        env_path = tmp_path / "config.env"
        env_path.write_text(
            "SERVER_PORT=8080\nWAZUH_AGENT_ID=000\nBOOTSTRAP_ADMIN_USERNAME=admin\n", encoding="utf-8"
        )

        was.upsert_config_env("WAZUH_AGENT_ID", "007", env_path=env_path)

        lines = env_path.read_text(encoding="utf-8").splitlines()
        assert lines == ["SERVER_PORT=8080", "WAZUH_AGENT_ID=007", "BOOTSTRAP_ADMIN_USERNAME=admin"]


class TestManagerHost:
    def test_defaults_to_loopback_when_unconfigured(self):
        from app.config import Settings

        settings = Settings(_env_file=None, wazuh_api_url=None)

        assert was._manager_host(settings) == "127.0.0.1"

    def test_parses_host_out_of_a_configured_url(self):
        from app.config import Settings

        settings = Settings(_env_file=None, wazuh_api_url="http://127.0.0.1:55000")

        assert was._manager_host(settings) == "127.0.0.1"


class TestPrivilegedSetupScript:
    """The generated bash script is the single riskiest piece of string
    construction in this module (three layers of quoting: Python -> bash
    -> sed's own `s#...#...#` delimiter syntax) — these tests actually
    RUN the generated script's sed step against a synthetic ossec.conf-
    shaped file, rather than only asserting on the string's literal
    contents, so a subtle escaping bug would fail loudly here instead of
    only during a real (unreproducible-in-CI) elevated install."""

    def test_script_is_syntactically_valid_bash(self, tmp_path):
        script = was.build_privileged_setup_script(
            pkg_path=tmp_path / "wazuh-agent-4.14.6-1.arm64.pkg",
            data_dir=tmp_path / "data",
            log_dir=tmp_path / "log",
        )
        script_path = tmp_path / "script.sh"
        script_path.write_text(script, encoding="utf-8")

        result = subprocess.run(["bash", "-n", str(script_path)], capture_output=True, text=True)

        assert result.returncode == 0, result.stderr

    def test_sed_step_injects_well_formed_directories_into_a_synthetic_ossec_conf(self, tmp_path):
        data_dir = tmp_path / "Library" / "Application Support" / "Hranix Shield"
        log_dir = tmp_path / "Library" / "Logs" / "Hranix Shield"
        conf_path = tmp_path / "ossec.conf"
        conf_path.write_text(
            "<ossec_config>\n"
            "  <syscheck>\n"
            "    <disabled>no</disabled>\n"
            "    <directories>/etc,/usr/bin</directories>\n"
            "  </syscheck>\n"
            "</ossec_config>\n",
            encoding="utf-8",
        )
        script = was.build_privileged_setup_script(
            pkg_path=tmp_path / "agent.pkg", data_dir=data_dir, log_dir=log_dir
        )
        # Strip the `installer`/`launchctl` lines (need real root/a real
        # pkg) — isolate and run ONLY the sed-guard block against our
        # synthetic conf, by pointing AGENT_CONF_PATH-equivalent `$CONF`
        # at our own tmp file instead of the real /Library path.
        sed_only = script.replace(str(was.AGENT_CONF_PATH), str(conf_path))
        lines = sed_only.splitlines()
        body_start = next(i for i, line in enumerate(lines) if line.startswith("CONF="))
        body_end = next(i for i, line in enumerate(lines) if line.startswith("/bin/launchctl"))
        isolated_script = "#!/bin/bash\nset -e\n" + "\n".join(lines[body_start:body_end])
        isolated_path = tmp_path / "sed_only.sh"
        isolated_path.write_text(isolated_script, encoding="utf-8")

        result = subprocess.run(["bash", str(isolated_path)], capture_output=True, text=True)

        assert result.returncode == 0, result.stderr
        new_content = conf_path.read_text(encoding="utf-8")
        assert f'<directories realtime="yes" report_changes="yes" check_all="yes">{data_dir}</directories>' in new_content
        assert f'<directories realtime="yes" report_changes="yes" check_all="yes">{log_dir}</directories>' in new_content
        # Still exactly one closing tag — the injected lines went BEFORE
        # it, not duplicating/breaking the XML structure.
        assert new_content.count("</syscheck>") == 1

        # Idempotent: running it again must not duplicate the entries.
        result2 = subprocess.run(["bash", str(isolated_path)], capture_output=True, text=True)
        assert result2.returncode == 0, result2.stderr
        assert conf_path.read_text(encoding="utf-8").count(str(data_dir)) == 1


class TestRunPrivilegedInstall:
    def test_builds_the_expected_osascript_invocation(self, tmp_path):
        captured = {}

        def fake_runner(args, **kwargs):
            captured["args"] = args
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        script_path = tmp_path / "it's a test.sh"

        result = was.run_privileged_install(script_path, runner=fake_runner)

        assert result.returncode == 0
        assert captured["args"][0] == "osascript"
        assert captured["args"][1] == "-e"
        applescript = captured["args"][2]
        assert "with administrator privileges" in applescript
        assert "/bin/bash" in applescript


class TestMaybeSetupWazuhAgent:
    """Exercises the whole orchestration function with `prompt`/`notify`
    injected and the actual install worker patched out — proves the
    decision logic (skip if already prompted/already installed; mark
    prompted exactly once; only spawn the background worker on explicit
    consent) without ever touching the network or a real shell."""

    def _settings(self):
        from app.config import Settings

        return Settings(_env_file=None)

    def test_skips_entirely_when_already_prompted(self, tmp_path):
        with patch("wazuh_agent_setup.already_prompted", return_value=True), \
             patch("wazuh_agent_setup.is_agent_installed") as installed_check:
            prompt = lambda *_: pytest.fail("must not prompt again")  # noqa: E731
            was.maybe_setup_wazuh_agent(prompt=prompt, notify=lambda *_: None, settings=self._settings())
            installed_check.assert_not_called()

    def test_marks_prompted_without_asking_when_agent_already_installed(self):
        with patch("wazuh_agent_setup.already_prompted", return_value=False), \
             patch("wazuh_agent_setup.is_agent_installed", return_value=True), \
             patch("wazuh_agent_setup.mark_prompted") as mark:
            prompt = lambda *_: pytest.fail("must not prompt when already installed")  # noqa: E731
            was.maybe_setup_wazuh_agent(prompt=prompt, notify=lambda *_: None, settings=self._settings())
            mark.assert_called_once()

    def test_declining_the_prompt_marks_prompted_and_starts_no_thread(self):
        with patch("wazuh_agent_setup.already_prompted", return_value=False), \
             patch("wazuh_agent_setup.is_agent_installed", return_value=False), \
             patch("wazuh_agent_setup.mark_prompted") as mark, \
             patch("threading.Thread") as thread_cls:
            was.maybe_setup_wazuh_agent(
                prompt=lambda *_: False, notify=lambda *_: None, settings=self._settings()
            )
            mark.assert_called_once()
            thread_cls.assert_not_called()

    def test_accepting_the_prompt_starts_exactly_one_background_thread(self):
        with patch("wazuh_agent_setup.already_prompted", return_value=False), \
             patch("wazuh_agent_setup.is_agent_installed", return_value=False), \
             patch("wazuh_agent_setup.mark_prompted"), \
             patch("threading.Thread") as thread_cls:
            was.maybe_setup_wazuh_agent(
                prompt=lambda *_: True, notify=lambda *_: None, settings=self._settings()
            )
            thread_cls.assert_called_once()
            _, kwargs = thread_cls.call_args
            assert kwargs["kwargs"]["manager_host"] == "127.0.0.1"
            thread_cls.return_value.start.assert_called_once()
