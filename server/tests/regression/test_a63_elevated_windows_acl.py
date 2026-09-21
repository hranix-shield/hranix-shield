"""A-63-1 regression anchor (первое живое тестирование с полным стеком,
2026-09-21): «Проверить обновления» → «Не удалось выполнить действие с
повышенными правами».

Корневая причина: в `_elevated_run_windows` временные stdout/stderr-файлы
создаёт САМ elevated-процесс (cmd.exe redirect `1>`/`2>`), и owner/ACL,
который он ставит на файл, оставляет не-elevated токен того же пользователя
без права чтения — `read_text` после УСПЕШНОГО прогона бросал
PermissionError, который роутер превращал в общее «не удалось выполнить
действие». Пин:

  1. сгенерированный PS-скрипт сам выдаёт текущему пользователю Full
     control на оба redirect-файла (`icacls ... /grant *<SID>:F`) как
     ПОСЛЕДНИЙ шаг elevated-команды; SID вычисляется в не-elevated части
     скрипта (`WindowsIdentity::GetCurrent()`) и вплетается в argv
     конкатенацией `' + $sid + '` — не интерполяцией питона;
  2. exitcode-файл грант НЕ получает — его пишет не-elevated PowerShell
     (Out-File) ПОСЛЕ Start-Process, ACL-проблемы у него нет;
  3. PermissionError на чтении результатов — честный `failed`-статус, а не
     необработанное исключение.

UAC-диалог живьём из автотеста не щёлкается (директива владельца
2026-09-20) — транспорт по-прежнему фейковый `runner`-инъекцией, как в
test_elevated_connector.py; живая UAC-приёмка — за владельцем.
"""

from pathlib import Path

import pytest

import app.services.mcp.security_connectors.elevated as elevated_module
from app.services.mcp.security_connectors.elevated import elevated_run


def _fake_runner_writing_outputs(responses_stdout: str = "", stderr_text: str = "", exit_code: str = "0"):
    """Fake UAC-транспорт: «elevated» cmd.exe, который пишет три файла и
    возвращает 0 — same technique test_elevated_connector.py's own Windows
    tests use. Заодно сохраняет сгенерированный PS-скрипт для проверок."""

    async def _run(argv: list[str], *, timeout: float):
        script_path = Path(argv[-1])
        captured["script"] = script_path.read_text(encoding="utf-8")
        tmp_path = script_path.parent
        (tmp_path / "stdout.txt").write_text(responses_stdout, encoding="utf-8")
        (tmp_path / "stderr.txt").write_text(stderr_text, encoding="utf-8")
        (tmp_path / "exitcode.txt").write_text(f"{exit_code}\n", encoding="ascii")
        return (0, "", "")

    captured: dict = {}
    return _run, captured


@pytest.mark.unit
async def test_windows_script_grants_the_calling_user_full_control_on_both_redirect_files(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(elevated_module.platform, "system", lambda: "Windows")
    runner, captured = _fake_runner_writing_outputs(responses_stdout="netsh output\n")

    result = await elevated_run(
        ["netsh", "advfirewall", "show", "allprofiles"],
        reason_ru="r",
        reason_en="e",
        runner=runner,
    )

    assert result.status == "ok"
    script = captured["script"]
    # SID вычисляется в скрипте (не пришивает питон)...
    assert "([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value" in script
    # ...и вплетается в elevated-argv конкатенацией PS-литералов.
    assert script.count("' + $sid + '") == 2
    # Грант ровно на ДВА redirect-файла (stdout/stderr), ровно по разу.
    assert script.count("icacls") == 2
    # Delayed expansion: exit code внутренней команды доходит до cmd's exit.
    # A-63 follow-up (живой фикс 2026-09-21): /S + внешняя обёртка кавычками
    # — cmd иначе срезает первую кавычку пути с пробелами (docker.exe) и
    # умирает с 9009 "'...' is not recognized".
    assert '/v:on /s /c " ' in script
    assert "& set EC=!ERRORLEVEL!" in script
    assert "& exit /b !EC! \"" in script
    # Сама команда владельца на месте, редиректы — в файлы.
    assert '1> "' in script and '2> "' in script


@pytest.mark.unit
async def test_windows_exitcode_file_is_written_non_elevated_and_gets_no_grant(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(elevated_module.platform, "system", lambda: "Windows")
    runner, captured = _fake_runner_writing_outputs()

    await elevated_run(["netsh"], reason_ru="r", reason_en="e", runner=runner)

    script = captured["script"]
    # exitcode.txt пишется Out-File'ом не-elevated PowerShell'а ПОСЛЕ
    # Start-Process — elevated-часть (одна строка $cmdArgs до грантов) его
    # не создаёт и в гранты не включает.
    assert "$p.ExitCode | Out-File -FilePath" in script
    cmd_args_line = next(line for line in script.splitlines() if "$cmdArgs" in line)
    assert cmd_args_line.count("icacls") == 2
    assert "exitcode" not in cmd_args_line


@pytest.mark.unit
async def test_windows_read_back_permission_error_is_an_honest_failed_never_raises(
    monkeypatch: pytest.MonkeyPatch,
):
    """Вторая линия обороны: даже если icacls не помог (экзотическая
    конфигурация/антивирус), PermissionError на read_text не должен
    вылетать из `_elevated_run_windows` наверх — наружу честный
    `failed`-статус с диагностикой."""
    monkeypatch.setattr(elevated_module.platform, "system", lambda: "Windows")

    real_read_text = Path.read_text

    def _denied_read_text(self, *args, **kwargs):
        if self.name in ("stdout.txt", "stderr.txt", "exitcode.txt"):
            raise PermissionError(13, "Access is denied")
        return real_read_text(self, *args, **kwargs)

    async def fake_runner(argv: list[str], *, timeout: float):
        script_path = Path(argv[-1])
        tmp_path = script_path.parent
        (tmp_path / "stdout.txt").write_text("real output\n", encoding="utf-8")
        (tmp_path / "stderr.txt").write_text("", encoding="utf-8")
        (tmp_path / "exitcode.txt").write_text("0\n", encoding="ascii")
        return (0, "", "")

    monkeypatch.setattr(Path, "read_text", _denied_read_text)

    result = await elevated_run(["netsh"], reason_ru="r", reason_en="e", runner=fake_runner)

    monkeypatch.undo()
    assert result.status == "failed"
    assert "could not be read back" in result.stderr
    # Реальный вывод команды при этом недоступен — не прикидываемся ok.
    assert result.stdout == ""
