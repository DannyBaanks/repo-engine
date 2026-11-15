from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from .config import CONFIG_PATH, ROOT, config, registry

TASK_NAME = "Repo Engine Startup"


def health() -> list[str]:
    problems: list[str] = []
    if not CONFIG_PATH.exists():
        problems.append("engine configuration is missing")
    elif not Path(config().get("policy_path", "")).is_file():
        problems.append("private publication policy is unavailable")
    for raw_path in registry().get("repos", {}):
        repo = Path(raw_path)
        if not repo.exists():
            problems.append(f"registered repository is missing: {repo}")
            continue
        for hook in ("pre-commit", "pre-push"):
            if not (repo / ".git" / "hooks" / hook).exists():
                problems.append(f"{repo.name}: {hook} hook is missing")
    return problems


def notify(message: str) -> None:
    escaped = message.replace("'", "''")
    script = (
        "Add-Type -AssemblyName System.Windows.Forms; "
        f"[System.Windows.Forms.MessageBox]::Show('{escaped}', 'Repo Engine health')"
    )
    subprocess.run(["powershell", "-NoProfile", "-Command", script], check=False)


def install_task() -> str:
    command = f'"{Path(sys.executable)}" "{ROOT / "repo-engine.py"}" startup'
    result = subprocess.run(
        [
            "schtasks.exe",
            "/Create",
            "/TN",
            TASK_NAME,
            "/SC",
            "ONLOGON",
            "/RL",
            "LIMITED",
            "/TR",
            command,
            "/F",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if not result.returncode:
        return "Task Scheduler"

    # Some Windows policies deny Task Scheduler registration to standard users.
    # HKCU Run gives the same per-user logon behavior without elevation.
    try:
        import winreg

        pythonw = Path(sys.executable).with_name("pythonw.exe")
        executable = pythonw if pythonw.exists() else Path(sys.executable)
        value = f'"{executable}" "{ROOT / "repo-engine.py"}" startup'
        key = winreg.CreateKey(
            winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"
        )
        winreg.SetValueEx(key, "Repo Engine Startup", 0, winreg.REG_SZ, value)
        winreg.CloseKey(key)
        return "Windows Run key"
    except OSError as error:
        details = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(
            f"could not install startup check: {details}; fallback failed: {error}"
        ) from error
