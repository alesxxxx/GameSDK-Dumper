
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
from typing import Optional

def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]

def _find_native_helper() -> Optional[Path]:
    candidates = [
        _project_root() / "bin" / "SteamLoginHelper.exe",
        Path(sys.executable).resolve().parent / "bin" / "SteamLoginHelper.exe",
    ]
    seen = set()
    for candidate in candidates:
        key = str(candidate).lower()
        if key in seen:
            continue
        seen.add(key)
        if candidate.is_file():
            return candidate
    return None

def _emit_result(success: bool, **payload) -> None:
    print(json.dumps({"success": success, **payload}))
    sys.stdout.flush()

def run_steam_login_dialog() -> int:
    helper_path = _find_native_helper()
    if helper_path is None:
        _emit_result(
            False,
            error=(
                "Steam login helper is missing. Rebuild with Build.bat so "
                "bin/SteamLoginHelper.exe is bundled."
            ),
        )
        return 1

    helper_args = [str(helper_path)]
    if any(arg == "--import-only" for arg in sys.argv[1:]):
        helper_args.append("--import-only")

    process = subprocess.Popen(
        helper_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    out, err = process.communicate()

    if out.strip():
        print(out.strip())
        sys.stdout.flush()
    if err.strip():
        print(f"[steam-login] helper-stderr={err.strip()}")
        sys.stdout.flush()

    return process.returncode

if __name__ == "__main__":
    sys.exit(run_steam_login_dialog())
