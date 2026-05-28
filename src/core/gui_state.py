
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Dict, List

_SETTINGS_VERSION = 2
_HISTORY_VERSION = 1
_DEFAULT_HISTORY_RETENTION = 200

_DEFAULT_SETTINGS = {
    "version": _SETTINGS_VERSION,
    "first_run_completed": False,
    "dpi_scale": 1.0,
    "latest_update_overrides": {},
    "stage_ema_seconds": {},
}

def _app_data_root() -> str:
    root = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    directory = os.path.join(root, "GameSDKKit")
    os.makedirs(directory, exist_ok=True)
    return directory

def gui_settings_path() -> str:
    return os.path.join(_app_data_root(), "gui_settings.json")

def dump_history_path() -> str:
    return os.path.join(_app_data_root(), "dump_history.json")

def _atomic_json_write(path: str, payload: Dict[str, object]) -> None:
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    os.replace(tmp_path, path)

def _coerce_overrides(value: object) -> Dict[str, str]:
    if not isinstance(value, dict):
        return {}
    out: Dict[str, str] = {}
    for key, raw in value.items():
        key_str = str(key or "").strip().lower()
        date_str = str(raw or "").strip()
        if key_str and date_str:
            out[key_str] = date_str
    return out

def _coerce_ema(value: object) -> Dict[str, float]:
    if not isinstance(value, dict):
        return {}
    out: Dict[str, float] = {}
    for key, raw in value.items():
        stage = str(key or "").strip().lower()
        if not stage:
            continue
        try:
            secs = float(raw)
        except (TypeError, ValueError):
            continue
        if secs > 0:
            out[stage] = secs
    return out

def _coerce_dpi_scale(value: object) -> float:
    try:
        scale = float(value)
    except (TypeError, ValueError):
        return 1.0
    return max(0.8, min(2.0, round(scale, 2)))

def load_gui_settings() -> Dict[str, object]:
    path = gui_settings_path()
    if not os.path.isfile(path):
        return dict(_DEFAULT_SETTINGS)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception:
        return dict(_DEFAULT_SETTINGS)

    if not isinstance(payload, dict):
        return dict(_DEFAULT_SETTINGS)

    return {
        "version": _SETTINGS_VERSION,
        "first_run_completed": bool(payload.get("first_run_completed", False)),
        "dpi_scale": _coerce_dpi_scale(payload.get("dpi_scale", 1.0)),
        "latest_update_overrides": _coerce_overrides(payload.get("latest_update_overrides", {})),
        "stage_ema_seconds": _coerce_ema(payload.get("stage_ema_seconds", {})),
    }

def save_gui_settings(settings: Dict[str, object]) -> Dict[str, object]:
    payload = {
        "version": _SETTINGS_VERSION,
        "first_run_completed": bool(settings.get("first_run_completed", False)),
        "dpi_scale": _coerce_dpi_scale(settings.get("dpi_scale", 1.0)),
        "latest_update_overrides": _coerce_overrides(settings.get("latest_update_overrides", {})),
        "stage_ema_seconds": _coerce_ema(settings.get("stage_ema_seconds", {})),
    }
    _atomic_json_write(gui_settings_path(), payload)
    return payload

def update_stage_ema(settings: Dict[str, object], stage: str, observed_seconds: float, alpha: float = 0.35) -> Dict[str, object]:
    stage_key = str(stage or "").strip().lower()
    if not stage_key:
        return settings
    try:
        observed = float(observed_seconds)
    except (TypeError, ValueError):
        return settings
    if observed <= 0:
        return settings

    ema = _coerce_ema(settings.get("stage_ema_seconds", {}))
    previous = ema.get(stage_key)
    if previous is None:
        ema[stage_key] = observed
    else:
        smoothing = max(0.05, min(0.95, float(alpha)))
        ema[stage_key] = (smoothing * observed) + ((1.0 - smoothing) * previous)
    settings["stage_ema_seconds"] = ema
    return settings

def load_dump_history() -> List[Dict[str, object]]:
    path = dump_history_path()
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception:
        return []
    if not isinstance(payload, dict):
        return []
    entries = payload.get("entries")
    if not isinstance(entries, list):
        return []
    sanitized: List[Dict[str, object]] = []
    for item in entries:
        if isinstance(item, dict):
            sanitized.append(dict(item))
    return sanitized

def append_dump_history(
    entry: Dict[str, object],
    *,
    retention: int = _DEFAULT_HISTORY_RETENTION,
) -> List[Dict[str, object]]:
    max_entries = max(1, int(retention))
    history = load_dump_history()
    record = dict(entry or {})
    if not record.get("recorded_at"):
        record["recorded_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    history.append(record)
    if len(history) > max_entries:
        history = history[-max_entries:]

    payload = {
        "version": _HISTORY_VERSION,
        "retention": max_entries,
        "entries": history,
    }
    _atomic_json_write(dump_history_path(), payload)
    return history
