
from __future__ import annotations

import json
import os
from typing import Dict

_DEFAULT_MODE = "simple"
_VALID_MODES = {"simple", "detailed"}
_DEFAULTS = {
    "url": "",
    "timeout": 6.0,
    "discord_message_id": "",
    "mode": _DEFAULT_MODE,
}
_MIN_TIMEOUT = 1.0
_MAX_TIMEOUT = 60.0

def _settings_path() -> str:
    root = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    directory = os.path.join(root, "GameSDKKit")
    os.makedirs(directory, exist_ok=True)
    return os.path.join(directory, "webhook_settings.json")

def _clamp_timeout(raw) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return float(_DEFAULTS["timeout"])
    if value < _MIN_TIMEOUT:
        return _MIN_TIMEOUT
    if value > _MAX_TIMEOUT:
        return _MAX_TIMEOUT
    return value

def _normalize_mode(raw) -> str:
    value = str(raw or "").strip().lower()
    if value in _VALID_MODES:
        return value
    return _DEFAULT_MODE

def load_webhook_settings() -> Dict[str, object]:
    path = _settings_path()
    if not os.path.exists(path):
        return dict(_DEFAULTS)

    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            return dict(_DEFAULTS)
    except Exception:
        return dict(_DEFAULTS)

    return {
        "url": str(payload.get("url", "") or "").strip(),
        "timeout": _clamp_timeout(payload.get("timeout", _DEFAULTS["timeout"])),
        "discord_message_id": str(payload.get("discord_message_id", "") or "").strip(),
        "mode": _normalize_mode(payload.get("mode", _DEFAULTS["mode"])),
    }

def save_webhook_settings(
    *,
    url: str,
    timeout: float = 6.0,
    discord_message_id: str = "",
    mode: str = _DEFAULT_MODE,
) -> None:
    payload = {
        "url": (url or "").strip(),
        "timeout": _clamp_timeout(timeout),
        "discord_message_id": str(discord_message_id or "").strip(),
        "mode": _normalize_mode(mode),
    }
    path = _settings_path()
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
