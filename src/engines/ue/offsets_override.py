
from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional, Tuple

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))

def _game_dir_name(process_name: str) -> str:
    return process_name.replace(".exe", "").strip()

def _offsets_json_path(process_name: str) -> str:
    return os.path.join(
        _PROJECT_ROOT, "games", _game_dir_name(process_name), "Offsets", "OffsetsInfo.json"
    )

def _parse_offset(data: Dict[str, Any], key: str) -> Optional[int]:
    if key in data:
        v = data[key]
        if isinstance(v, bool):
            return None
        if isinstance(v, (int, float)):
            return int(v)
        if isinstance(v, str):
            try:
                return int(v, 0)
            except ValueError:
                return None
    for row in data.get("data") or []:
        if isinstance(row, (list, tuple)) and len(row) >= 2 and row[0] == key:
            try:
                return int(row[1])
            except (TypeError, ValueError):
                return None
    return None

def load_game_offsets_override(
    process_name: Optional[str],
) -> Optional[Tuple[int, int, Optional[int], int, bool]]:
    if not process_name:
        return None
    path = _offsets_json_path(process_name)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    og = _parse_offset(data, "OFFSET_GNAMES")
    oo = _parse_offset(data, "OFFSET_GOBJECTS")
    if og is None or oo is None:
        return None
    ow = _parse_offset(data, "OFFSET_GWORLD")
    stride = data.get("item_stride")
    if isinstance(stride, (int, float)):
        item_stride = int(stride)
    else:
        item_stride = 24
    legacy = bool(data.get("legacy", False))
    return og, oo, ow, item_stride, legacy

def mark_offsets_stale(process_name: str) -> None:
    path = _offsets_json_path(process_name)
    if not os.path.isfile(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return
        game_block = data.get("game")
        if not isinstance(game_block, dict):
            data["game"] = {}
            game_block = data["game"]
        stale = game_block.get("stale_detection")
        if not isinstance(stale, dict):
            game_block["stale_detection"] = {}
            stale = game_block["stale_detection"]
        stale["redump_recommended"] = True
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        pass
