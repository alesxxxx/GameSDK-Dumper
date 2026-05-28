
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import date, datetime
from typing import Dict, Iterable, List, Optional, Tuple

from src.core.update_resolver import SteamUpdateResolver, parse_user_date

def normalize_game_key(name: str) -> str:
    cleaned = (name or "").lower().replace(".exe", "").replace(".dll", "")
    return re.sub(r"[^a-z0-9]+", "", cleaned)

def _load_json(path: str) -> Dict[str, object]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
            return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}

def _extract_dump_date(info: Dict[str, object], offsets_path: str) -> Optional[date]:
    game_block = info.get("game")
    if isinstance(game_block, dict):
        raw = game_block.get("dump_timestamp")
        if isinstance(raw, str) and raw.strip():
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00")).date()
            except ValueError:
                pass
    try:
        return datetime.fromtimestamp(os.path.getmtime(offsets_path)).date()
    except OSError:
        return None

def _parse_health_state(health_path: str) -> Tuple[str, str]:
    if not os.path.isfile(health_path):
        return "unknown", "health.txt missing"
    try:
        with open(health_path, "r", encoding="utf-8", errors="ignore") as handle:
            text = handle.read()
    except OSError:
        return "unknown", "health.txt unreadable"

    if not text.strip():
        return "unknown", "health.txt empty"

    grade_match = re.search(r"Dump confidence:\s*(HIGH|MEDIUM|LOW|INCOMPLETE)", text, re.IGNORECASE)
    grade = grade_match.group(1).upper() if grade_match else ""
    has_clean = "dump looks clean" in text.lower()
    has_warning = "[!!]" in text

    if grade == "HIGH" and (has_clean or not has_warning):
        return "verified", "health confidence HIGH"
    if grade in {"MEDIUM", "LOW", "INCOMPLETE"}:
        return "failed", f"health confidence {grade}"
    if has_warning:
        return "failed", "health warnings present"
    if has_clean:
        return "verified", "health says dump looks clean"
    return "unknown", "health confidence unclear"

def _status_from_matrix(
    *,
    health_state: str,
    dump_date: Optional[date],
    latest_update_date: Optional[date],
) -> Tuple[str, str]:
    health_failed = health_state == "failed"
    health_verified = health_state == "verified"

    if health_failed:
        return "Not Verified", "health check failed"
    if latest_update_date and dump_date and dump_date < latest_update_date:
        return "Not Verified", "dump predates latest game update"
    if health_verified and latest_update_date and dump_date and dump_date >= latest_update_date:
        return "Verified", "health passed and dump is up to date"
    return "Unknown", "missing or unclear health/update recency"

@dataclass
class KnownGoodRecord:
    game: str
    game_key: str
    process: str
    steam_appid: Optional[int]
    dump_date: Optional[date]
    latest_update_date: Optional[date]
    health_state: str
    health_reason: str
    final_status: str
    final_reason: str
    source: str
    offsets_dir: str
    offsets_path: str
    health_path: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "game": self.game,
            "game_key": self.game_key,
            "process": self.process,
            "steam_appid": self.steam_appid,
            "dump_date": self.dump_date.isoformat() if self.dump_date else "",
            "latest_update_date": self.latest_update_date.isoformat() if self.latest_update_date else "",
            "health_state": self.health_state,
            "health_reason": self.health_reason,
            "final_status": self.final_status,
            "final_reason": self.final_reason,
            "source": self.source,
            "offsets_dir": self.offsets_dir,
            "offsets_path": self.offsets_path,
            "health_path": self.health_path,
        }

def _coerce_appid(raw: object) -> Optional[int]:
    if raw is None:
        return None
    try:
        appid = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    if appid <= 0:
        return None
    return appid

def _manual_override_for_game(
    overrides: Dict[str, str],
    *,
    game_key: str,
    appid: Optional[int],
) -> Optional[date]:
    if game_key:
        parsed = parse_user_date(str(overrides.get(game_key, "") or ""))
        if parsed is not None:
            return parsed
    if appid is not None:
        parsed = parse_user_date(str(overrides.get(str(appid), "") or ""))
        if parsed is not None:
            return parsed
    return None

def collect_known_good_records(
    games_root: str,
    *,
    resolver: Optional[SteamUpdateResolver] = None,
    latest_update_overrides: Optional[Dict[str, str]] = None,
    force_refresh: bool = False,
) -> List[KnownGoodRecord]:
    if not os.path.isdir(games_root):
        return []

    active_resolver = resolver or SteamUpdateResolver()
    overrides = {
        str(key or "").strip().lower(): str(value or "").strip()
        for key, value in (latest_update_overrides or {}).items()
    }

    records: List[KnownGoodRecord] = []
    game_dirs = sorted(
        name for name in os.listdir(games_root)
        if os.path.isdir(os.path.join(games_root, name))
    )
    for game_dir in game_dirs:
        offsets_dir = os.path.join(games_root, game_dir, "Offsets")
        offsets_path = os.path.join(offsets_dir, "OffsetsInfo.json")
        if not os.path.isfile(offsets_path):
            continue
        health_path = os.path.join(offsets_dir, "health.txt")
        info = _load_json(offsets_path)
        game_block = info.get("game") if isinstance(info.get("game"), dict) else {}

        process_name = str(game_block.get("process", "") or "")
        display_name = process_name.replace(".exe", "").replace(".dll", "") if process_name else game_dir
        game_key = normalize_game_key(display_name)
        steam_appid = _coerce_appid(game_block.get("steam_appid"))

        dump_date = _extract_dump_date(info, offsets_path)
        health_state, health_reason = _parse_health_state(health_path)

        manual_override = _manual_override_for_game(
            overrides,
            game_key=game_key,
            appid=steam_appid,
        )
        if manual_override is not None:
            latest_update_date, source = manual_override, "manual_override"
        else:
            latest_update_date, source = active_resolver.resolve_latest_update_date(
                steam_appid,
                force_refresh=force_refresh,
            )

        final_status, final_reason = _status_from_matrix(
            health_state=health_state,
            dump_date=dump_date,
            latest_update_date=latest_update_date,
        )

        records.append(
            KnownGoodRecord(
                game=display_name,
                game_key=game_key,
                process=process_name,
                steam_appid=steam_appid,
                dump_date=dump_date,
                latest_update_date=latest_update_date,
                health_state=health_state,
                health_reason=health_reason,
                final_status=final_status,
                final_reason=final_reason,
                source=source,
                offsets_dir=offsets_dir,
                offsets_path=offsets_path,
                health_path=health_path,
            )
        )

    return records

def find_record_for_game(records: Iterable[KnownGoodRecord], game_key: str) -> Optional[KnownGoodRecord]:
    key = normalize_game_key(game_key)
    for record in records:
        if record.game_key == key:
            return record
    return None
