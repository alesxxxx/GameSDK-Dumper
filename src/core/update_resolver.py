
from __future__ import annotations

import json
import os
import time
from datetime import date, datetime, timezone
from typing import Dict, Iterable, Optional, Tuple
from urllib import request

_CACHE_VERSION = 1
_DEFAULT_CACHE_TTL_SECONDS = 60 * 60 * 6
_STEAM_NEWS_URL = (
    "https://api.steampowered.com/ISteamNews/GetNewsForApp/v0002/"
    "?appid={appid}&count=50&maxlength=0&format=json"
)

_DATE_FORMATS = (
    "%Y-%m-%d",
    "%Y/%m/%d",
    "%m/%d/%y",
    "%m/%d/%Y",
    "%m-%d-%y",
    "%m-%d-%Y",
)

def _app_data_root() -> str:
    root = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    directory = os.path.join(root, "GameSDKKit")
    os.makedirs(directory, exist_ok=True)
    return directory

def update_cache_path() -> str:
    return os.path.join(_app_data_root(), "update_cache.json")

def parse_user_date(raw: str) -> Optional[date]:
    if not raw:
        return None
    text = raw.strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    return None

def _parse_iso_date(raw: object) -> Optional[date]:
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip()
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        pass
    try:
        return datetime.strptime(text, "%Y-%m-%d").date()
    except ValueError:
        return None

def _atomic_json_write(path: str, payload: Dict[str, object]) -> None:
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    os.replace(tmp_path, path)

class SteamUpdateResolver:
    def __init__(
        self,
        *,
        cache_ttl_seconds: int = _DEFAULT_CACHE_TTL_SECONDS,
        cache_path: Optional[str] = None,
    ) -> None:
        self.cache_ttl_seconds = max(60, int(cache_ttl_seconds))
        self.cache_path = cache_path or update_cache_path()
        self._cache = self._load_cache()

    def _load_cache(self) -> Dict[str, object]:
        if not os.path.isfile(self.cache_path):
            return {"version": _CACHE_VERSION, "apps": {}}
        try:
            with open(self.cache_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except Exception:
            return {"version": _CACHE_VERSION, "apps": {}}
        if not isinstance(payload, dict):
            return {"version": _CACHE_VERSION, "apps": {}}
        apps = payload.get("apps")
        if not isinstance(apps, dict):
            apps = {}
        return {"version": _CACHE_VERSION, "apps": apps}

    def _save_cache(self) -> None:
        payload = {
            "version": _CACHE_VERSION,
            "apps": self._cache.get("apps", {}),
        }
        _atomic_json_write(self.cache_path, payload)

    def _fetch_latest_update_date(self, appid: int) -> Optional[date]:
        url = _STEAM_NEWS_URL.format(appid=int(appid))
        req = request.Request(
            url,
            headers={"User-Agent": "GameSDKKit-UpdateResolver/1.0"},
            method="GET",
        )
        with request.urlopen(req, timeout=8.0) as resp:
            body = resp.read()
        payload = json.loads(body.decode("utf-8", errors="ignore"))
        items = (
            payload.get("appnews", {}).get("newsitems", [])
            if isinstance(payload, dict)
            else []
        )
        if not isinstance(items, list):
            return None
        latest_ts = 0
        for item in items:
            if not isinstance(item, dict):
                continue
            ts = item.get("date")
            try:
                ts_int = int(ts)
            except (TypeError, ValueError):
                continue
            if ts_int > latest_ts:
                latest_ts = ts_int
        if latest_ts <= 0:
            return None
        return datetime.fromtimestamp(latest_ts, tz=timezone.utc).date()

    @staticmethod
    def _coerce_appid(appid: object) -> Optional[int]:
        if appid is None:
            return None
        try:
            value = int(str(appid).strip())
        except (TypeError, ValueError):
            return None
        if value <= 0:
            return None
        return value

    def resolve_latest_update_date(
        self,
        appid: object,
        *,
        manual_override: Optional[date] = None,
        force_refresh: bool = False,
    ) -> Tuple[Optional[date], str]:
        if manual_override is not None:
            return manual_override, "manual_override"

        appid_int = self._coerce_appid(appid)
        if appid_int is None:
            return None, "unknown"

        app_key = str(appid_int)
        apps = self._cache.setdefault("apps", {})
        entry = apps.get(app_key) if isinstance(apps, dict) else None
        now_ts = int(time.time())

        if isinstance(entry, dict):
            cached_date = _parse_iso_date(entry.get("latest_update_date"))
            fetched_at = int(entry.get("fetched_at", 0) or 0)
            if not force_refresh and cached_date and fetched_at > 0:
                if (now_ts - fetched_at) <= self.cache_ttl_seconds:
                    return cached_date, "steam_api_cache"

        try:
            latest_date = self._fetch_latest_update_date(appid_int)
        except Exception:
            latest_date = None

        if latest_date is not None:
            apps[app_key] = {
                "latest_update_date": latest_date.isoformat(),
                "fetched_at": now_ts,
            }
            self._save_cache()
            return latest_date, "steam_api"

        if isinstance(entry, dict):
            stale_date = _parse_iso_date(entry.get("latest_update_date"))
            if stale_date is not None:
                return stale_date, "steam_api_cache_stale"

        return None, "unknown"

    def refresh_many(self, appids: Iterable[object]) -> Dict[int, Tuple[Optional[date], str]]:
        results: Dict[int, Tuple[Optional[date], str]] = {}
        seen = set()
        for raw in appids:
            appid = self._coerce_appid(raw)
            if appid is None or appid in seen:
                continue
            seen.add(appid)
            results[appid] = self.resolve_latest_update_date(appid, force_refresh=True)
        return results
