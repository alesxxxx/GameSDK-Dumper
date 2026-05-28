
import json
import os
import re
import sys
from datetime import date, datetime
from typing import Dict, List, Optional, Tuple
from urllib import error, request
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.core.steam_appid import infer_steam_appid
from src.core.update_resolver import SteamUpdateResolver

_DATE_FORMATS = (
    "%Y-%m-%d",
    "%Y/%m/%d",
    "%m/%d/%y",
    "%m/%d/%Y",
    "%m-%d-%y",
    "%m-%d-%Y",
)
_WEBHOOK_MODE_SIMPLE = "simple"
_WEBHOOK_MODE_DETAILED = "detailed"

def parse_update_date(raw: str) -> Optional[date]:
    if not raw:
        return None
    value = raw.strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(value, fmt).date()
        except ValueError:
            continue
    return None

def _short_date(value: Optional[date]) -> str:
    if value is None:
        return "unknown"
    return f"{value.month}/{value.day}/{str(value.year)[2:]}"

def _normalize_game_key(name: str) -> str:
    clean = name.lower().replace(".exe", "").replace(".dll", "")
    clean = re.sub(r"[^a-z0-9]+", "", clean)
    return clean

def _normalize_webhook_mode(raw: object) -> str:
    value = str(raw or "").strip().lower()
    if value in {_WEBHOOK_MODE_SIMPLE, _WEBHOOK_MODE_DETAILED}:
        return value
    return _WEBHOOK_MODE_SIMPLE

def _pretty_game_label(name: str) -> str:
    text = str(name or "").replace(".exe", "").replace(".dll", "").strip()
    if not text:
        return "Unknown"

    for suffix in (
        "-Win64-Shipping",
        "_Win64_Shipping",
        "-Shipping",
        "_Shipping",
    ):
        if text.lower().endswith(suffix.lower()):
            text = text[: -len(suffix)]
            break

    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", text)
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    text = re.sub(r"(?<=[A-Za-z])(?=\d)", " ", text)
    text = re.sub(r"(?<=\d)(?=[A-Za-z])", " ", text)
    text = text.replace("_", " ").replace("-", " ")
    text = re.sub(r"\s+", " ", text).strip()
    return text or name

def _coerce_override_date(raw: object) -> Optional[date]:
    if isinstance(raw, date):
        return raw
    if raw is None:
        return None
    return parse_update_date(str(raw))

def _coerce_appid(raw: object) -> Optional[int]:
    if raw is None:
        return None
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None

def _project_games_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

def _candidate_games_roots(preferred: str) -> List[str]:
    roots: List[str] = []
    if preferred:
        roots.append(os.path.abspath(preferred))

    roots.append(os.path.abspath(os.path.join(os.getcwd(), "games")))
    roots.append(os.path.join(_project_games_root(), "games"))

    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        roots.append(os.path.join(exe_dir, "games"))

    local_data = os.environ.get("LOCALAPPDATA")
    if local_data:
        roots.append(os.path.join(local_data, "GameSDKKit", "games"))

    deduped: List[str] = []
    seen = set()
    for root in roots:
        norm = os.path.normcase(os.path.normpath(root))
        if norm in seen:
            continue
        seen.add(norm)
        deduped.append(root)
    return deduped

def _offsets_count(games_root: str) -> int:
    if not games_root or not os.path.isdir(games_root):
        return 0
    count = 0
    try:
        game_dirs = sorted(os.listdir(games_root))
    except OSError:
        return 0
    for game_dir in game_dirs:
        offsets_path = os.path.join(games_root, game_dir, "Offsets", "OffsetsInfo.json")
        if os.path.isfile(offsets_path):
            count += 1
    return count

def _resolve_games_root(games_root: str) -> str:
    candidates = _candidate_games_roots(games_root)

    for root in candidates:
        if _offsets_count(root) > 0:
            return root

    for root in candidates:
        if os.path.isdir(root):
            return root

    return os.path.abspath(games_root or "")

def _load_json(path: str) -> Dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
            return loaded if isinstance(loaded, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}

def _load_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""

def _extract_dump_date(info: Dict, path: str) -> Optional[date]:
    game_block = info.get("game")
    if isinstance(game_block, dict):
        raw = game_block.get("dump_timestamp")
        if isinstance(raw, str) and raw:
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00")).date()
            except ValueError:
                pass
    try:
        return datetime.fromtimestamp(os.path.getmtime(path)).date()
    except OSError:
        return None

def _assess_health_file(health_path: str) -> Tuple[bool, str]:
    if not os.path.isfile(health_path):
        return False, "NOT VERIFIED (missing health.txt)"

    text = _load_text(health_path)
    if not text.strip():
        return False, "NOT VERIFIED (empty health.txt)"

    match = re.search(r"Dump confidence:\s*(HIGH|MEDIUM|LOW|INCOMPLETE)", text, re.IGNORECASE)
    grade = match.group(1).upper() if match else ""
    has_clean_line = "dump looks clean" in text.lower()
    has_warning = "[!!]" in text

    if grade == "HIGH" and (has_clean_line or not has_warning):
        return True, "VERIFIED"
    if grade in ("MEDIUM", "LOW", "INCOMPLETE"):
        return False, f"NOT VERIFIED ({grade})"
    if has_warning:
        return False, "NOT VERIFIED (warnings)"
    if has_clean_line:
        return True, "VERIFIED"
    return False, "NOT VERIFIED (health unclear)"

def collect_offset_statuses(
    games_root: str,
    *,
    latest_update_overrides: Optional[Dict[str, object]] = None,
    as_of_date: Optional[date] = None,
    resolver: Optional[SteamUpdateResolver] = None,
    force_refresh: bool = False,
) -> List[Dict[str, str]]:
    statuses: List[Dict[str, str]] = []
    overrides = latest_update_overrides or {}
    games_root = _resolve_games_root(games_root)
    today = as_of_date or datetime.now().date()
    active_resolver = resolver or SteamUpdateResolver()
    if not os.path.isdir(games_root):
        return statuses

    for game_dir in sorted(os.listdir(games_root)):
        offsets_path = os.path.join(games_root, game_dir, "Offsets", "OffsetsInfo.json")
        if not os.path.isfile(offsets_path):
            continue
        health_path = os.path.join(games_root, game_dir, "Offsets", "health.txt")

        info = _load_json(offsets_path)
        game_block = info.get("game") if isinstance(info.get("game"), dict) else {}
        process_name = game_block.get("process") if isinstance(game_block, dict) else ""
        display_name = (
            str(process_name).replace(".exe", "").replace(".dll", "")
            if process_name
            else game_dir
        )
        game_key = _normalize_game_key(display_name)
        steam_appid = _coerce_appid(game_block.get("steam_appid"))
        if steam_appid is None:
            steam_appid = infer_steam_appid(process_name=str(process_name or ""), game_name=display_name)
        dump_date = _extract_dump_date(info, offsets_path)
        dump_age_days = None
        dump_age_display = ""
        if dump_date:
            try:
                dump_age_days = max(0, int((today - dump_date).days))
            except Exception:
                dump_age_days = None
            if dump_age_days is not None:
                dump_age_display = f"{dump_age_days}d old"
        latest_update = _coerce_override_date(overrides.get(game_key))
        update_source = "manual_override" if latest_update is not None else "unknown"
        if latest_update is None and steam_appid is not None:
            latest_update = _coerce_override_date(overrides.get(str(steam_appid)))
            if latest_update is not None:
                update_source = "manual_override"
        if latest_update is None and steam_appid is not None:
            latest_update, update_source = active_resolver.resolve_latest_update_date(
                steam_appid,
                force_refresh=force_refresh,
            )
        health_verified, health_status = _assess_health_file(health_path)

        status = "UNKNOWN"
        note = ""
        if latest_update and dump_date:
            if dump_date < latest_update:
                status = "DATED"
                note = f"MOST RECENT UPDATE {_short_date(latest_update)}!"
            else:
                status = "UP TO DATE"
        elif latest_update and not dump_date:
            note = "DUMP DATE UNKNOWN"
        elif dump_date and not latest_update:
            note = "LATEST UPDATE UNKNOWN"
        else:
            note = "DUMP DATE + LATEST UPDATE UNKNOWN"

        if health_verified and status == "UP TO DATE":
            verification_status = "VERIFIED"
        elif not health_verified:
            verification_status = "NOT VERIFIED"
        else:
            verification_status = "UNVERIFIED"

        statuses.append(
            {
                "game": display_name,
                "game_label": _pretty_game_label(display_name),
                "status": status,
                "dump_date": dump_date.isoformat() if dump_date else "",
                "dump_date_display": _short_date(dump_date),
                "dump_age_days": dump_age_days if dump_age_days is not None else "",
                "dump_age_display": dump_age_display,
                "latest_update_date": latest_update.isoformat() if latest_update else "",
                "latest_update_display": _short_date(latest_update) if latest_update else "",
                "note": note,
                "verification_status": verification_status,
                "steam_appid": steam_appid if steam_appid is not None else "",
                "update_source": update_source,
                "offsets_path": os.path.abspath(offsets_path),
                "health_path": os.path.abspath(health_path),
                "health_verified": health_verified,
                "health_status": health_status,
            }
        )
    return statuses

def format_offset_status_board(statuses: List[Dict[str, str]]) -> str:
    lines = [
        "OFFSET STATUS'S",
        "========================",
        "",
    ]
    if not statuses:
        lines.append("No OffsetsInfo.json files found.")
        return "\n".join(lines)

    for entry in statuses:
        line = f"{entry['game'].upper()}: {entry['status']} : {entry['dump_date_display']}"
        if entry.get("dump_age_display"):
            line += f" - {entry['dump_age_display']}"
        if entry["status"] == "DATED" and entry["latest_update_display"]:
            line += f" - MOST RECENT UPDATE {entry['latest_update_display']}!"
        elif entry.get("note"):
            line += f" - {entry['note']}"
        if entry.get("verification_status"):
            line += f" - {entry['verification_status']}"
        line += f" - {entry.get('health_status', 'NOT VERIFIED')}"
        lines.append(line)
    return "\n".join(lines)

def send_webhook_json(
    url: str,
    payload: Dict,
    *,
    timeout: float = 6.0,
    secret: Optional[str] = None,
) -> Tuple[bool, str]:
    body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "SDKKit-Webhook/1.0",
    }
    if secret:
        headers["X-SDKKit-Secret"] = secret

    req = request.Request(url, data=body, headers=headers, method="POST")
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            code = getattr(resp, "status", None) or resp.getcode()
            text = resp.read(200).decode("utf-8", errors="ignore").strip()
            if text:
                return (200 <= code < 300), f"HTTP {code} {text[:120]}"
            return (200 <= code < 300), f"HTTP {code}"
    except error.HTTPError as exc:
        try:
            text = exc.read(200).decode("utf-8", errors="ignore").strip()
        except Exception:
            text = ""
        return False, f"HTTP {exc.code} {text}".strip()
    except Exception as exc:
        return False, str(exc)

def _is_discord_webhook_url(url: str) -> bool:
    try:
        parsed = urlparse(url.strip())
    except Exception:
        return False
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    if not host:
        return False
    if "discord.com" not in host and "discordapp.com" not in host:
        return False
    return "/api/webhooks/" in path

def _discord_url_with_wait(url: str) -> str:
    parsed = urlparse(url.strip())
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query["wait"] = "true"
    return urlunparse(parsed._replace(query=urlencode(query)))

def _discord_message_edit_url(url: str, message_id: str) -> str:
    parsed = urlparse(url.strip())
    base_path = parsed.path.rstrip("/")
    message_path = f"{base_path}/messages/{message_id.strip()}"
    return urlunparse(parsed._replace(path=message_path))

def _chunk_embed_lines(lines: List[str], *, max_chars: int = 960, max_lines: int = 12) -> List[str]:
    chunks: List[str] = []
    current: List[str] = []
    current_len = 0
    for line in lines:
        add_len = len(line) + (1 if current else 0)
        if current and (current_len + add_len > max_chars or len(current) >= max_lines):
            chunks.append("\n".join(current))
            current = [line]
            current_len = len(line)
        else:
            current.append(line)
            current_len += add_len
    if current:
        chunks.append("\n".join(current))
    return chunks

def _compact_health_reason(health_status: str) -> str:
    text = str(health_status or "").strip()
    if not text:
        return "health check failed"
    friendly = {
        "INCOMPLETE": "health incomplete",
        "LOW": "low confidence",
        "MEDIUM": "medium confidence",
        "WARNINGS": "warnings found",
    }
    upper = text.upper()
    if upper.startswith("NOT VERIFIED"):
        stripped = text[len("NOT VERIFIED"):].strip().strip(" -")
        if stripped.startswith("(") and stripped.endswith(")"):
            stripped = stripped[1:-1].strip()
        if not stripped:
            return "health check failed"
        return friendly.get(stripped.upper(), stripped)
    return friendly.get(text.upper(), text)

def _display_name(item: Dict[str, object]) -> str:
    label = str(item.get("game_label", "") or "").strip()
    if label:
        return label
    return _pretty_game_label(str(item.get("game", "Unknown") or "Unknown"))

def _build_simple_lines(statuses: List[Dict[str, object]]) -> Tuple[List[str], List[str], int]:
    verified_lines: List[str] = []
    not_verified_lines: List[str] = []
    verified_unknown = 0

    for item in statuses:
        if not isinstance(item, dict):
            continue
        name = _display_name(item)
        status = str(item.get("status", "UNKNOWN") or "UNKNOWN").upper()
        health_verified = bool(item.get("health_verified", False))

        if not health_verified:
            reason = _compact_health_reason(str(item.get("health_status", "") or ""))
            not_verified_lines.append(f"- **{name}** - {reason}")
            continue

        if status == "DATED":
            latest = str(item.get("latest_update_display", "") or "").strip()
            if latest and latest != "unknown":
                not_verified_lines.append(f"- **{name}** - outdated, latest {latest}")
            else:
                not_verified_lines.append(f"- **{name}** - outdated")
            continue

        verified_lines.append(f"- **{name}**")
        if status == "UNKNOWN":
            verified_unknown += 1

    return verified_lines, not_verified_lines, verified_unknown

def _build_detailed_groups(
    statuses: List[Dict[str, object]]
) -> Tuple[List[str], List[str], List[str], int, int, int]:
    current_lines: List[str] = []
    verified_unknown_lines: List[str] = []
    attention_lines: List[str] = []
    up_to_date = 0
    dated = 0
    unknown = 0

    for item in statuses:
        if not isinstance(item, dict):
            continue
        name = _display_name(item)
        status = str(item.get("status", "UNKNOWN") or "UNKNOWN").upper()
        health_verified = bool(item.get("health_verified", False))
        age = str(item.get("dump_age_display", "") or "").strip()
        latest = str(item.get("latest_update_display", "") or "").strip()

        if status == "UP TO DATE":
            up_to_date += 1
        elif status == "DATED":
            dated += 1
        else:
            unknown += 1

        if not health_verified:
            reason = _compact_health_reason(str(item.get("health_status", "") or ""))
            if age:
                attention_lines.append(f"- **{name}** - Not Verified ({reason}, {age})")
            else:
                attention_lines.append(f"- **{name}** - Not Verified ({reason})")
            continue

        if status == "DATED":
            extras = []
            if latest and latest != "unknown":
                extras.append(f"latest {latest}")
            if age:
                extras.append(age)
            detail = ", ".join(extras) if extras else "outdated"
            attention_lines.append(f"- **{name}** - Update Needed ({detail})")
            continue

        if status == "UP TO DATE":
            if age:
                current_lines.append(f"- **{name}** - Verified & Current ({age})")
            else:
                current_lines.append(f"- **{name}** - Verified & Current")
            continue

        if age:
            verified_unknown_lines.append(f"- **{name}** - Verified Dump ({age}, update date unknown)")
        else:
            verified_unknown_lines.append(f"- **{name}** - Verified Dump (update date unknown)")

    return current_lines, verified_unknown_lines, attention_lines, up_to_date, dated, unknown

def _build_discord_status_payload_v2(
    status_board: str,
    payload: Dict,
    *,
    mode: str = _WEBHOOK_MODE_SIMPLE,
) -> Dict:
    statuses = payload.get("statuses", []) if isinstance(payload, dict) else []
    if not isinstance(statuses, list):
        statuses = []

    mode = _normalize_webhook_mode(mode)
    embed = {
        "title": "Offset Status",
        "color": 0xE67E22,
        "fields": [],
        "footer": {"text": "SDKKit webhook status board (auto-updated)"},
    }

    sent_at = str(payload.get("sent_at", "") or "").strip()
    if sent_at:
        embed["timestamp"] = sent_at

    if mode == _WEBHOOK_MODE_SIMPLE:
        verified_lines, not_verified_lines, verified_unknown = _build_simple_lines(statuses)
        embed["description"] = "\n".join(
            [
                f"Tracked dumps: **{len(statuses)}**",
                f"Verified: **{len(verified_lines)}**",
                f"Not Verified: **{len(not_verified_lines)}**",
                f"Update dates unknown: **{verified_unknown}**",
            ]
        )

        if not_verified_lines:
            for idx, chunk in enumerate(_chunk_embed_lines(not_verified_lines), start=1):
                name = "Not Verified" if len(not_verified_lines) <= 12 else f"Not Verified ({idx})"
                embed["fields"].append({"name": name, "value": chunk, "inline": False})
        else:
            embed["fields"].append(
                {
                    "name": "Not Verified",
                    "value": "All tracked dumps passed verification.",
                    "inline": False,
                }
            )

        if verified_lines:
            for idx, chunk in enumerate(_chunk_embed_lines(verified_lines), start=1):
                name = "Verified" if len(verified_lines) <= 12 else f"Verified ({idx})"
                embed["fields"].append({"name": name, "value": chunk, "inline": False})

        if not not_verified_lines and verified_unknown == 0 and verified_lines:
            embed["color"] = 0x2ECC71
        elif not_verified_lines:
            embed["color"] = 0xD35454
    else:
        (
            current_lines,
            verified_unknown_lines,
            attention_lines,
            up_to_date,
            dated,
            unknown,
        ) = _build_detailed_groups(statuses)
        embed["description"] = "\n".join(
            [
                f"Tracked dumps: **{len(statuses)}**",
                f"Verified & current: **{len(current_lines)}**",
                f"Verified, update unknown: **{len(verified_unknown_lines)}**",
                f"Needs attention: **{len(attention_lines)}**",
            ]
        )

        if attention_lines:
            for idx, chunk in enumerate(_chunk_embed_lines(attention_lines), start=1):
                name = "Needs Attention" if len(attention_lines) <= 12 else f"Needs Attention ({idx})"
                embed["fields"].append({"name": name, "value": chunk, "inline": False})
        if verified_unknown_lines:
            for idx, chunk in enumerate(_chunk_embed_lines(verified_unknown_lines), start=1):
                name = "Verified, Update Unknown" if len(verified_unknown_lines) <= 12 else f"Verified, Update Unknown ({idx})"
                embed["fields"].append({"name": name, "value": chunk, "inline": False})
        if current_lines:
            for idx, chunk in enumerate(_chunk_embed_lines(current_lines), start=1):
                name = "Verified & Current" if len(current_lines) <= 12 else f"Verified & Current ({idx})"
                embed["fields"].append({"name": name, "value": chunk, "inline": False})

        if not embed["fields"]:
            fallback = (status_board or "").strip() or "No games found."
            if len(fallback) > 950:
                fallback = fallback[:947] + "..."
            embed["fields"].append({"name": "Status", "value": fallback, "inline": False})

        if dated == 0 and not attention_lines and unknown == 0 and current_lines:
            embed["color"] = 0x2ECC71
        elif attention_lines:
            embed["color"] = 0xD35454

    return {
        "content": "",
        "embeds": [embed],
        "allowed_mentions": {"parse": []},
    }

def _build_discord_status_payload(status_board: str, payload: Dict) -> Dict:
    meta = payload.get("metadata", {}) if isinstance(payload, dict) else {}
    process = str(meta.get("process", "") or payload.get("process", "") or "").strip()
    engine = str(meta.get("engine", "") or payload.get("engine", "") or "").strip()
    statuses = payload.get("statuses", []) if isinstance(payload, dict) else []
    if not isinstance(statuses, list):
        statuses = []

    title = "Offset Status"

    up_to_date = 0
    dated = 0
    unknown = 0
    verified = 0
    unverified = 0
    not_verified = 0

    clean_lines: List[str] = []
    verified_unknown_lines: List[str] = []
    attention_lines: List[str] = []
    unknown_lines: List[str] = []

    def _line_for(item: Dict[str, object], label: str) -> str:
        game = str(item.get("game", "Unknown") or "Unknown")
        age = str(item.get("dump_age_display", "") or "--")
        status_text = str(item.get("status", "UNKNOWN") or "UNKNOWN").replace("_", " ").title()
        extras = [age]
        if label == "Verified Dump":
            extras.append("update date unknown")
        elif label == "Update Needed":
            latest = str(item.get("latest_update_display", "") or "")
            if latest:
                extras.append(f"latest {latest}")
        return f"• **{game}** — {label} ({', '.join(extras)})"

    for item in statuses:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status", "UNKNOWN") or "UNKNOWN").upper()
        trust = str(item.get("verification_status", "UNKNOWN") or "UNKNOWN").upper()

        if status == "UP TO DATE":
            up_to_date += 1
        elif status == "DATED":
            dated += 1
        else:
            unknown += 1

        if trust == "VERIFIED":
            verified += 1
        elif trust == "UNVERIFIED":
            unverified += 1
        elif trust == "NOT VERIFIED":
            not_verified += 1

        health_verified = bool(item.get("health_verified", False))

        if status == "UP TO DATE" and trust == "VERIFIED":
            clean_lines.append(_line_for(item, "Verified & Current"))
        elif health_verified and status == "UNKNOWN":
            verified_unknown_lines.append(_line_for(item, "Verified Dump"))
        elif status == "DATED":
            attention_lines.append(_line_for(item, "Update Needed"))
        elif trust == "NOT VERIFIED":
            attention_lines.append(_line_for(item, "Not Verified"))
        else:
            unknown_lines.append(_line_for(item, "Needs Review"))

    def _chunk_lines(lines: List[str], *, max_chars: int = 960, max_lines: int = 12) -> List[str]:
        chunks: List[str] = []
        current: List[str] = []
        current_len = 0
        for line in lines:
            add_len = len(line) + (1 if current else 0)
            if current and (current_len + add_len > max_chars or len(current) >= max_lines):
                chunks.append("\n".join(current))
                current = [line]
                current_len = len(line)
            else:
                current.append(line)
                current_len += add_len
        if current:
            chunks.append("\n".join(current))
        return chunks

    summary_lines = [
        f"Total games: **{len(statuses)}**",
        f"Verified & current: **{len(clean_lines)}**",
        f"Verified, update unknown: **{len(verified_unknown_lines)}**",
        f"Needs attention: **{len(attention_lines) + len(unknown_lines)}**",
        f"Offsets: `UP TO DATE {up_to_date}` | `DATED {dated}` | `UNKNOWN {unknown}`",
    ]
    if process and process.lower() != "unknown":
        summary_lines.insert(0, f"Process: `{process}`")
    summary = "\n".join(summary_lines)

    color = 0xE67E22
    if dated == 0 and len(attention_lines) == 0 and len(unknown_lines) == 0 and len(clean_lines) > 0:
        color = 0x2ECC71
    elif len(attention_lines) > 0:
        color = 0xD35454

    embed = {
        "title": title,
        "description": summary,
        "color": color,
        "fields": [],
        "footer": {"text": "SDKKit webhook status board (auto-updated)"},
    }

    sent_at = str(payload.get("sent_at", "") or "").strip()
    if sent_at:
        embed["timestamp"] = sent_at

    attention_chunks = _chunk_lines(attention_lines + unknown_lines)
    verified_unknown_chunks = _chunk_lines(verified_unknown_lines)
    clean_chunks = _chunk_lines(clean_lines)

    max_fields = 6
    field_count = 0
    hidden_sections = 0

    for idx, chunk in enumerate(attention_chunks, start=1):
        if field_count >= max_fields:
            hidden_sections += 1
            continue
        name = "Needs Attention" if len(attention_chunks) == 1 else f"Needs Attention ({idx}/{len(attention_chunks)})"
        embed["fields"].append(
            {
                "name": name,
                "value": chunk,
                "inline": False,
            }
        )
        field_count += 1

    for idx, chunk in enumerate(verified_unknown_chunks, start=1):
        if field_count >= max_fields:
            hidden_sections += 1
            continue
        name = (
            "Verified, Update Unknown"
            if len(verified_unknown_chunks) == 1
            else f"Verified, Update Unknown ({idx}/{len(verified_unknown_chunks)})"
        )
        embed["fields"].append(
            {
                "name": name,
                "value": chunk,
                "inline": False,
            }
        )
        field_count += 1

    for idx, chunk in enumerate(clean_chunks, start=1):
        if field_count >= max_fields:
            hidden_sections += 1
            continue
        name = "Verified & Current" if len(clean_chunks) == 1 else f"Verified & Current ({idx}/{len(clean_chunks)})"
        embed["fields"].append(
            {
                "name": name,
                "value": chunk,
                "inline": False,
            }
        )
        field_count += 1

    if not embed["fields"]:
        fallback = (status_board or "").strip() or "No games found."
        if len(fallback) > 950:
            fallback = fallback[:947] + "..."
        embed["fields"].append(
            {
                "name": "Status",
                "value": fallback,
                "inline": False,
            }
        )

    if hidden_sections > 0:
        embed["fields"].append(
            {
                "name": "Notice",
                "value": f"Output truncated to keep embed readable ({hidden_sections} extra section(s) hidden).",
                "inline": False,
            }
        )

    return {
        "content": "",
        "embeds": [embed],
        "allowed_mentions": {"parse": []},
    }

def send_or_update_webhook_status(
    url: str,
    payload: Dict,
    *,
    status_board: str,
    timeout: float = 6.0,
    previous_message_id: str = "",
    mode: str = _WEBHOOK_MODE_SIMPLE,
) -> Tuple[bool, str, str]:
    if not _is_discord_webhook_url(url):
        ok, detail = send_webhook_json(url, payload, timeout=timeout)
        return ok, detail, ""

    body = json.dumps(
        _build_discord_status_payload_v2(status_board, payload, mode=mode),
        ensure_ascii=True,
    ).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "SDKKit-Webhook/1.0",
    }

    def _send(req_url: str, method: str) -> Tuple[bool, str, str]:
        req = request.Request(req_url, data=body, headers=headers, method=method)
        try:
            with request.urlopen(req, timeout=timeout) as resp:
                code = getattr(resp, "status", None) or resp.getcode()
                raw = resp.read(4096).decode("utf-8", errors="ignore")
                msg_id = ""
                try:
                    parsed = json.loads(raw) if raw.strip() else {}
                    if isinstance(parsed, dict):
                        msg_id = str(parsed.get("id", "") or "").strip()
                except Exception:
                    msg_id = ""
                text = raw.strip()
                if text:
                    return (200 <= code < 300), f"HTTP {code} {text[:120]}", msg_id
                return (200 <= code < 300), f"HTTP {code}", msg_id
        except error.HTTPError as exc:
            try:
                text = exc.read(200).decode("utf-8", errors="ignore").strip()
            except Exception:
                text = ""
            return False, f"HTTP {exc.code} {text}".strip(), ""
        except Exception as exc:
            return False, str(exc), ""

    previous = str(previous_message_id or "").strip()
    if previous:
        ok, detail, msg_id = _send(_discord_message_edit_url(url, previous), "PATCH")
        if ok:
            return True, detail, msg_id or previous
        if "HTTP 404" not in detail:
            return False, detail, previous

    ok, detail, msg_id = _send(_discord_url_with_wait(url), "POST")
    return ok, detail, msg_id
