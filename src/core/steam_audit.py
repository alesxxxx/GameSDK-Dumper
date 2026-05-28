
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from html import unescape
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import psutil
from typing import Dict, Iterable, Iterator, List, Optional, Tuple
from urllib.parse import quote
from urllib.request import Request, urlopen

from src.core.pe_parser import get_unity_version_from_pe
from src.engines.ue.detector import detect_engine

_STEAM_LIBRARY_FILE = Path("steamapps") / "libraryfolders.vdf"
_STEAM_LOGINUSERS_FILE = Path("config") / "loginusers.vdf"
_STEAM_APPINFO_FILE = Path("appcache") / "appinfo.vdf"
_APPMANIFEST_RE = re.compile(r"appmanifest_(\d+)\.acf$", re.IGNORECASE)
_HTTP_TIMEOUT = 10
_OWNED_SCAN_TIMEOUT = 180
_AWACY_DATASET_URL = (
    "https://raw.githubusercontent.com/AreWeAntiCheatYet/AreWeAntiCheatYet/master/games.json"
)
_AWACY_CACHE_TTL = 60 * 60 * 24
_LOCAL_STEAM_METADATA_CACHE_TTL = 60 * 60 * 6
_STEAMDB_FILE_PATTERNS = {
    "UnityEngine.dll": "unity_unknown",
    "UnityPlayer.dll": "unity_unknown", 
    "il2cpp_data": "il2cpp",
    "Mono.Posix.dll": "mono",
    "Mono.Security.dll": "mono",
    
    "Engine/Binaries/Win64": "ue_unknown",
    "Engine/Content": "ue_unknown",
    "UE4Editor.exe": "ue4",
    "UE5Editor.exe": "ue5",
    "UnrealEd.exe": "ue_unknown",
    
    "options.ini": "gamemaker",
    "data.win": "gamemaker", 
    "snd_": "gamemaker",
    
    "hl2.exe": "source",
    "engine2.dll": "source_2",
    "client.dll": "source",
    
    "CryEngine.exe": "cryengine",
    "CrySystem.dll": "cryengine",
    "engine.pak": "cryengine",
    
    "RPG_RT.exe": "rpg_maker",
    "RPG_RT.ini": "rpg_maker",
    "RPGVXAce.exe": "rpg_maker",
    
    "Adobe AIR.dll": "avm2",
    ".swf": "avm2",
    ".swz": "avm2",
    
    "godot": "godot",
    "engine.pck": "godot",
    
    "renpy": "renpy",
    ".rpy": "renpy",
    ".rpyc": "renpy",
}

_STEAMDB_ANTICHEAT_PATTERNS = {
    "easyanticheat.exe": "Easy Anti-Cheat",
    "easyanticheat_x64.dll": "Easy Anti-Cheat",
    "easyanticheat_eos_setup.exe": "Easy Anti-Cheat (EOS)",
    "beclient_x64.dll": "BattlEye",
    "beservice.exe": "BattlEye",
    "belauncher.exe": "BattlEye",
    "equ8.dll": "EQU8",
    "vgk.sys": "Riot Vanguard",
    "vgc.exe": "Riot Vanguard", 
    "xigncode3.dll": "XIGNCODE3",
    "npggnt.des": "nProtect GameGuard",
    "gameguard.des": "nProtect GameGuard",
    "mhyprot2.sys": "mhyprot2",
    "fairfight.dll": "FairFight",
    "denuvo": "Denuvo Anti-Cheat",
    "eaclauncher.exe": "EA Javelin",
}
_HTTP_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/137.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
}
_PCGW_HTTP_HEADERS = {
    **_HTTP_HEADERS,
    "Referer": "https://www.pcgamingwiki.com/",
}
_WIKI_HTTP_HEADERS = {
    **_HTTP_HEADERS,
    "Referer": "https://en.wikipedia.org/",
}
_WIKIDATA_HTTP_HEADERS = {
    **_HTTP_HEADERS,
    "Referer": "https://www.wikidata.org/",
}
_AWACY_HTTP_HEADERS = {
    **_HTTP_HEADERS,
    "Referer": "https://github.com/AreWeAntiCheatYet/AreWeAntiCheatYet",
}
_METADATA_CACHE_VERSION = 4
_STORE_CACHE_TTL = 60 * 60 * 24 * 7
_PCGW_CACHE_TTL = 60 * 60 * 24 * 14
_WIKI_CACHE_TTL = 60 * 60 * 24 * 14
_STEAM_APPINFO_MAGIC_V41 = 0x07564429
_STEAM_APPINFO_BINARY_OFFSET_V41 = 65
_OWNED_LIBRARY_TYPES = {"game"}
_SKIP_EXECUTABLE_NAMES = {
    "unitycrashhandler64.exe",
    "unitycrashhandler32.exe",
    "unitycrashhandler.exe",
    "eaclauncher.exe",
    "eadesktop.exe",
    "start_protected_game.exe",
    "unins000.exe",
    "ucrtbase.exe",
}
_ANTI_CHEAT_FILE_MARKERS = {
    "easyanticheat_eos_setup.exe": "Easy Anti-Cheat (EOS)",
    "easyanticheat.exe": "Easy Anti-Cheat",
    "easyanticheat_x64.dll": "Easy Anti-Cheat",
    "eaclauncher.exe": "Easy Anti-Cheat",
    "start_protected_game.exe": "Easy Anti-Cheat",
    "beclient_x64.dll": "BattlEye",
    "beclient.dll": "BattlEye",
    "beservice.exe": "BattlEye",
    "belauncher.exe": "BattlEye",
    "equ8.dll": "EQU8",
    "equ8_launcher.exe": "EQU8",
    "vgk.sys": "Riot Vanguard",
    "vgc.exe": "Riot Vanguard",
    "xigncode3.dll": "XIGNCODE3",
    "x3.xem": "XIGNCODE3",
    "npggnt.des": "nProtect GameGuard",
    "gameguard.des": "nProtect GameGuard",
    "mhyprot2.sys": "mhyprot2",
}
_REMOTE_ANTI_CHEAT_MARKERS = {
    "easy anti-cheat (eos)": "Easy Anti-Cheat (EOS)",
    "easy anti-cheat": "Easy Anti-Cheat",
    "easyanticheat": "Easy Anti-Cheat",
    "ea anticheat": "EA Javelin",
    "ea anti-cheat": "EA Javelin",
    "ea javelin": "EA Javelin",
    "battleye": "BattlEye",
    "byfron": "Byfron",
    "xigncode": "XIGNCODE3",
    "gameguard": "nProtect GameGuard",
    "vanguard": "Riot Vanguard",
    "equ8": "EQU8",
    "mhyprot2": "mhyprot2",
    "punkbuster": "PunkBuster",
    "fairfight": "FairFight",
    "hyperion": "Hyperion",
    "netease anti-cheat expert": "Netease Anti-Cheat Expert",
    "netease anticheat expert": "Netease Anti-Cheat Expert",
    "nexon game security": "Nexon Game Security",
}
_ANTI_CHEAT_NAME_ALIASES = {
    "easy anti-cheat (eos)": "Easy Anti-Cheat (EOS)",
    "easy anti-cheat": "Easy Anti-Cheat",
    "easy anti cheat": "Easy Anti-Cheat",
    "easyanticheat": "Easy Anti-Cheat",
    "ea anticheat": "EA Javelin",
    "ea anti-cheat": "EA Javelin",
    "ea javelin": "EA Javelin",
    "battleye": "BattlEye",
    "byfron": "Byfron",
    "vac": "VAC",
    "valve anti-cheat": "VAC",
    "valve anti cheat": "VAC",
    "riot vanguard": "Riot Vanguard",
    "xigncode3": "XIGNCODE3",
    "nprotect gameguard": "nProtect GameGuard",
    "gameguard": "nProtect GameGuard",
    "mhyprot2": "mhyprot2",
    "equ8": "EQU8",
    "fairfight": "FairFight",
    "punkbuster": "PunkBuster",
    "hyperion": "Hyperion",
    "netease anti-cheat expert": "Netease Anti-Cheat Expert",
    "nexon game security": "Nexon Game Security",
}
_UNITY_DLL_SKIP_NAMES = {
    "steam_api64.dll",
    "steam_api.dll",
    "unityplayer.dll",
    "d3d11.dll",
    "d3d12.dll",
    "dxgi.dll",
    "xinput1_3.dll",
    "xinput1_4.dll",
}
_KERNEL_RECOMMENDED_ANTI_CHEATS = {
    "Easy Anti-Cheat",
    "Easy Anti-Cheat (EOS)",
    "BattlEye",
    "Riot Vanguard",
    "XIGNCODE3",
    "nProtect GameGuard",
    "EQU8",
    "mhyprot2",
}
_SUPPORTED_ENGINES = {"ue4", "ue5", "ue_unknown", "il2cpp", "mono", "unity_unknown"}
_GENERIC_ENGINE_IDS = {"ue_unknown", "unity_unknown"}
_NON_GAME_APPIDS = {228980}
_LOCAL_ENGINE_APPID_OVERRIDES = {
    223350: ("enfusion", "", "appid_override"),
    287700: ("fox_engine", "", "appid_override"),
    2483190: ("forzatech", "", "appid_override"),
    3199170: ("ue5", "", "appid_override"),
}
_REMOTE_ENGINE_APPID_OVERRIDES = {
    1245620: ("fromsoftware_engine", "", "remote_appid_override"),
    2483190: ("forzatech", "", "remote_appid_override"),
    244210: ("proprietary_engine", "", "remote_appid_override"),
    322330: ("proprietary_engine", "", "remote_appid_override"),
    374320: ("fromsoftware_engine", "", "remote_appid_override"),
    427520: ("proprietary_engine", "", "remote_appid_override"),
    596350: ("ue3", "", "remote_appid_override"),
    1276390: ("il2cpp", "", "remote_appid_override"),
    1283700: ("ue5", "", "remote_appid_override"),
    1593500: ("proprietary_engine", "", "remote_appid_override"),
    1625450: ("il2cpp", "", "remote_appid_override"),
    2140510: ("il2cpp", "", "remote_appid_override"),
    2215430: ("proprietary_engine", "", "remote_appid_override"),
    2357570: ("proprietary_engine", "", "remote_appid_override"),
    238960: ("proprietary_engine", "", "remote_appid_override"),
    275850: ("proprietary_engine", "", "remote_appid_override"),
    289070: ("proprietary_engine", "", "remote_appid_override"),
    1295660: ("proprietary_engine", "", "remote_appid_override"),
    233450: ("proprietary_engine", "", "remote_appid_override"),
}
_EXTERNAL_ENGINE_ALIASES = {
    "bang!": ("bang", "", "pcgw_engine_infobox"),
    "adventure game studio": ("adventure_game_studio", "", "pcgw_engine_infobox"),
    "visionaire": ("visionaire", "", "pcgw_engine_infobox"),
    "lwjgl": ("lwjgl", "", "pcgw_engine_infobox"),
    "xna": ("xna", "", "pcgw_engine_infobox"),
    "fna": ("fna", "", "pcgw_engine_infobox"),
    "smartsim": ("smartsim", "", "pcgw_engine_infobox"),
    "liquid": ("liquid", "", "pcgw_engine_infobox"),
    "godot": ("godot", "", "pcgw_engine_infobox"),
    "evolution (digital extremes)": ("evolution_engine", "", "pcgw_engine_infobox"),
    "messiah engine": ("messiah_engine", "", "pcgw_engine_infobox"),
    "renderware": ("renderware", "", "pcgw_engine_infobox"),
    "black desert engine": ("black_desert_engine", "", "pcgw_engine_infobox"),
    "tiger engine": ("tiger_engine", "", "pcgw_engine_infobox"),
    "proprietary engine": ("proprietary_engine", "", "wikidata_engine_property"),
    "custom engine": ("proprietary_engine", "", "wikidata_engine_property"),
    "in-house engine": ("proprietary_engine", "", "wikidata_engine_property"),
}
_ENGINE_HINTS = (
    (re.compile(r"\bunreal engine 5(?:\.\d+)?\b|\bue5\b", re.IGNORECASE), "ue5", ""),
    (re.compile(r"\bunreal engine 4(?:\.\d+)?\b|\bue4\b", re.IGNORECASE), "ue4", ""),
    (re.compile(r"\bunreal engine\b", re.IGNORECASE), "ue_unknown", ""),
    (re.compile(r"\bil2cpp\b", re.IGNORECASE), "il2cpp", ""),
    (re.compile(r"\bunity\b.*\bmono\b|\bmono\b.*\bunity\b", re.IGNORECASE), "mono", ""),
    (re.compile(r"\bunity\b", re.IGNORECASE), "unity_unknown", ""),
    (re.compile(r"\bsource 2\b", re.IGNORECASE), "source_2", ""),
    (re.compile(r"\bgoldsrc\b|\bhalf-life engine\b", re.IGNORECASE), "goldsrc", ""),
    (re.compile(r"\bsource engine\b|\bvalve'?s source\b", re.IGNORECASE), "source", ""),
    (re.compile(r"\biw(?: |-)?engine\b", re.IGNORECASE), "iw_engine", ""),
    (re.compile(r"\bred ?engine\b", re.IGNORECASE), "redengine", ""),
    (re.compile(r"\bre engine\b", re.IGNORECASE), "re_engine", ""),
    (re.compile(r"\bmt framework\b", re.IGNORECASE), "mt_framework", ""),
    (re.compile(r"\bcryengine(?:\s*v)?\b", re.IGNORECASE), "cryengine", ""),
    (re.compile(r"\bgame ?maker(?: studio(?: 2)?)?\b", re.IGNORECASE), "gamemaker", ""),
    (re.compile(r"\bren'?py\b", re.IGNORECASE), "renpy", ""),
    (re.compile(r"\brpg maker(?: [a-z0-9+._-]+)?\b", re.IGNORECASE), "rpg_maker", ""),
    (re.compile(r"\bmono ?game\b", re.IGNORECASE), "monogame", ""),
    (re.compile(r"\belectron\b", re.IGNORECASE), "electron", ""),
    (re.compile(r"\badobe air\b|\bactionscript 3\b|\bflash\/air\b", re.IGNORECASE), "avm2", ""),
    (re.compile(r"\bavm2\b", re.IGNORECASE), "avm2", ""),
    (re.compile(r"\bfox engine\b", re.IGNORECASE), "fox_engine", ""),
    (re.compile(r"\bessence engine\b|\bessence\b", re.IGNORECASE), "essence", ""),
    (re.compile(r"\bcardinal\b", re.IGNORECASE), "cardinal", ""),
    (re.compile(r"\banvil(?:next)?\b", re.IGNORECASE), "anvil", ""),
    (re.compile(r"\bforge\b", re.IGNORECASE), "forge", ""),
    (re.compile(r"\bcreation engine\b", re.IGNORECASE), "creation_engine", ""),
    (re.compile(r"\bgamebryo\b|\btes engine\b", re.IGNORECASE), "gamebryo", ""),
    (re.compile(r"\bforzatech\b", re.IGNORECASE), "forzatech", ""),
    (re.compile(r"\bneox\b", re.IGNORECASE), "neox", ""),
    (re.compile(r"\bnitrous\b", re.IGNORECASE), "nitrous", ""),
    (re.compile(r"\bdiesel\b", re.IGNORECASE), "diesel", ""),
    (re.compile(r"\bclausewitz\b", re.IGNORECASE), "clausewitz", ""),
    (re.compile(r"\bdivinity engine\b", re.IGNORECASE), "divinity_engine", ""),
    (re.compile(r"\bfirebird engine\b", re.IGNORECASE), "firebird_engine", ""),
    (re.compile(r"\bfallout engine\b", re.IGNORECASE), "fallout_engine", ""),
    (re.compile(r"\bcathode\b", re.IGNORECASE), "cathode", ""),
    (re.compile(r"\bbang!\b", re.IGNORECASE), "bang", ""),
    (re.compile(r"\bgfd\b", re.IGNORECASE), "gfd", ""),
    (re.compile(r"\bctg\b", re.IGNORECASE), "ctg", ""),
    (re.compile(r"\basura\b", re.IGNORECASE), "asura", ""),
    (re.compile(r"\bholistic\b", re.IGNORECASE), "holistic", ""),
    (re.compile(r"\bdagor engine\b", re.IGNORECASE), "dagor_engine", ""),
    (re.compile(r"\bscumm\b", re.IGNORECASE), "scumm", ""),
    (re.compile(r"\benfusion\b", re.IGNORECASE), "enfusion", ""),
)
_PCGW_ENGINE_ROW_RE = re.compile(r"\{\{Infobox game/row/engine\|([^|}]+)", re.IGNORECASE)
_PCGW_ANTI_CHEAT_RE = re.compile(r"^\|\s*anticheat\s*=\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_WIKIPEDIA_ENGINE_ROW_RE = re.compile(
    r"^\|\s*(?:engine|game_engine)\s*=\s*([^\r\n]*)",
    re.IGNORECASE | re.MULTILINE,
)
_SUPPORT_PRIORITY = {
    "usermode_ready": 0,
    "kernel_recommended": 1,
    "install_then_scan": 2,
    "install_then_kernel": 3,
    "engine_identified": 4,
    "install_engine_identified": 5,
    "manual_review": 6,
}
_AWACY_DATASET_MEMO: Optional[List[Dict[str, object]]] = None

@dataclass
class SteamAccount:
    steamid: str
    account_name: str = ""
    persona_name: str = ""
    most_recent: bool = False

@dataclass
class SteamInstalledGame:
    appid: int
    name: str
    library_path: str
    install_dir: str
    manifest_path: str
    executable_path: str = ""
    engine: str = "unknown"
    version: str = ""
    detection_method: str = "none"
    confidence: str = "low"
    anti_cheats: List[str] = field(default_factory=list)
    kernel_recommended: bool = False
    likely_dumpable: bool = False
    support_tier: str = "manual_review"
    evidence: List[str] = field(default_factory=list)
    installed: bool = True
    owned_on_account: bool = False
    scan_source: str = "installed_disk"
    support_score: int = 0
    diagnostic_summary: str = ""
    next_step: str = ""
    diagnostic_flags: List[str] = field(default_factory=list)
    store_url: str = ""

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)

@dataclass
class SteamAuditReport:
    steam_path: str
    libraries: List[str]
    accounts: List[SteamAccount]
    games: List[SteamInstalledGame]
    audit_mode: str = "installed"
    steamid: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "steam_path": self.steam_path,
            "libraries": list(self.libraries),
            "accounts": [asdict(account) for account in self.accounts],
            "audit_mode": self.audit_mode,
            "steamid": self.steamid,
            "games": [game.to_dict() for game in self.games],
            "summary": {
                "total_games": len(self.games),
                "installed_games": sum(1 for game in self.games if game.installed),
                "owned_only_games": sum(1 for game in self.games if not game.installed),
                "usermode_ready": sum(1 for game in self.games if game.support_tier == "usermode_ready"),
                "kernel_recommended": sum(1 for game in self.games if game.support_tier == "kernel_recommended"),
                "needs_install": sum(
                    1 for game in self.games
                    if game.support_tier in {"install_then_scan", "install_then_kernel"}
                ),
                "engine_identified": sum(
                    1 for game in self.games
                    if game.support_tier in {"engine_identified", "install_engine_identified"}
                ),
                "manual_review": sum(1 for game in self.games if game.support_tier == "manual_review"),
            },
        }

def _unescape_vdf_string(value: str) -> str:
    return value.replace("\\\\", "\\")

def parse_vdf_text(text: str) -> Dict[str, object]:
    token_re = re.compile(r'"((?:\\.|[^"\\])*)"|([{}])')
    tokens: List[str] = []
    for match in token_re.finditer(text):
        quoted, brace = match.groups()
        if brace:
            tokens.append(brace)
        elif quoted is not None:
            tokens.append(_unescape_vdf_string(quoted))

    if not tokens:
        return {}

    root: Dict[str, object] = {}
    stack: List[Dict[str, object]] = [root]
    pending_key: Optional[str] = None
    idx = 0
    while idx < len(tokens):
        token = tokens[idx]
        if token == "{":
            new_obj: Dict[str, object] = {}
            if pending_key is not None:
                stack[-1][pending_key] = new_obj
                pending_key = None
            stack.append(new_obj)
            idx += 1
            continue
        if token == "}":
            if len(stack) > 1:
                stack.pop()
            pending_key = None
            idx += 1
            continue

        next_token = tokens[idx + 1] if idx + 1 < len(tokens) else None
        if next_token == "{":
            pending_key = token
            idx += 1
            continue

        if next_token not in (None, "{", "}"):
            stack[-1][token] = next_token
            idx += 2
            continue

        stack[-1][token] = ""
        idx += 1

    return root

def _read_vdf_file(path: Path) -> Dict[str, object]:
    try:
        return parse_vdf_text(path.read_text(encoding="utf-8", errors="ignore"))
    except OSError:
        return {}

def _fetch_json_payload(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    max_retries: int = 3,
) -> object:
    for attempt in range(max_retries):
        try:
            request = Request(url, headers={**_HTTP_HEADERS, **(headers or {})})
            with urlopen(request, timeout=_HTTP_TIMEOUT) as response:
                payload = response.read().decode("utf-8", errors="ignore")
            return json.loads(payload)
        except Exception as e:
            if attempt == max_retries - 1:
                print(f"Warning: Failed to fetch {url} after {max_retries} attempts: {e}")
                return {}
            time.sleep(1 * (attempt + 1))
    return {}

def _fetch_json(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    max_retries: int = 3,
) -> Dict[str, object]:
    payload = _fetch_json_payload(url, headers=headers, max_retries=max_retries)
    return payload if isinstance(payload, dict) else {}

def _runtime_root() -> Path:
    if getattr(sys, "_MEIPASS", None):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parents[2]

def _steam_cache_root() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA") or str(Path.home())
    cache_root = Path(local_app_data) / "GameSDKKit"
    cache_root.mkdir(parents=True, exist_ok=True)
    return cache_root

def _metadata_cache_path(name: str) -> Path:
    return _steam_cache_root() / f"steam_audit_{name}_cache.json"

def _load_metadata_cache(name: str) -> Dict[str, object]:
    cache_path = _metadata_cache_path(name)
    if not cache_path.is_file():
        return {}
    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(payload, dict) or payload.get("version") != _METADATA_CACHE_VERSION:
        return {}
    entries = payload.get("entries", {})
    return entries if isinstance(entries, dict) else {}

def _save_metadata_cache(name: str, entries: Dict[str, object]) -> None:
    cache_path = _metadata_cache_path(name)
    payload = {
        "version": _METADATA_CACHE_VERSION,
        "updated_at": int(time.time()),
        "entries": entries,
    }
    temp_path = cache_path.with_suffix(".tmp")
    temp_path.write_text(json.dumps(payload, ensure_ascii=True, separators=(",", ":")), encoding="utf-8")
    temp_path.replace(cache_path)

def _cache_key(key: object) -> str:
    if isinstance(key, str):
        return key.strip().lower()
    return str(int(key))

def _cache_lookup(entries: Dict[str, object], key: object, ttl_seconds: int) -> Tuple[bool, object]:
    entry = entries.get(_cache_key(key))
    if not isinstance(entry, dict):
        return False, None
    cached_at = int(entry.get("ts", 0) or 0)
    if cached_at <= 0 or (time.time() - cached_at) > ttl_seconds:
        return False, None
    return True, entry.get("data")

def _cache_store(entries: Dict[str, object], key: object, data: object) -> None:
    entries[_cache_key(key)] = {
        "ts": int(time.time()),
        "data": data,
    }

def _steam_owned_helper_path() -> Path:
    helper_path = _runtime_root() / "bin" / "SteamLoginHelper.exe"
    if helper_path.is_file():
        return helper_path
    raise FileNotFoundError(
        "Steam ownership helper is missing. Run Build.bat once so bin\\SteamLoginHelper.exe is available."
    )

def _read_cstring(blob: bytes, offset: int) -> Tuple[str, int]:
    end = blob.index(0, offset)
    return blob[offset:end].decode("utf-8", errors="ignore"), end + 1

def _load_appinfo_string_table(blob: bytes, offset: int) -> List[str]:
    if offset < 4 or offset >= len(blob):
        raise ValueError("Steam appinfo string table offset is invalid.")

    count = int.from_bytes(blob[offset:offset + 4], "little")
    cursor = offset + 4
    keys: List[str] = []
    for _ in range(count):
        value, cursor = _read_cstring(blob, cursor)
        keys.append(value)
    return keys

def _parse_appinfo_common_fields(entry_blob: bytes, string_table: List[str]) -> Tuple[str, str]:
    if len(entry_blob) <= _STEAM_APPINFO_BINARY_OFFSET_V41:
        return "", ""

    cursor = _STEAM_APPINFO_BINARY_OFFSET_V41
    path: List[str] = []
    app_name = ""
    app_type = ""

    while cursor < len(entry_blob):
        field_type = entry_blob[cursor]
        cursor += 1

        if field_type == 8:
            if path:
                path.pop()
                continue
            break

        if cursor + 4 > len(entry_blob):
            break
        key_index = int.from_bytes(entry_blob[cursor:cursor + 4], "little")
        cursor += 4
        key_name = string_table[key_index] if 0 <= key_index < len(string_table) else ""

        if field_type == 0:
            path.append(key_name)
            continue

        if field_type == 1:
            value, cursor = _read_cstring(entry_blob, cursor)
            if path == ["common"] and key_name == "name":
                app_name = value
            elif path == ["common"] and key_name == "type":
                app_type = value.strip().lower()
            if app_name and app_type:
                break
            continue

        if field_type in (2, 3, 6):
            cursor += 4
            continue

        if field_type == 7:
            cursor += 8
            continue

        if field_type == 5:
            if cursor + 2 > len(entry_blob):
                break
            wchar_count = int.from_bytes(entry_blob[cursor:cursor + 2], "little")
            cursor += 2 + (wchar_count * 2)
            continue

        break

    return app_name, app_type

def _load_local_app_index(steam_path: str) -> Dict[int, Dict[str, str]]:
    appinfo_path = Path(steam_path) / _STEAM_APPINFO_FILE
    if not appinfo_path.is_file():
        raise FileNotFoundError(
            f"Steam app cache was not found at {appinfo_path}. Start Steam once so the tool can index your library."
        )

    try:
        blob = appinfo_path.read_bytes()
    except OSError as exc:
        raise ValueError(f"Could not read Steam app cache: {exc}") from exc

    if len(blob) < 16:
        raise ValueError("Steam app cache is unexpectedly small.")

    magic = int.from_bytes(blob[0:4], "little")
    if magic != _STEAM_APPINFO_MAGIC_V41:
        raise ValueError(
            f"Steam app cache format 0x{magic:08X} is not supported yet. Update the tool so it can read this Steam client version."
        )

    string_table_offset = int.from_bytes(blob[8:16], "little", signed=True)
    string_table = _load_appinfo_string_table(blob, string_table_offset)

    cursor = 16
    app_index: Dict[int, Dict[str, str]] = {}
    while cursor + 8 <= len(blob):
        appid = int.from_bytes(blob[cursor:cursor + 4], "little")
        if appid == 0:
            break

        entry_size = int.from_bytes(blob[cursor + 4:cursor + 8], "little")
        if entry_size <= 0 or cursor + 8 + entry_size > len(blob):
            raise ValueError("Steam app cache is malformed or truncated.")

        entry_blob = blob[cursor + 8:cursor + 8 + entry_size]
        app_name, app_type = _parse_appinfo_common_fields(entry_blob, string_table)
        app_index[appid] = {
            "name": app_name or f"App {appid}",
            "type": app_type,
        }
        cursor += 8 + entry_size

    if not app_index:
        raise ValueError("Steam app cache did not yield any app IDs.")

    return app_index

def _local_candidate_appids(steam_path: str) -> List[int]:
    candidate_ids = set()

    for library_root, manifest in iter_installed_steam_games(steam_path):
        _ = library_root
        try:
            appid = int(manifest.get("appid", "0") or 0)
        except (TypeError, ValueError):
            appid = 0
        if appid > 0:
            candidate_ids.add(appid)

    accounts = get_steam_accounts(steam_path)
    for account in accounts:
        try:
            account_id = int(account.steamid) - 76561197960265728
        except (TypeError, ValueError):
            continue
        if account_id < 0:
            continue

        localconfig = Path(steam_path) / "userdata" / str(account_id) / "config" / "localconfig.vdf"
        if localconfig.is_file():
            try:
                content = localconfig.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                content = ""
            for match in re.finditer(r'^[\t ]+"(\d+)"\s*\{$', content, re.MULTILINE):
                try:
                    candidate_ids.add(int(match.group(1)))
                except (TypeError, ValueError):
                    continue

        library_cache = Path(steam_path) / "userdata" / str(account_id) / "config" / "librarycache"
        if library_cache.is_dir():
            try:
                for entry in library_cache.iterdir():
                    if not entry.is_file() or entry.suffix.lower() != ".json":
                        continue
                    if not entry.stem.isdigit():
                        continue
                    try:
                        candidate_ids.add(int(entry.stem))
                    except ValueError:
                        continue
            except OSError:
                pass

    return sorted(candidate_ids)

def _query_owned_appids_via_helper(steam_path: str, candidate_ids: Iterable[int]) -> List[int]:
    helper_path = _steam_owned_helper_path()

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".txt", delete=False) as handle:
        appid_file = Path(handle.name)
        for appid in candidate_ids:
            if int(appid) > 0:
                handle.write(f"{int(appid)}\n")

    try:
        completed = subprocess.run(
            [str(helper_path), "--steam-path", steam_path, "--appid-file", str(appid_file)],
            capture_output=True,
            text=True,
            timeout=_OWNED_SCAN_TIMEOUT,
        )
    finally:
        try:
            appid_file.unlink(missing_ok=True)
        except OSError:
            pass

    payload_text = (completed.stdout or "").strip().splitlines()
    payload = {}
    for line in reversed(payload_text):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
            break
        except json.JSONDecodeError:
            continue

    if completed.returncode != 0 or not payload.get("success"):
        error_message = str(payload.get("error") or "").strip()
        if not error_message:
            error_message = (completed.stderr or completed.stdout or "Steam ownership helper failed.").strip()
        raise ValueError(error_message)

    owned_ids_raw = payload.get("owned_appids", [])
    if not isinstance(owned_ids_raw, list):
        raise ValueError("Steam ownership helper returned an invalid owned app list.")

    owned_ids: List[int] = []
    for value in owned_ids_raw:
        try:
            appid = int(value)
        except (TypeError, ValueError):
            continue
        if appid > 0:
            owned_ids.append(appid)
    return owned_ids

def is_steam_running() -> bool:
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            proc_info = proc.info
            if proc_info and proc_info['name']:
                proc_name = proc_info['name'].lower()
                if proc_name in ('steam.exe', 'steam'):
                    return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return False

def get_steam_install_path(explicit_path: Optional[str] = None) -> Optional[str]:
    candidates: List[Path] = []
    if explicit_path:
        candidates.append(Path(explicit_path))

    try:
        import winreg

        for hive, subkey, value_name in (
            (winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam", "SteamPath"),
            (winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam", "SteamExe"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Valve\Steam", "InstallPath"),
        ):
            try:
                key = winreg.OpenKey(hive, subkey)
                value, _ = winreg.QueryValueEx(key, value_name)
                winreg.CloseKey(key)
                if isinstance(value, str) and value:
                    path = Path(value)
                    candidates.append(path.parent if path.suffix.lower() == ".exe" else path)
            except OSError:
                continue
    except Exception:
        pass

    for env_name in ("PROGRAMFILES(X86)", "PROGRAMFILES"):
        env_root = os.environ.get(env_name)
        if env_root:
            candidates.append(Path(env_root) / "Steam")

    seen = set()
    for candidate in candidates:
        normalized = str(candidate.resolve()) if candidate.exists() else str(candidate)
        if normalized in seen:
            continue
        seen.add(normalized)
        if candidate.is_dir() and (candidate / "steamapps").is_dir():
            return str(candidate)
    return None

def get_steam_accounts(steam_path: str) -> List[SteamAccount]:
    loginusers = _read_vdf_file(Path(steam_path) / _STEAM_LOGINUSERS_FILE)
    users_obj = loginusers.get("users", {})
    if not isinstance(users_obj, dict):
        return []

    accounts: List[SteamAccount] = []
    for steamid, payload in users_obj.items():
        if not isinstance(payload, dict):
            continue
        accounts.append(
            SteamAccount(
                steamid=str(steamid),
                account_name=str(payload.get("AccountName", "")),
                persona_name=str(payload.get("PersonaName", "")),
                most_recent=str(payload.get("MostRecent", "0")) == "1",
            )
        )
    accounts.sort(key=lambda item: (not item.most_recent, item.account_name.lower(), item.steamid))
    return accounts

def get_steam_library_paths(steam_path: str) -> List[str]:
    libraries = [Path(steam_path)]
    parsed = _read_vdf_file(Path(steam_path) / _STEAM_LIBRARY_FILE)
    library_root = parsed.get("libraryfolders", {})
    if isinstance(library_root, dict):
        for value in library_root.values():
            if isinstance(value, dict):
                raw_path = value.get("path")
            else:
                raw_path = value
            if isinstance(raw_path, str) and raw_path:
                libraries.append(Path(raw_path))

    out: List[str] = []
    seen = set()
    for lib in libraries:
        steamapps = lib / "steamapps"
        if not steamapps.is_dir():
            continue
        resolved = str(lib)
        key = os.path.normcase(resolved)
        if key in seen:
            continue
        seen.add(key)
        out.append(resolved)
    return out

def _read_appmanifest(path: Path) -> Dict[str, str]:
    parsed = _read_vdf_file(path)
    app_state = parsed.get("AppState", {})
    if isinstance(app_state, dict):
        return {str(k): str(v) for k, v in app_state.items()}
    return {}

def iter_installed_steam_games(steam_path: str) -> Iterator[Tuple[Path, Dict[str, str]]]:
    for library in get_steam_library_paths(steam_path):
        steamapps = Path(library) / "steamapps"
        try:
            entries = sorted(steamapps.iterdir(), key=lambda item: item.name.lower())
        except OSError:
            continue
        for entry in entries:
            if not entry.is_file():
                continue
            if not _APPMANIFEST_RE.match(entry.name):
                continue
            manifest = _read_appmanifest(entry)
            if manifest:
                yield Path(library), manifest

def _find_candidate_executables(game_dir: Path, max_depth: int = 4) -> List[Path]:
    candidates: List[Path] = []
    queue: List[Tuple[Path, int]] = [(game_dir, 0)]
    while queue:
        current, depth = queue.pop(0)
        try:
            with os.scandir(current) as it:
                for entry in it:
                    path = Path(entry.path)
                    if entry.is_file() and entry.name.lower().endswith(".exe"):
                        candidates.append(path)
                    elif entry.is_dir() and depth < max_depth:
                        queue.append((path, depth + 1))
        except OSError:
            continue
    return candidates

def _executable_penalty(candidate: Path) -> int:
    lowered_name = candidate.name.lower()
    lowered_path = str(candidate).lower()

    penalty = 0
    noisy_tokens = (
        "installer",
        "install",
        "uninstall",
        "launcher",
        "helper",
        "report",
        "crash",
        "service",
        "cleanup",
        "updater",
        "prereq",
        "protected_game",
        "anticheat",
    )
    if any(token in lowered_name for token in noisy_tokens):
        penalty += 4
    if "\\easyanticheat\\" in lowered_path or "\\battleye\\" in lowered_path:
        penalty += 6
    if "\\support\\" in lowered_path or "\\installers\\" in lowered_path:
        penalty += 5
    return penalty

def _pick_primary_executable(game_dir: Path, app_name: str) -> Optional[Path]:
    app_slug = re.sub(r"[^a-z0-9]", "", app_name.lower())
    best: Optional[Tuple[Tuple[int, int, int, str], Path]] = None

    for candidate in _find_candidate_executables(game_dir):
        lowered = candidate.name.lower()
        if lowered in _SKIP_EXECUTABLE_NAMES:
            continue
        name_slug = re.sub(r"[^a-z0-9]", "", candidate.stem.lower())
        try:
            size = candidate.stat().st_size
        except OSError:
            size = 0
        path_lower = str(candidate).lower()
        path_bonus = 0
        if "\\binaries\\win64\\" in path_lower or "\\bin\\win64" in path_lower or "\\bin\\x64" in path_lower:
            path_bonus += 3
        if "shipping" in lowered or "win64" in lowered or "x64" in lowered:
            path_bonus += 1
        name_bonus = 0
        if app_slug and name_slug == app_slug:
            name_bonus += 3
        elif app_slug and app_slug in name_slug:
            name_bonus += 2
        elif name_slug and name_slug in app_slug:
            name_bonus += 1
        if lowered.endswith("_be.exe") or lowered.endswith("_nobe.exe"):
            path_bonus -= 1
        penalty = _executable_penalty(candidate)
        score = (
            name_bonus,
            path_bonus - penalty,
            size,
            str(candidate),
        )
        if best is None or score > best[0]:
            best = (score, candidate)

    return best[1] if best else None

def _find_unity_data_dirs(game_dir: Path) -> List[Path]:
    out: List[Path] = []
    try:
        for entry in game_dir.iterdir():
            if entry.is_dir() and entry.name.lower().endswith("_data"):
                out.append(entry)
            elif entry.is_dir() and entry.name.lower() == "il2cpp_data":
                out.append(entry)
    except OSError:
        pass
    return out

def _detect_unity_runtime(game_dir: Path, exe_path: Optional[Path]) -> Tuple[str, str, str, List[str]]:
    evidence: List[str] = []
    data_dirs = _find_unity_data_dirs(game_dir)
    il2cpp_dirs = [
        path for path in data_dirs
        if path.name.lower() == "il2cpp_data" or (path / "il2cpp_data").is_dir()
    ]
    managed_dirs = [path / "Managed" for path in data_dirs if (path / "Managed").is_dir()]
    unity_player = (game_dir / "UnityPlayer.dll").is_file()
    if unity_player:
        evidence.append("UnityPlayer.dll present")

    unity_version = get_unity_version_from_pe(str(exe_path)) if exe_path else None

    if il2cpp_dirs:
        evidence.append("il2cpp_data present")
        return "il2cpp", unity_version or "", "unity_disk_markers", evidence
    if managed_dirs:
        evidence.append("Managed assemblies present")
        return "mono", unity_version or "", "unity_disk_markers", evidence
    if unity_player:
        return "unity_unknown", unity_version or "", "unity_disk_markers", evidence
    return "unknown", "", "none", evidence

def _detect_unreal_runtime(exe_path: Optional[Path], game_dir: Path) -> Tuple[str, str, str, List[str]]:
    evidence: List[str] = []
    if exe_path and exe_path.is_file():
        try:
            result = detect_engine(exe_path.name, str(exe_path))
        except Exception:
            result = {"engine": "unknown", "version": "", "method": "none"}
        if result["engine"] != "unknown":
            if result.get("version"):
                evidence.append(f"PE/strings report {result['engine']} {result['version']}")
            else:
                evidence.append(f"PE/strings report {result['engine']}")
            return result["engine"], result.get("version", ""), result.get("method", "ue_detector"), evidence

    content_paks = game_dir / "Content" / "Paks"
    if content_paks.is_dir():
        evidence.append("Content/Paks present")
        return "ue_unknown", "", "ue_layout_heuristic", evidence
    return "unknown", "", "none", evidence

def _detect_anticheat_markers(game_dir: Path, max_depth: int = 2) -> List[str]:
    found: List[str] = []
    seen = set()
    queue: List[Tuple[Path, int]] = [(game_dir, 0)]
    while queue:
        current, depth = queue.pop(0)
        try:
            with os.scandir(current) as it:
                for entry in it:
                    lowered = entry.name.lower()
                    marker = _ANTI_CHEAT_FILE_MARKERS.get(lowered)
                    if marker and marker not in seen:
                        seen.add(marker)
                        found.append(marker)
                    if entry.is_dir() and depth < max_depth:
                        queue.append((Path(entry.path), depth + 1))
        except OSError:
            continue
    return sorted(found)

def _detect_il2cpp_binary_name(game_dir: Path) -> Optional[str]:
    largest_name: Optional[str] = None
    largest_size = -1
    try:
        for entry in game_dir.iterdir():
            if not entry.is_file() or entry.suffix.lower() != ".dll":
                continue
            lowered = entry.name.lower()
            if lowered in _UNITY_DLL_SKIP_NAMES:
                continue
            try:
                size = entry.stat().st_size
            except OSError:
                size = 0
            if size > largest_size:
                largest_size = size
                largest_name = entry.name
    except OSError:
        pass
    return largest_name

def _collect_disk_markers(game_dir: Path, max_depth: int = 4, max_entries: int = 6000) -> Tuple[set[str], set[str]]:
    file_paths: set[str] = set()
    dir_paths: set[str] = set()
    queue: List[Tuple[Path, int]] = [(game_dir, 0)]

    while queue and (len(file_paths) + len(dir_paths)) < max_entries:
        current, depth = queue.pop(0)
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        relative = Path(entry.path).relative_to(game_dir).as_posix().lower()
                    except Exception:
                        continue
                    if entry.is_file():
                        file_paths.add(relative)
                    elif entry.is_dir():
                        dir_paths.add(relative)
                        if depth < max_depth:
                            queue.append((Path(entry.path), depth + 1))
                    if (len(file_paths) + len(dir_paths)) >= max_entries:
                        break
        except OSError:
            continue

    return file_paths, dir_paths

def _detect_disk_engine_runtime(
    appid: int,
    game_dir: Path,
    app_name: str,
    exe_path: Optional[Path],
) -> Tuple[str, str, str, List[str]]:
    override = _LOCAL_ENGINE_APPID_OVERRIDES.get(appid)
    if override:
        engine, version, method = override
        return engine, version, method, [f"Matched curated engine override for appid {appid}"]

    file_paths, dir_paths = _collect_disk_markers(game_dir)
    file_names = {Path(path).name for path in file_paths}
    dir_names = {Path(path).name for path in dir_paths}
    top_level_files = {path for path in file_paths if "/" not in path}
    evidence: List[str] = []

    if "adobe air" in dir_names or any(path.endswith(".swf") for path in file_paths):
        if "adobe air" in dir_names:
            evidence.append("Adobe AIR runtime folder present")
        if any(path.endswith(".swz") for path in file_paths):
            evidence.append("Adobe AIR SWZ libraries present")
        if any(path.endswith(".swf") for path in file_paths):
            evidence.append("ActionScript SWF content present")
        return "avm2", "", "disk_engine_markers", evidence

    electron_markers = {
        "license.electron.txt",
        "resources.pak",
        "chrome_100_percent.pak",
        "chrome_200_percent.pak",
        "snapshot_blob.bin",
        "v8_context_snapshot.bin",
    }
    if len(electron_markers & top_level_files) >= 3 or "resources/app.asar" in file_paths:
        evidence.append("Electron runtime packaging files present")
        return "electron", "", "disk_engine_markers", evidence

    if "engine/binaries/win64" in dir_paths and any(path.startswith("engine/plugins/runtime/") for path in dir_paths):
        evidence.append("Unreal-style Engine/Binaries/Win64 layout present")
        evidence.append("Unreal Engine runtime plugins present")
        return "ue_unknown", "", "disk_engine_markers", evidence

    if any(path.endswith(".vpk") for path in file_paths) or "hl2.exe" in file_names:
        evidence.append("Valve VPK package files present")
        return "source", "", "disk_engine_markers", evidence

    if "engine2.dll" in file_names:
        evidence.append("engine2.dll present")
        return "source_2", "", "disk_engine_markers", evidence

    if any(path.endswith(".forge") for path in file_paths):
        evidence.append("Ubisoft .forge archives present")
        return "anvil", "", "disk_engine_markers", evidence

    if "reliccardinal.exe" in file_names or any(name.startswith("essence.") for name in file_names):
        if "reliccardinal.exe" in file_names:
            evidence.append("RelicCardinal.exe present")
        if any(name.startswith("essence.") for name in file_names):
            evidence.append("Essence engine DLLs present")
        return "essence", "", "disk_engine_markers", evidence

    if "system.cfg" in file_names and ("engine.pak" in file_names or "whgame.dll" in file_names):
        if "system.cfg" in file_names:
            evidence.append("CryEngine-style system.cfg present")
        if "engine.pak" in file_names:
            evidence.append("Engine.pak present")
        if "whgame.dll" in file_names:
            evidence.append("WHGame.dll present")
        return "cryengine", "", "disk_engine_markers", evidence

    lowered_name = app_name.lower()
    lowered_exe = exe_path.name.lower() if exe_path else ""
    if lowered_exe.startswith("mgsv") or "metal gear solid v" in lowered_name:
        evidence.append("MGSV executable naming matches FOX Engine builds")
        return "fox_engine", "", "disk_engine_markers", evidence
    if lowered_exe.startswith("dayz") or lowered_name.startswith("dayz"):
        evidence.append("DayZ executable naming matches Enfusion builds")
        return "enfusion", "", "disk_engine_markers", evidence

    return "unknown", "", "none", evidence

def _store_url_for_appid(appid: int) -> str:
    return f"https://store.steampowered.com/app/{appid}/" if appid else ""

def _sorted_unique(values: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for value in values:
        normalized = value.strip()
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(normalized)
    return sorted(out)

def _merge_scan_source(scan_source: str, source: str) -> str:
    token = source.strip()
    if not token or token in scan_source.split("+"):
        return scan_source
    return scan_source + f"+{token}" if scan_source else token

def _normalize_anti_cheat_name(value: str) -> str:
    cleaned = _clean_wiki_markup(str(value)).strip()
    if not cleaned:
        return ""
    lowered = re.sub(r"\s+", " ", cleaned.lower())
    return _ANTI_CHEAT_NAME_ALIASES.get(lowered, cleaned)

def _normalize_anti_cheat_names(values: Iterable[str]) -> List[str]:
    normalized = [_normalize_anti_cheat_name(value) for value in values]
    return _sorted_unique(value for value in normalized if value)

def _is_known_engine(engine: str) -> bool:
    return bool(engine) and engine != "unknown"

def _is_supported_engine(engine: str) -> bool:
    return engine in _SUPPORTED_ENGINES

def _build_diagnostic(
    *,
    appid: int,
    name: str,
    engine: str,
    detection_method: str,
    anti_cheats: List[str],
    evidence: List[str],
    installed: bool,
    executable_path: str = "",
    scan_source: str,
) -> Dict[str, object]:
    score = 0
    flags: List[str] = []

    if installed:
        score += 16
        flags.append("installed_local_files")
    else:
        flags.append("owned_account_only")

    if executable_path:
        score += 4

    if engine in {"ue4", "ue5", "il2cpp", "mono"}:
        score += 62
        flags.append("strong_engine_match")
    elif engine in _GENERIC_ENGINE_IDS:
        score += 44
        flags.append("weak_engine_match")
    elif _is_known_engine(engine):
        score += 32
        flags.append("known_engine_match")
    else:
        score += 6
        flags.append("unknown_engine")

    if detection_method in {"appid_override", "disk_engine_markers", "pe_string_scan", "pe_version_info", "unity_disk_markers", "ue_detector"}:
        score += 10
    elif detection_method in {
        "pcgw_engine_infobox",
        "pcgw_title_search",
        "store_text_engine_alias",
        "store_text_unreal_engine",
        "store_text_unity",
        "ue_layout_heuristic",
    }:
        score += 4

    kernel_recommended = any(marker in _KERNEL_RECOMMENDED_ANTI_CHEATS for marker in anti_cheats)
    if anti_cheats:
        score -= 12
        flags.append("anti_cheat_markers")
    if engine == "ue_unknown" and installed:
        kernel_recommended = True
        flags.append("weak_unreal_markers")
    if not installed:
        score -= 18

    score = max(0, min(score, 100))
    likely_dumpable = _is_supported_engine(engine)

    if installed:
        if likely_dumpable and not kernel_recommended and score >= 55:
            support_tier = "usermode_ready"
        elif likely_dumpable and kernel_recommended:
            support_tier = "kernel_recommended"
        elif _is_known_engine(engine):
            support_tier = "engine_identified"
        else:
            support_tier = "manual_review"
    else:
        if likely_dumpable and kernel_recommended:
            support_tier = "install_then_kernel"
        elif likely_dumpable:
            support_tier = "install_then_scan"
        elif _is_known_engine(engine):
            support_tier = "install_engine_identified"
        else:
            support_tier = "manual_review"

    if support_tier == "usermode_ready":
        confidence = "high" if engine in {"ue4", "ue5", "il2cpp", "mono"} else "medium"
        diagnostic_summary = (
            f"Strong local evidence suggests {name} is a good user-mode target."
        )
        next_step = "Launch the game and try a normal user-mode dump first."
    elif support_tier == "kernel_recommended":
        confidence = "medium" if engine != "unknown" else "low"
        diagnostic_summary = (
            f"Found usable engine markers for {name}, but anti-cheat or weak Unreal evidence means kernel mode is the safer path."
        )
        next_step = "Launch the game with kernel mode enabled before scanning."
    elif support_tier == "install_then_scan":
        confidence = "medium" if engine != "unknown" else "low"
        diagnostic_summary = (
            f"{name} appears promising, but this result is based on owned-account metadata rather than on-disk binaries."
        )
        next_step = "Install the game to run a file-based deep diagnostic."
    elif support_tier == "install_then_kernel":
        confidence = "medium" if anti_cheats else "low"
        diagnostic_summary = (
            f"{name} looks relevant, but only remote metadata is available and it already shows signs that kernel mode may be needed."
        )
        next_step = "Install the game, then run a local audit and be ready to enable kernel mode."
    elif support_tier == "engine_identified":
        confidence = "medium"
        diagnostic_summary = (
            f"Identified {name}'s engine as {engine.replace('_', ' ')}, but that engine family is not on the deep-dump path yet."
        )
        next_step = "Use this engine ID as a detection target or add a dedicated dumper for that engine family."
    elif support_tier == "install_engine_identified":
        confidence = "medium"
        diagnostic_summary = (
            f"{name}'s engine appears identified from remote metadata, but a dedicated workflow for that engine family is not yet available."
        )
        next_step = "Install the game if you want local file confirmation, then add a detector or dumper for this engine."
    else:
        confidence = "low"
        diagnostic_summary = (
            f"Could not find enough evidence to classify {name} confidently."
        )
        next_step = (
            "Install or inspect the game locally to read real binaries and runtime markers."
            if not installed else
            "Open the game folder or run a manual verification pass to inspect binaries more deeply."
        )

    if not installed:
        evidence = list(evidence) + ["Owned via the running Steam desktop client; no local game files were scanned"]

    return {
        "confidence": confidence,
        "kernel_recommended": kernel_recommended,
        "likely_dumpable": likely_dumpable,
        "support_tier": support_tier,
        "support_score": score,
        "diagnostic_summary": diagnostic_summary,
        "next_step": next_step,
        "diagnostic_flags": _sorted_unique(flags),
        "evidence": evidence,
        "store_url": _store_url_for_appid(appid),
        "scan_source": scan_source,
    }

def _classify_installed_game(
    appid: int,
    game_dir: Path,
    app_name: str,
    exe_path: Optional[Path],
) -> SteamInstalledGame:
    anti_cheats = _detect_anticheat_markers(game_dir)
    evidence: List[str] = []

    engine, version, method, markers = _detect_unity_runtime(game_dir, exe_path)
    evidence.extend(markers)
    if engine == "il2cpp":
        il2cpp_binary = _detect_il2cpp_binary_name(game_dir)
        if il2cpp_binary:
            evidence.append(f"IL2CPP binary candidate: {il2cpp_binary}")
    if engine == "unknown":
        engine, version, method, markers = _detect_unreal_runtime(exe_path, game_dir)
        evidence.extend(markers)
    if engine == "unknown":
        engine, version, method, markers = _detect_disk_engine_runtime(appid, game_dir, app_name, exe_path)
        evidence.extend(markers)

    awacy_record = _lookup_awacy_record(appid, app_name)
    awacy_anti_cheats = _extract_awacy_anticheats(awacy_record)
    if awacy_anti_cheats:
        anti_cheats = _normalize_anti_cheat_names(list(anti_cheats) + awacy_anti_cheats)
        evidence.append("AWACY anti-cheat data: " + ", ".join(awacy_anti_cheats))
    else:
        anti_cheats = _normalize_anti_cheat_names(anti_cheats)

    if anti_cheats:
        evidence.append("Anti-cheat markers: " + ", ".join(anti_cheats))
    if exe_path:
        evidence.append(f"Primary exe: {exe_path.name}")
    else:
        evidence.append("No primary executable was confidently identified")

    diag = _build_diagnostic(
        appid=appid,
        name=app_name,
        engine=engine,
        detection_method=method,
        anti_cheats=anti_cheats,
        evidence=evidence,
        installed=True,
        executable_path=str(exe_path) if exe_path else "",
        scan_source="installed_disk",
    )

    return SteamInstalledGame(
        appid=appid,
        name=app_name,
        library_path=str(game_dir.parent.parent),
        install_dir=str(game_dir),
        manifest_path=str(game_dir.parent.parent / "steamapps" / f"appmanifest_{appid}.acf"),
        executable_path=str(exe_path) if exe_path else "",
        engine=engine,
        version=version,
        detection_method=method,
        confidence=str(diag["confidence"]),
        anti_cheats=anti_cheats,
        kernel_recommended=bool(diag["kernel_recommended"]),
        likely_dumpable=bool(diag["likely_dumpable"]),
        support_tier=str(diag["support_tier"]),
        evidence=list(diag["evidence"]),
        installed=True,
        owned_on_account=False,
        scan_source=str(diag["scan_source"]),
        support_score=int(diag["support_score"]),
        diagnostic_summary=str(diag["diagnostic_summary"]),
        next_step=str(diag["next_step"]),
        diagnostic_flags=list(diag["diagnostic_flags"]),
        store_url=str(diag["store_url"]),
    )

def _collect_store_text(value: object, parts: List[str]) -> None:
    if isinstance(value, str):
        parts.append(value)
        return
    if isinstance(value, dict):
        for nested in value.values():
            _collect_store_text(nested, parts)
        return
    if isinstance(value, list):
        for nested in value:
            _collect_store_text(nested, parts)

def _extract_store_text(store_data: Dict[str, object]) -> str:
    parts: List[str] = []
    for key in (
        "name",
        "short_description",
        "detailed_description",
        "about_the_game",
        "supported_languages",
        "legal_notice",
        "ext_user_account_notice",
        "notice",
        "pc_requirements",
        "mac_requirements",
        "linux_requirements",
        "categories",
        "content_descriptors",
    ):
        _collect_store_text(store_data.get(key), parts)
    return " ".join(parts).lower()

def _extract_remote_anti_cheat_markers(text_blob: str, *, allow_vac_token: bool = False) -> List[str]:
    anti_cheats: List[str] = []
    lowered = f" {text_blob.lower()} "
    for token, marker in _REMOTE_ANTI_CHEAT_MARKERS.items():
        if token in lowered:
            anti_cheats.append(marker)
    if "valve anti-cheat" in lowered or (allow_vac_token and re.search(r"\bvac\b", lowered)):
        anti_cheats.append("VAC")
    return _normalize_anti_cheat_names(anti_cheats)

def _title_search_candidates(title: str) -> List[str]:
    candidates: List[str] = []
    seen: set[str] = set()

    def canonical_key(value: str) -> str:
        lowered = value.lower().replace("’", "'").replace("®", "").replace("™", "").replace("©", "")
        lowered = re.sub(r"[^a-z0-9]+", " ", lowered)
        return re.sub(r"\s+", " ", lowered).strip()

    def add(value: str) -> None:
        cleaned = re.sub(r"\s+", " ", value).strip(" -\t\r\n")
        if not cleaned:
            return
        key = cleaned.lower()
        if key in seen:
            return
        seen.add(key)
        candidates.append(cleaned)

    add(title)
    add(re.sub(r"^[\W_]+|[\W_]+$", "", title, flags=re.UNICODE))
    add(title.replace("’", "'").replace("®", "").replace("™", "").replace("©", ""))
    ascii_friendly = re.sub(r"[^A-Za-z0-9&+'!?:./ -]+", " ", title)
    add(ascii_friendly)
    add(re.sub(r"\s+-\s+", " ", ascii_friendly))

    stripped_suffix = re.sub(
        r"\s*(?:[-:]\s*)?(?:public test|test server|experimental server|demo|playtest|beta|alpha|prologue)$",
        "",
        title,
        flags=re.IGNORECASE,
    )
    add(stripped_suffix)
    add(
        re.sub(
            r"\s+(?:director'?s cut|definitive edition|game of the year edition|complete edition|ultimate edition|remastered|enhanced edition|anniversary edition)$",
            "",
            stripped_suffix,
            flags=re.IGNORECASE,
        )
    )

    publisher_trimmed = re.sub(r"^(?:sid meier'?s|tom clancy'?s)\s+", "", stripped_suffix, flags=re.IGNORECASE)
    add(publisher_trimmed)

    alias_map = {
        "overwatch": ["Overwatch 2", "Overwatch (video game)"],
        "pubg": ["PUBG: Battlegrounds", "PUBG"],
        "rainbow six siege": ["Tom Clancy's Rainbow Six Siege", "Rainbow Six Siege"],
        "civilization vi": ["Civilization VI"],
        "civilization vii": ["Civilization VII"],
        "ghost of tsushima": ["Ghost of Tsushima"],
        "god of war": ["God of War (2018 video game)", "God of War (2018)"],
    }
    for alias in alias_map.get(canonical_key(publisher_trimmed or stripped_suffix or title), []):
        add(alias)

    return candidates

def _detect_engine_hint(text_blob: str) -> Tuple[str, str]:
    for pattern, detected_engine, detected_version in _ENGINE_HINTS:
        if pattern.search(text_blob):
            return detected_engine, detected_version
    return "unknown", ""

def _detect_engine_from_text(text: str) -> Tuple[str, str, str]:
    if not text:
        return "unknown", "", "steam_desktop_ownership"
    
    text_lower = text.lower()
    
    explicit_patterns = [
        (re.compile(r"\bunreal engine\s*5\b", re.IGNORECASE), "ue5", ""),
        (re.compile(r"\bunreal engine\s*4\b", re.IGNORECASE), "ue4", ""),
        (re.compile(r"\bue5\b", re.IGNORECASE), "ue5", ""),
        (re.compile(r"\bue4\b", re.IGNORECASE), "ue4", ""),
        (re.compile(r"\bunreal engine\b", re.IGNORECASE), "ue_unknown", ""),
        
        (re.compile(r"\bunity\s*(\d+\.[\d.x]+)?\b", re.IGNORECASE), "unity_unknown", ""),
        (re.compile(r"\bil2cpp\b", re.IGNORECASE), "il2cpp", ""),
        (re.compile(r"\bunity\b.*\bmono\b|\bmono\b.*\bunity\b", re.IGNORECASE), "mono", ""),
        
        (re.compile(r"\bsource\s*2\b", re.IGNORECASE), "source_2", ""),
        (re.compile(r"\bsource engine\b", re.IGNORECASE), "source", ""),
        (re.compile(r"\bcryengine\b", re.IGNORECASE), "cryengine", ""),
        (re.compile(r"\bforzatech\b", re.IGNORECASE), "forzatech", ""),
        (re.compile(r"\bgodot\b", re.IGNORECASE), "godot", ""),
        (re.compile(r"\badobe air\b", re.IGNORECASE), "avm2", ""),
        (re.compile(r"\bactionscript\s*3\b", re.IGNORECASE), "avm2", ""),
        (re.compile(r"\brpg maker\b", re.IGNORECASE), "rpg_maker", ""),
        (re.compile(r"\bgamemaker\b", re.IGNORECASE), "gamemaker", ""),
        (re.compile(r"\bren'?py\b", re.IGNORECASE), "renpy", ""),
    ]
    
    for pattern, engine_id, version_key in explicit_patterns:
        match = pattern.search(text_lower)
        if match:
            version = ""
            if version_key and match.groups():
                version = match.group(1).strip()
            return engine_id, version, f"store_text_{engine_id}"
    
    return "unknown", "", "steam_desktop_ownership"

def _engine_confidence_rank(engine: str) -> int:
    if engine in {"ue4", "ue5", "il2cpp", "mono"}:
        return 4
    if _is_known_engine(engine) and engine not in _GENERIC_ENGINE_IDS:
        return 3
    if engine in _GENERIC_ENGINE_IDS:
        return 2
    return 0

def _clean_wiki_markup(text: str) -> str:
    cleaned = re.sub(r"<ref[^>]*>.*?</ref>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    cleaned = re.sub(r"<[^>]+>", " ", cleaned)
    cleaned = re.sub(r"\{\{note\|([^{}]+)\}\}", r"\1", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\{\{[^{}]*\}\}", " ", cleaned)
    cleaned = re.sub(r"\[\[[^|\]]+\|([^\]]+)\]\]", r"\1", cleaned)
    cleaned = re.sub(r"\[\[([^\]]+)\]\]", r"\1", cleaned)
    cleaned = re.sub(r"\[(?:https?://[^\s\]]+)\s+([^\]]+)\]", r"\1", cleaned)
    cleaned = unescape(cleaned)
    return re.sub(r"\s+", " ", cleaned).strip(" ,;")

def _normalize_external_engine(
    engine_name: str,
    source_method: str = "external_engine_metadata",
) -> Tuple[str, str, str]:
    cleaned = _clean_wiki_markup(engine_name)
    normalized = re.sub(r"\s+", " ", cleaned).strip()
    if not normalized:
        return "unknown", "", "steam_desktop_ownership"
    lowered = normalized.lower()
    alias = _EXTERNAL_ENGINE_ALIASES.get(lowered)
    if alias:
        return alias[0], alias[1], source_method
    if lowered == "source":
        return "source", "", source_method
    if lowered == "source 2":
        return "source_2", "", source_method
    engine, version = _detect_engine_hint(normalized)
    if engine != "unknown":
        return engine, version, source_method
    return "unknown", "", "steam_desktop_ownership"

def _parse_pcgw_metadata(wikitext: str) -> Optional[Dict[str, object]]:
    engine_candidates = [
        _clean_wiki_markup(match)
        for match in _PCGW_ENGINE_ROW_RE.findall(wikitext)
        if _clean_wiki_markup(match)
    ]
    anti_cheat_match = _PCGW_ANTI_CHEAT_RE.search(wikitext)
    anti_cheat_text = _clean_wiki_markup(anti_cheat_match.group(1)) if anti_cheat_match else ""
    anti_cheats = _extract_remote_anti_cheat_markers(anti_cheat_text, allow_vac_token=True) if anti_cheat_text else []
    if not engine_candidates and not anti_cheats:
        return None
    return {
        "engines": engine_candidates,
        "anticheats": anti_cheats,
    }

def _fetch_pcgw_page_metadata(page_name: str) -> Optional[Dict[str, object]]:
    if not page_name:
        return None

    try:
        page_payload = _fetch_json(
            "https://www.pcgamingwiki.com/w/api.php?action=query&prop=revisions"
            f"&titles={quote(page_name, safe='')}"
            "&rvslots=main&rvprop=content&format=json",
            headers=_PCGW_HTTP_HEADERS,
        )
    except Exception:
        return None

    pages = page_payload.get("query", {}).get("pages", {})
    if not isinstance(pages, dict) or not pages:
        return None
    page_record = next(iter(pages.values()))
    if not isinstance(page_record, dict):
        return None
    revisions = page_record.get("revisions", [])
    if not isinstance(revisions, list) or not revisions:
        return None
    slots = revisions[0].get("slots", {})
    if not isinstance(slots, dict):
        return None
    main_slot = slots.get("main", {})
    if not isinstance(main_slot, dict):
        return None
    wikitext = str(main_slot.get("*") or "")
    if not wikitext:
        return None

    metadata = _parse_pcgw_metadata(wikitext)
    if not metadata:
        return None
    metadata["page"] = page_name
    return metadata

def _normalize_search_title(title: str) -> str:
    cleaned = re.sub(r"[®™©'’`]", "", title.lower())
    cleaned = re.sub(r"[^a-z0-9]+", " ", cleaned)
    return re.sub(r"\s+", " ", cleaned).strip()

def _collapsed_search_title(title: str) -> str:
    return _normalize_search_title(title).replace(" ", "")

def _search_result_score(candidate_title: str, wanted_title: str) -> int:
    candidate_norm = _normalize_search_title(candidate_title)
    wanted_norm = _normalize_search_title(wanted_title)
    if not candidate_norm or not wanted_norm:
        return 0

    candidate_compact = candidate_norm.replace(" ", "")
    wanted_compact = wanted_norm.replace(" ", "")
    if candidate_compact == wanted_compact:
        return 100

    candidate_tokens = set(candidate_norm.split())
    wanted_tokens = set(wanted_norm.split())
    if len(wanted_tokens) >= 2 and wanted_tokens.issubset(candidate_tokens):
        return 80 + len(wanted_tokens)
    if candidate_compact.startswith(wanted_compact) and len(wanted_compact) >= 12:
        return 70

    overlap = len(candidate_tokens & wanted_tokens)
    if overlap:
        return overlap * 10
    return 0

def _search_pcgw_page_name(game_name: str) -> Optional[str]:
    if not game_name:
        return None

    for candidate in _title_search_candidates(game_name):
        search_url = (
            "https://www.pcgamingwiki.com/w/api.php?action=query&list=search&format=json"
            f"&srlimit=5&srsearch={quote(candidate, safe='')}"
        )
        try:
            payload = _fetch_json(search_url, headers=_PCGW_HTTP_HEADERS)
        except Exception:
            continue

        rows = payload.get("query", {}).get("search", [])
        if not isinstance(rows, list):
            continue

        best_title = None
        best_score = 0
        for row in rows:
            title = str(row.get("title") or "").strip()
            if not title:
                continue
            score = _search_result_score(title, candidate)
            if score > best_score:
                best_score = score
                best_title = title
        if best_title and best_score >= 80:
            return best_title
    return None

def _split_engine_candidates(engine_text: str) -> List[str]:
    cleaned = _clean_wiki_markup(engine_text)
    if not cleaned:
        return []
    parts = re.split(r"\s*(?:<br\s*/?>|,|;|/|\|)\s*", cleaned, flags=re.IGNORECASE)
    out: List[str] = []
    for part in parts:
        value = part.strip()
        if value:
            out.append(value)
    return _sorted_unique(out or [cleaned])

def _parse_wikipedia_metadata(wikitext: str) -> Optional[Dict[str, object]]:
    engines: List[str] = []
    for match in _WIKIPEDIA_ENGINE_ROW_RE.findall(wikitext):
        engines.extend(_split_engine_candidates(match))
    engines = _sorted_unique(engines)
    if not engines:
        return None
    return {"engines": engines}

def _fetch_wikidata_entity(entity_id: str) -> Optional[Dict[str, object]]:
    if not entity_id:
        return None
    url = (
        "https://www.wikidata.org/w/api.php?action=wbgetentities&format=json"
        f"&ids={quote(entity_id, safe='')}&props=claims|labels|descriptions|sitelinks"
        "&languages=en&sitefilter=enwiki"
    )
    try:
        payload = _fetch_json(url, headers=_WIKIDATA_HTTP_HEADERS)
    except Exception:
        return None
    entities = payload.get("entities", {})
    if not isinstance(entities, dict):
        return None
    entity = entities.get(entity_id)
    return entity if isinstance(entity, dict) else None

def _resolve_wikidata_engine_labels(entity: Dict[str, object]) -> List[str]:
    claims = entity.get("claims", {})
    if not isinstance(claims, dict):
        return []
    engine_claims = claims.get("P408", [])
    if not isinstance(engine_claims, list) or not engine_claims:
        return []

    engine_ids: List[str] = []
    for claim in engine_claims:
        try:
            engine_id = str(claim["mainsnak"]["datavalue"]["value"]["id"])
        except Exception:
            continue
        if engine_id and engine_id not in engine_ids:
            engine_ids.append(engine_id)
    if not engine_ids:
        return []

    url = (
        "https://www.wikidata.org/w/api.php?action=wbgetentities&format=json"
        f"&ids={quote('|'.join(engine_ids), safe='|')}&props=labels&languages=en"
    )
    try:
        payload = _fetch_json(url, headers=_WIKIDATA_HTTP_HEADERS)
    except Exception:
        return []
    entities = payload.get("entities", {})
    if not isinstance(entities, dict):
        return []

    labels: List[str] = []
    for engine_id in engine_ids:
        record = entities.get(engine_id, {})
        if not isinstance(record, dict):
            continue
        label = str(record.get("labels", {}).get("en", {}).get("value") or "").strip()
        if label:
            labels.append(label)
    return _sorted_unique(labels)

def _search_wikidata_entity_id(game_name: str) -> Optional[str]:
    if not game_name:
        return None
    for candidate in _title_search_candidates(game_name):
        url = (
            "https://www.wikidata.org/w/api.php?action=wbsearchentities&language=en&format=json"
            f"&limit=8&search={quote(candidate, safe='')}"
        )
        try:
            payload = _fetch_json(url, headers=_WIKIDATA_HTTP_HEADERS)
        except Exception:
            continue
        rows = payload.get("search", [])
        if not isinstance(rows, list):
            continue

        best_id = None
        best_score = 0
        for row in rows:
            if not isinstance(row, dict):
                continue
            label = str(row.get("label") or "").strip()
            if not label:
                continue
            score = _search_result_score(label, candidate)
            description = str(row.get("description") or "").lower()
            if "video game" in description:
                score += 20
            if score > best_score:
                best_score = score
                best_id = str(row.get("id") or "").strip() or None
        if best_id and best_score >= 100:
            return best_id
    return None

def _fetch_wikipedia_page_metadata(page_name: str) -> Optional[Dict[str, object]]:
    if not page_name:
        return None

    try:
        page_payload = _fetch_json(
            "https://en.wikipedia.org/w/api.php?action=query&prop=revisions|pageprops"
            f"&titles={quote(page_name, safe='')}"
            "&rvslots=main&rvprop=content&format=json",
            headers=_WIKI_HTTP_HEADERS,
        )
    except Exception:
        return None

    pages = page_payload.get("query", {}).get("pages", {})
    if not isinstance(pages, dict) or not pages:
        return None
    page_record = next(iter(pages.values()))
    if not isinstance(page_record, dict):
        return None

    metadata: Dict[str, object] = {"page": page_name, "engines": []}
    revisions = page_record.get("revisions", [])
    if isinstance(revisions, list) and revisions:
        slots = revisions[0].get("slots", {})
        if isinstance(slots, dict):
            main_slot = slots.get("main", {})
            if isinstance(main_slot, dict):
                wikitext = str(main_slot.get("*") or "")
                parsed = _parse_wikipedia_metadata(wikitext)
                if parsed:
                    metadata["engines"] = list(parsed.get("engines", []))

    pageprops = page_record.get("pageprops", {})
    if isinstance(pageprops, dict):
        wikibase_item = str(pageprops.get("wikibase_item") or "").strip()
        if wikibase_item:
            metadata["entity"] = wikibase_item
            entity = _fetch_wikidata_entity(wikibase_item)
            if entity:
                entity_engines = _resolve_wikidata_engine_labels(entity)
                if entity_engines:
                    metadata["engines"] = _sorted_unique(list(metadata.get("engines", [])) + entity_engines)

    return metadata if metadata.get("engines") else None

def _fetch_wiki_metadata(title: str) -> Optional[Dict[str, object]]:
    for candidate in _title_search_candidates(title):
        search_url = (
            "https://en.wikipedia.org/w/api.php?action=query&list=search&format=json"
            f"&srlimit=5&srsearch={quote(candidate, safe='')}"
        )
        try:
            payload = _fetch_json(search_url, headers=_WIKI_HTTP_HEADERS)
        except Exception:
            continue
        rows = payload.get("query", {}).get("search", [])
        if not isinstance(rows, list):
            continue

        best_title = None
        best_score = 0
        for row in rows:
            page_title = str(row.get("title") or "").strip()
            if not page_title:
                continue
            score = _search_result_score(page_title, candidate)
            if score > best_score:
                best_score = score
                best_title = page_title
        if best_title and best_score >= 80:
            metadata = _fetch_wikipedia_page_metadata(best_title)
            if metadata:
                return metadata

    entity_id = _search_wikidata_entity_id(title)
    if not entity_id:
        return None
    entity = _fetch_wikidata_entity(entity_id)
    if not entity:
        return None

    entity_engines = _resolve_wikidata_engine_labels(entity)
    wiki_title = str(entity.get("sitelinks", {}).get("enwiki", {}).get("title") or "").strip()
    metadata: Dict[str, object] = {"entity": entity_id, "engines": entity_engines}
    if wiki_title:
        metadata["page"] = wiki_title
        wiki_page_metadata = _fetch_wikipedia_page_metadata(wiki_title)
        if wiki_page_metadata:
            metadata["engines"] = _sorted_unique(
                list(metadata.get("engines", [])) + list(wiki_page_metadata.get("engines", []))
            )
    return metadata if metadata.get("engines") else None

def _fetch_awacy_dataset() -> List[Dict[str, object]]:
    global _AWACY_DATASET_MEMO
    if _AWACY_DATASET_MEMO is not None:
        return list(_AWACY_DATASET_MEMO)

    cache_entries = _load_metadata_cache("awacy_dataset")
    found, cached = _cache_lookup(cache_entries, "dataset", _AWACY_CACHE_TTL)
    if found and isinstance(cached, list):
        _AWACY_DATASET_MEMO = [item for item in cached if isinstance(item, dict)]
        return list(_AWACY_DATASET_MEMO)

    payload = _fetch_json_payload(_AWACY_DATASET_URL, headers=_AWACY_HTTP_HEADERS)
    dataset = [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []
    _cache_store(cache_entries, "dataset", dataset)
    _save_metadata_cache("awacy_dataset", cache_entries)
    _AWACY_DATASET_MEMO = dataset
    return list(dataset)

def _lookup_awacy_record(appid: int, game_name: str) -> Optional[Dict[str, object]]:
    dataset = _fetch_awacy_dataset()
    if not dataset:
        return None

    if appid > 0:
        for record in dataset:
            store_ids = record.get("storeIds", {})
            if not isinstance(store_ids, dict):
                continue
            try:
                if int(store_ids.get("steam", 0) or 0) == appid:
                    return record
            except (TypeError, ValueError):
                continue

    wanted_name = str(game_name or "").strip()
    if not wanted_name:
        return None

    best_record: Optional[Dict[str, object]] = None
    best_score = 0
    for record in dataset:
        candidate_name = str(record.get("name") or "").strip()
        if not candidate_name:
            continue
        score = _search_result_score(candidate_name, wanted_name)
        if score > best_score:
            best_score = score
            best_record = record
    return best_record if best_score >= 100 else None

def _extract_awacy_anticheats(record: Optional[Dict[str, object]]) -> List[str]:
    if not record:
        return []
    anticheats = record.get("anticheats", [])
    if not isinstance(anticheats, list):
        return []
    return _normalize_anti_cheat_names(str(value) for value in anticheats if str(value).strip())

def _extract_pcgw_anticheats(pcgw_data: Optional[Dict[str, object]]) -> List[str]:
    if not pcgw_data:
        return []

    anticheats: List[str] = []
    ac_field = pcgw_data.get("anticheat")
    if ac_field:
        if isinstance(ac_field, str):
            anticheats.append(ac_field.strip())
        elif isinstance(ac_field, list):
            for ac in ac_field:
                if isinstance(ac, str) and ac.strip():
                    anticheats.append(ac.strip())
    
    ac_array = pcgw_data.get("anticheats")
    if isinstance(ac_array, list):
        for ac in ac_array:
            if isinstance(ac, str) and ac.strip():
                anticheats.append(ac.strip())

    text_content = ""
    for field in ["text", "content", "description"]:
        value = pcgw_data.get(field)
        if isinstance(value, str):
            text_content += " " + value.lower()

    if text_content:
        ac_keywords = {
            "easy anti-cheat": "Easy Anti-Cheat",
            "battleye": "BattlEye",
            "vanguard": "Riot Vanguard",
            "xigncode3": "XIGNCODE3",
            "gameguard": "nProtect GameGuard",
            "fairfight": "FairFight",
            "denuvo": "Denuvo Anti-Cheat",
            "equ8": "EQU8",
            "punkbuster": "PunkBuster",
            "vac": "VAC",
            "ea javelin": "EA Javelin",
            "hyperion": "Hyperion",
            "netease": "Netease Anti-Cheat Expert",
            "nexon game security": "Nexon Game Security",
            "byfron": "Byfron",
        }
        for keyword, full_name in ac_keywords.items():
            if keyword in text_content and full_name not in anticheats:
                anticheats.append(full_name)

    return _normalize_anti_cheat_names(anticheats)

def _fetch_pcgw_metadata(appid: int, game_name: str = "") -> Optional[Dict[str, object]]:
    page_name = ""
    if appid:
        lookup_url = (
            "https://www.pcgamingwiki.com/w/api.php?action=cargoquery&format=json"
            "&tables=Infobox_game"
            "&fields=Infobox_game._pageName%3DPage,Infobox_game.Steam_AppID"
            f"&where=Infobox_game.Steam_AppID%20HOLDS%20%22{quote(str(appid), safe='')}%22"
        )
        try:
            lookup_payload = _fetch_json(lookup_url, headers=_PCGW_HTTP_HEADERS)
        except Exception:
            lookup_payload = {}

        rows = lookup_payload.get("cargoquery", [])
        if isinstance(rows, list) and rows:
            title_data = rows[0].get("title", {})
            if isinstance(title_data, dict):
                page_name = str(title_data.get("Page") or "").strip()

    if not page_name and game_name:
        page_name = _search_pcgw_page_name(game_name) or ""

    return _fetch_pcgw_page_metadata(page_name) if page_name else None

def _classify_remote_game(
    appid: int,
    name: str,
    store_data: Optional[Dict[str, object]],
    pcgw_data: Optional[Dict[str, object]] = None,
    wiki_data: Optional[Dict[str, object]] = None,
    steam_path: Optional[str] = None,
) -> SteamInstalledGame:
    evidence: List[str] = []
    anti_cheats: List[str] = []
    engine = "unknown"
    version = ""
    method = "steam_desktop_ownership"
    scan_source = "steam_desktop_metadata"

    if store_data:
        evidence.append("Steam store metadata fetched")
        text_blob = _extract_store_text(store_data)
        store_anti_cheats = _extract_remote_anti_cheat_markers(text_blob)
        anti_cheats.extend(store_anti_cheats)
        engine, version, method = _detect_engine_from_text(text_blob)
        if method != "steam_desktop_ownership":
            evidence.append(f"Store metadata references {engine.replace('_', ' ')}")

        platforms = store_data.get("platforms", {})
        if isinstance(platforms, dict) and platforms.get("windows"):
            evidence.append("Steam store lists Windows support")
        elif isinstance(platforms, dict):
            evidence.append("Steam store does not clearly list Windows support")
    else:
        evidence.append("Steam store metadata unavailable")

    if steam_path and (engine == "unknown" or not anti_cheats):
        local_data = _analyze_local_steam_metadata(appid, steam_path, name)
        if local_data:
            local_engine = local_data.get("engine", "unknown")
            local_anti_cheats = local_data.get("anti_cheats", [])
            local_evidence = local_data.get("evidence", [])
            if local_engine != "unknown" and _engine_confidence_rank(local_engine) > _engine_confidence_rank(engine):
                engine = local_engine
                version = local_data.get("version", "")
                method = local_data.get("method", "steam_manifest")
                evidence.extend([f"Steam manifest analysis: {ev}" for ev in local_evidence])
                scan_source = _merge_scan_source(scan_source, "local")
            if local_anti_cheats:
                anti_cheats.extend(local_anti_cheats)
                scan_source = _merge_scan_source(scan_source, "local")

    if pcgw_data:
        pcgw_page = str(pcgw_data.get("page") or "").strip()
        if pcgw_page:
            evidence.append(f"PCGamingWiki metadata fetched ({pcgw_page})")
        pcgw_anti_cheats = _extract_pcgw_anticheats(pcgw_data)
        if pcgw_anti_cheats:
            anti_cheats = _sorted_unique(list(anti_cheats) + pcgw_anti_cheats)
            scan_source = _merge_scan_source(scan_source, "pcgw")

        for raw_engine in pcgw_data.get("engines", []):
            candidate_engine, candidate_version, candidate_method = _normalize_external_engine(
                str(raw_engine),
                "pcgw_engine_infobox",
            )
            if _engine_confidence_rank(candidate_engine) > _engine_confidence_rank(engine):
                engine = candidate_engine
                version = candidate_version
                method = candidate_method
                evidence.append(f"PCGamingWiki lists engine: {_clean_wiki_markup(str(raw_engine))}")
                scan_source = _merge_scan_source(scan_source, "pcgw")
                break
            if engine == "unknown" and candidate_engine != "unknown":
                engine = candidate_engine
                version = candidate_version
                method = candidate_method
                evidence.append(f"PCGamingWiki lists engine: {_clean_wiki_markup(str(raw_engine))}")
                scan_source = _merge_scan_source(scan_source, "pcgw")
                break

    if wiki_data:
        wiki_page = str(wiki_data.get("page") or "").strip()
        wiki_entity = str(wiki_data.get("entity") or "").strip()
        if wiki_page:
            evidence.append(f"Wikipedia metadata fetched ({wiki_page})")
        elif wiki_entity:
            evidence.append(f"Wikidata metadata fetched ({wiki_entity})")

        for raw_engine in wiki_data.get("engines", []):
            candidate_engine, candidate_version, candidate_method = _normalize_external_engine(
                str(raw_engine),
                "wikipedia_engine_infobox" if wiki_page else "wikidata_engine_property",
            )
            if _engine_confidence_rank(candidate_engine) > _engine_confidence_rank(engine):
                engine = candidate_engine
                version = candidate_version
                method = candidate_method
                evidence.append(f"Encyclopedia metadata lists engine: {_clean_wiki_markup(str(raw_engine))}")
                scan_source = _merge_scan_source(scan_source, "wiki")
                break
            if engine == "unknown" and candidate_engine != "unknown":
                engine = candidate_engine
                version = candidate_version
                method = candidate_method
                evidence.append(f"Encyclopedia metadata lists engine: {_clean_wiki_markup(str(raw_engine))}")
                scan_source = _merge_scan_source(scan_source, "wiki")
                break

    if engine == "unknown":
        remote_override = _REMOTE_ENGINE_APPID_OVERRIDES.get(appid)
        if remote_override:
            engine, version, method = remote_override
            evidence.append(f"Matched curated remote engine override for appid {appid}")
            scan_source = _merge_scan_source(scan_source, "override")

    awacy_record = _lookup_awacy_record(appid, name)
    awacy_anti_cheats = _extract_awacy_anticheats(awacy_record)
    if awacy_anti_cheats:
        anti_cheats.extend(awacy_anti_cheats)
        awacy_name = str(awacy_record.get("name") or name).strip() if awacy_record else name
        evidence.append(f"AWACY anti-cheat data fetched ({awacy_name})")
        scan_source = _merge_scan_source(scan_source, "awacy")

    anti_cheats = _normalize_anti_cheat_names(anti_cheats)
    if anti_cheats:
        evidence.append("Remote anti-cheat hints: " + ", ".join(anti_cheats))

    diag = _build_diagnostic(
        appid=appid,
        name=name,
        engine=engine,
        detection_method=method,
        anti_cheats=anti_cheats,
        evidence=evidence,
        installed=False,
        scan_source=scan_source,
    )

    return SteamInstalledGame(
        appid=appid,
        name=name,
        library_path="",
        install_dir="",
        manifest_path="",
        executable_path="",
        engine=engine,
        version=version,
        detection_method=method,
        confidence=str(diag["confidence"]),
        anti_cheats=anti_cheats,
        kernel_recommended=bool(diag["kernel_recommended"]),
        likely_dumpable=bool(diag["likely_dumpable"]),
        support_tier=str(diag["support_tier"]),
        evidence=list(diag["evidence"]),
        installed=False,
        owned_on_account=True,
        scan_source=str(diag["scan_source"]),
        support_score=int(diag["support_score"]),
        diagnostic_summary=str(diag["diagnostic_summary"]),
        next_step=str(diag["next_step"]),
        diagnostic_flags=list(diag["diagnostic_flags"]),
        store_url=str(diag["store_url"]),
    )

def _detect_engine_from_file_list(
    file_list: List[str],
    *,
    source_label: str = "file pattern",
) -> Tuple[str, str, List[str]]:
    if not file_list:
        return "unknown", "", []

    evidence: List[Tuple[str, str]] = []
    engine_scores: Dict[str, int] = {}
    for file_path in file_list:
        file_lower = file_path.lower()
        for pattern, engine_id in _STEAMDB_FILE_PATTERNS.items():
            if pattern.lower() in file_lower:
                engine_scores[engine_id] = engine_scores.get(engine_id, 0) + 10
                if engine_id not in [engine for engine, _reason in evidence]:
                    evidence.append((engine_id, f"{source_label}: {pattern}"))

    gamemaker_indicators = 0
    for file_path in file_list:
        file_lower = file_path.lower()
        if "options.ini" in file_lower:
            gamemaker_indicators += 1
        elif "data.win" in file_lower:
            gamemaker_indicators += 1
        elif file_lower.startswith("snd_") and file_lower.endswith(".ogg"):
            gamemaker_indicators += 1

    if gamemaker_indicators >= 2 and "gamemaker" not in engine_scores:
        engine_scores["gamemaker"] = 15
        evidence.append(("gamemaker", f"{source_label}: GameMaker layout"))

    if engine_scores:
        best_engine = max(engine_scores.items(), key=lambda x: x[1])
        return best_engine[0], "", [f"{engine_id} - {reason}" for engine_id, reason in evidence]

    return "unknown", "", []

def _detect_anticheat_from_file_list(file_list: List[str]) -> List[str]:
    if not file_list:
        return []

    detected_cheats = set()
    for file_path in file_list:
        file_lower = file_path.lower()
        for pattern, anticheat_name in _STEAMDB_ANTICHEAT_PATTERNS.items():
            if pattern.lower() in file_lower:
                detected_cheats.add(anticheat_name)
    return _normalize_anti_cheat_names(detected_cheats)

def _collect_manifest_text_hints(manifest_path: Path) -> List[str]:
    try:
        manifest_text = manifest_path.read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        return []

    hints: List[str] = []
    for token in (
        "unityplayer.dll",
        "gameassembly.dll",
        "il2cpp_data",
        "mono",
        "engine/binaries",
        "engine/content",
        "easyanticheat",
        "battleye",
        "byfron",
        "xigncode",
        "gameguard",
        "vanguard",
        "vac",
        "equ8",
        "punkbuster",
        "fairfight",
    ):
        if token in manifest_text:
            hints.append(token)
    return hints

def _analyze_local_steam_metadata(
    appid: int,
    steam_path: str,
    game_name: str = "",
) -> Optional[Dict[str, object]]:
    if not appid or not steam_path:
        return None

    cache_entries = _load_metadata_cache("local_steam")
    cache_key = f"{Path(steam_path)}::{appid}"
    found, cached = _cache_lookup(cache_entries, cache_key, _LOCAL_STEAM_METADATA_CACHE_TTL)
    if found:
        return cached if isinstance(cached, dict) else None

    result: Optional[Dict[str, object]] = None
    for library in get_steam_library_paths(steam_path):
        library_path = Path(library)
        manifest_path = library_path / "steamapps" / f"appmanifest_{appid}.acf"
        if not manifest_path.is_file():
            continue

        manifest = _read_appmanifest(manifest_path)
        install_dir = str(manifest.get("installdir", "") or "").strip()
        resolved_name = str(manifest.get("name", "") or game_name or f"App {appid}")
        evidence = [f"Steam manifest found: {manifest_path.name}"]
        anti_cheats: List[str] = []
        engine = "unknown"
        version = ""
        method = "steam_manifest"

        if install_dir:
            game_dir = library_path / "steamapps" / "common" / install_dir
            if game_dir.is_dir():
                exe_path = _pick_primary_executable(game_dir, resolved_name)
                engine, version, method, markers = _detect_unity_runtime(game_dir, exe_path)
                evidence.extend(markers)
                if engine == "unknown":
                    engine, version, method, markers = _detect_unreal_runtime(exe_path, game_dir)
                    evidence.extend(markers)
                if engine == "unknown":
                    engine, version, method, markers = _detect_disk_engine_runtime(appid, game_dir, resolved_name, exe_path)
                    evidence.extend(markers)
                anti_cheats = _detect_anticheat_markers(game_dir)
                if anti_cheats:
                    evidence.append("Local anti-cheat markers: " + ", ".join(anti_cheats))
                if exe_path:
                    evidence.append(f"Manifest install dir resolved to {game_dir}")
                    evidence.append(f"Manifest primary exe: {exe_path.name}")

        if engine == "unknown" and not anti_cheats:
            manifest_hints = _collect_manifest_text_hints(manifest_path)
            if manifest_hints:
                hinted_engine, hinted_version, hinted_evidence = _detect_engine_from_file_list(
                    manifest_hints,
                    source_label="manifest hint",
                )
                hinted_anti_cheats = _detect_anticheat_from_file_list(manifest_hints)
                if hinted_engine != "unknown":
                    engine = hinted_engine
                    version = hinted_version
                    method = "steam_manifest_hints"
                    evidence.extend(hinted_evidence)
                if hinted_anti_cheats:
                    anti_cheats = hinted_anti_cheats
                    evidence.append("Manifest anti-cheat hints: " + ", ".join(hinted_anti_cheats))

        if engine != "unknown" or anti_cheats:
            result = {
                "engine": engine,
                "version": version,
                "evidence": evidence,
                "anti_cheats": _normalize_anti_cheat_names(anti_cheats),
                "method": method,
                "source": "local_steam_manifest",
                "manifest_path": str(manifest_path),
            }
            break

    _cache_store(cache_entries, cache_key, result)
    _save_metadata_cache("local_steam", cache_entries)
    return result

def _fetch_owned_games(steam_path: str) -> List[Dict[str, object]]:
    local_app_index = _load_local_app_index(steam_path)
    candidate_ids = [
        appid
        for appid, metadata in local_app_index.items()
        if metadata.get("type", "") in _OWNED_LIBRARY_TYPES
    ]

    owned_appids = _query_owned_appids_via_helper(steam_path, candidate_ids)
    games: List[Dict[str, object]] = []
    for appid in owned_appids:
        metadata = local_app_index.get(appid, {})
        games.append({
            "appid": appid,
            "name": str(metadata.get("name") or f"App {appid}"),
        })
    return games

def _fetch_store_details(appid: int) -> Optional[Dict[str, object]]:
    if not appid:
        return None
    
    url = f"https://store.steampowered.com/api/appdetails?appids={appid}&l=english"
    
    try:
        payload = _fetch_json(url)
        if not payload:
            return None
            
        node = payload.get(str(appid), {})
        if not isinstance(node, dict) or not node.get("success"):
            if str(appid) not in payload and payload:
                for key_str, value in payload.items():
                    try:
                        if int(key_str) == appid and isinstance(value, dict) and value.get("success"):
                            node = value
                            break
                    except ValueError:
                        continue
            
            if not isinstance(node, dict) or not node.get("success"):
                return None
                
        data = node.get("data")
        return data if isinstance(data, dict) else None
    except Exception as e:
        print(f"Warning: Failed to fetch store details for appid {appid}: {e}")
        return None

def _fetch_store_details_many(appids: Iterable[int]) -> Dict[int, Dict[str, object]]:
    unique_ids = sorted({int(appid) for appid in appids if int(appid) > 0})
    if not unique_ids:
        return {}

    cache_entries = _load_metadata_cache("store")
    results: Dict[int, Dict[str, object]] = {}
    missing_ids: List[int] = []
    for appid in unique_ids:
        found, cached = _cache_lookup(cache_entries, appid, _STORE_CACHE_TTL)
        if found:
            if isinstance(cached, dict):
                results[appid] = cached
            continue
        missing_ids.append(appid)

    if missing_ids:
        max_workers = min(12, max(1, len(missing_ids)))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            fetched = executor.map(_fetch_store_details, missing_ids)
            for appid, store_data in zip(missing_ids, fetched):
                _cache_store(cache_entries, appid, store_data)
                if store_data:
                    results[appid] = store_data
        _save_metadata_cache("store", cache_entries)
    return results

def _needs_pcgw_metadata(
    appid: int,
    game_name: str,
    store_data: Optional[Dict[str, object]],
) -> bool:
    if appid in _REMOTE_ENGINE_APPID_OVERRIDES:
        return False
    if not store_data:
        return True
    text_blob = _extract_store_text(store_data)
    has_engine = _detect_engine_from_text(text_blob)[0] != "unknown"
    has_anticheat = bool(_extract_remote_anti_cheat_markers(text_blob))
    if not has_anticheat:
        awacy_record = _lookup_awacy_record(appid, str(store_data.get("name") or game_name or ""))
        has_anticheat = bool(_extract_awacy_anticheats(awacy_record))
    return not (has_engine and has_anticheat)

def _needs_wiki_metadata(
    store_data: Optional[Dict[str, object]],
    pcgw_data: Optional[Dict[str, object]],
) -> bool:
    if store_data and _detect_engine_from_text(_extract_store_text(store_data))[0] != "unknown":
        return False
    if pcgw_data:
        for raw_engine in pcgw_data.get("engines", []):
            if _normalize_external_engine(str(raw_engine), "pcgw_engine_infobox")[0] != "unknown":
                return False
    return True

def _fetch_pcgw_metadata_many(
    appids: Iterable[int],
    app_names: Optional[Dict[int, str]] = None,
) -> Dict[int, Dict[str, object]]:
    unique_ids = sorted({int(appid) for appid in appids if int(appid) > 0})
    if not unique_ids:
        return {}

    cache_entries = _load_metadata_cache("pcgw")
    results: Dict[int, Dict[str, object]] = {}
    missing_ids: List[int] = []
    for appid in unique_ids:
        found, cached = _cache_lookup(cache_entries, appid, _PCGW_CACHE_TTL)
        if found:
            if isinstance(cached, dict):
                results[appid] = cached
            continue
        missing_ids.append(appid)

    if missing_ids:
        max_workers = min(8, max(1, len(missing_ids)))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(_fetch_pcgw_metadata, appid, (app_names or {}).get(appid, "")): appid
                for appid in missing_ids
            }
            for future, appid in future_map.items():
                try:
                    metadata = future.result()
                except Exception:
                    metadata = None
                _cache_store(cache_entries, appid, metadata)
                if metadata:
                    results[appid] = metadata
        _save_metadata_cache("pcgw", cache_entries)
    return results

def _fetch_wiki_metadata_many(app_names: Iterable[str]) -> Dict[str, Dict[str, object]]:
    unique_names = sorted({str(name).strip() for name in app_names if str(name).strip()})
    if not unique_names:
        return {}

    cache_entries = _load_metadata_cache("wiki")
    results: Dict[str, Dict[str, object]] = {}
    missing_names: List[str] = []
    for name in unique_names:
        found, cached = _cache_lookup(cache_entries, name, _WIKI_CACHE_TTL)
        if found:
            if isinstance(cached, dict):
                results[name] = cached
            continue
        missing_names.append(name)

    if missing_names:
        max_workers = min(2, max(1, len(missing_names)))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {executor.submit(_fetch_wiki_metadata, name): name for name in missing_names}
            for future, name in future_map.items():
                try:
                    metadata = future.result()
                except Exception:
                    metadata = None
                if metadata:
                    _cache_store(cache_entries, name, metadata)
                    results[name] = metadata
        _save_metadata_cache("wiki", cache_entries)
    return results

def _scan_installed_games(
    resolved_steam_path: str,
    *,
    limit: Optional[int] = None,
) -> List[SteamInstalledGame]:
    games: List[SteamInstalledGame] = []
    for index, (library_path, manifest) in enumerate(iter_installed_steam_games(resolved_steam_path)):
        if limit is not None and index >= limit:
            break

        name = manifest.get("name", f"App {manifest.get('appid', '?')}")
        installdir = manifest.get("installdir", "")
        appid_raw = manifest.get("appid", "0")
        try:
            appid = int(appid_raw)
        except ValueError:
            appid = 0
        if appid in _NON_GAME_APPIDS:
            continue

        game_dir = library_path / "steamapps" / "common" / installdir
        if not game_dir.is_dir():
            continue

        exe_path = _pick_primary_executable(game_dir, name)
        game = _classify_installed_game(appid, game_dir, name, exe_path)
        game.library_path = str(library_path)
        game.manifest_path = str(library_path / "steamapps" / f"appmanifest_{appid}.acf")
        games.append(game)
    return games

def scan_steam_library(
    steam_path: Optional[str] = None,
    *,
    limit: Optional[int] = None,
    include_owned_games: bool = False,
    steam_account: Optional[str] = None,
    progress_fn=None,
) -> SteamAuditReport:
    def _progress(msg: str):
        if progress_fn is not None:
            try:
                progress_fn(msg)
            except Exception:
                pass

    resolved_steam_path = get_steam_install_path(steam_path)
    accounts = get_steam_accounts(resolved_steam_path) if resolved_steam_path else []
    libraries = get_steam_library_paths(resolved_steam_path) if resolved_steam_path else []

    if not resolved_steam_path:
        raise FileNotFoundError("Could not locate a Steam install with a steamapps directory.")

    if include_owned_games and not is_steam_running():
        raise RuntimeError(
            "Steam is not running. Start Steam and sign in to use --steam-owned mode, "
            "or run without --steam-owned to scan only installed games."
        )

    _progress("Scanning installed Steam games...")
    installed_games = _scan_installed_games(resolved_steam_path, limit=limit)
    installed_by_appid = {game.appid: game for game in installed_games if game.appid}

    games: List[SteamInstalledGame]
    audit_mode = "installed"
    steamid = ""

    if include_owned_games:
        _progress("Checking Steam ownership via desktop client (this can take a moment)...")
        owned_games = _fetch_owned_games(resolved_steam_path)
        limited_owned_games = owned_games if limit is None else owned_games[:limit]
        remote_appids = [
            int(owned.get("appid", 0) or 0)
            for owned in limited_owned_games
            if int(owned.get("appid", 0) or 0) not in installed_by_appid
        ]
        _progress(f"Fetching store details for {len(remote_appids)} uninstalled games (may take a while on first run)...")
        remote_store_details = _fetch_store_details_many(
            remote_appids
        )
        pcgw_appids = [
            appid
            for appid in remote_appids
            if _needs_pcgw_metadata(
                appid,
                str(
                    (remote_store_details.get(appid, {}) or {}).get("name")
                    or next(
                        (
                            owned.get("name", "")
                            for owned in limited_owned_games
                            if int(owned.get("appid", 0) or 0) == appid
                        ),
                        "",
                    )
                ),
                remote_store_details.get(appid),
            )
        ]
        _progress(f"Fetching PCGamingWiki data for {len(pcgw_appids)} games...")
        remote_pcgw_details = _fetch_pcgw_metadata_many(
            pcgw_appids,
            {
                int(owned.get("appid", 0) or 0): str(owned.get("name", ""))
                for owned in limited_owned_games
            },
        )
        _progress("Fetching wiki engine metadata...")
        remote_wiki_details = _fetch_wiki_metadata_many(
            str((remote_store_details.get(int(owned.get("appid", 0) or 0), {}) or {}).get("name") or owned.get("name") or "")
            for owned in limited_owned_games
            if int(owned.get("appid", 0) or 0) in remote_appids
            and int(owned.get("appid", 0) or 0) not in _REMOTE_ENGINE_APPID_OVERRIDES
            and _needs_wiki_metadata(
                remote_store_details.get(int(owned.get("appid", 0) or 0)),
                remote_pcgw_details.get(int(owned.get("appid", 0) or 0)),
            )
        )
        _progress("Classifying games...")
        games = []
        for owned in limited_owned_games:
            appid = int(owned.get("appid", 0) or 0)
            name = str(owned.get("name", f"App {appid}"))
            local_game = installed_by_appid.get(appid)
            if local_game is not None:
                local_game.owned_on_account = True
                local_game.scan_source = "steam_desktop+installed_disk"
                local_game.evidence = list(local_game.evidence) + ["Confirmed in the running Steam desktop client"]
                games.append(local_game)
                continue

            store_data = remote_store_details.get(appid)
            if store_data and store_data.get("name"):
                name = store_data["name"]

            pcgw_data = remote_pcgw_details.get(appid)
            wiki_data = remote_wiki_details.get(name)
            remote_game = _classify_remote_game(appid, name, store_data, pcgw_data, wiki_data, resolved_steam_path)
            games.append(remote_game)

        seen_appids = {game.appid for game in games}
        for local_game in installed_games:
            if local_game.appid in seen_appids:
                continue
            local_game.scan_source = "installed_disk_only"
            games.append(local_game)
        audit_mode = "owned+installed"
    else:
        games = installed_games

    games.sort(
        key=lambda game: (
            _SUPPORT_PRIORITY.get(game.support_tier, 99),
            not game.installed,
            game.kernel_recommended,
            game.name.lower(),
        )
    )
    
    return SteamAuditReport(
        steam_path=resolved_steam_path or "",
        libraries=libraries,
        accounts=accounts,
        games=games,
        audit_mode=audit_mode,
        steamid=steamid,
    )

def format_steam_audit_report(report: SteamAuditReport) -> str:
    lines = [
        "Steam Library Audit",
        f"  Mode: {report.audit_mode}",
        f"  Steam: {report.steam_path or 'not required / not found locally'}",
        f"  Libraries: {len(report.libraries)}",
        f"  Total games: {len(report.games)}",
        f"  Installed locally: {sum(1 for game in report.games if game.installed)}",
        f"  Owned only: {sum(1 for game in report.games if not game.installed)}",
    ]

    if report.accounts:
        active = next((account for account in report.accounts if account.most_recent), report.accounts[0])
        lines.append(
            f"  Local Steam account: {active.persona_name or active.account_name or active.steamid}"
        )
    if report.steamid:
        lines.append(f"  Account audit SteamID: {report.steamid}")

    usermode_ready = [game for game in report.games if game.support_tier == "usermode_ready"]
    kernel_ready = [game for game in report.games if game.support_tier == "kernel_recommended"]
    needs_install = [
        game for game in report.games
        if game.support_tier in {"install_then_scan", "install_then_kernel"}
    ]
    engine_identified = [
        game for game in report.games
        if game.support_tier in {"engine_identified", "install_engine_identified"}
    ]
    manual_review = [game for game in report.games if game.support_tier == "manual_review"]

    lines.append("")
    lines.append(f"  Deep-ready in user mode: {len(usermode_ready)}")
    lines.append(f"  Kernel suggested: {len(kernel_ready)}")
    lines.append(f"  Owned-only / install to verify: {len(needs_install)}")
    lines.append(f"  Engine identified only: {len(engine_identified)}")
    lines.append(f"  Manual review: {len(manual_review)}")
    lines.append("")

    def _render_section(title: str, games: Iterable[SteamInstalledGame], limit: int = 12) -> None:
        rendered = 0
        lines.append(title)
        for game in games:
            installed_label = "installed" if game.installed else "owned-only"
            engine_label = game.engine + (f" {game.version}" if game.version else "")
            anti_cheat = f" [{', '.join(game.anti_cheats)}]" if game.anti_cheats else ""
            lines.append(f"  - {game.name} ({installed_label}, {engine_label}){anti_cheat}")
            lines.append(f"    {game.diagnostic_summary}")
            rendered += 1
            if rendered >= limit:
                break
        if rendered == 0:
            lines.append("  - none")

    _render_section("User-mode ready:", usermode_ready)
    lines.append("")
    _render_section("Kernel suggested:", kernel_ready)
    lines.append("")
    _render_section("Install for deeper scan:", needs_install)
    lines.append("")
    _render_section("Engine identified (not yet targeted):", engine_identified)
    lines.append("")
    _render_section("Manual review:", manual_review)
    return "\n".join(lines)

def write_steam_audit_report(report: SteamAuditReport, output_path: str) -> str:
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return str(target)
