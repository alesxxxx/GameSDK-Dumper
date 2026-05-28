
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

_STEAM_LIBRARY_FILE = Path("steamapps") / "libraryfolders.vdf"
_APPMANIFEST_RE = re.compile(r"appmanifest_(\d+)\.acf$", re.IGNORECASE)
_UE_SHIPPING_SUFFIX_RE = re.compile(
    r"(?i)(?:[-_]?win64[-_]?shipping|[-_]?win32[-_]?shipping|[-_]?shipping|[-_]?win64|[-_]?win32)$"
)

def _normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (value or "").lower())

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

def get_steam_library_paths(steam_path: str) -> List[str]:
    libraries = [Path(steam_path)]
    parsed = _read_vdf_file(Path(steam_path) / _STEAM_LIBRARY_FILE)
    library_root = parsed.get("libraryfolders", {})
    if isinstance(library_root, dict):
        for value in library_root.values():
            raw_path = value.get("path") if isinstance(value, dict) else value
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

def _iter_installed_manifests(steam_path: str):
    for library in get_steam_library_paths(steam_path):
        steamapps = Path(library) / "steamapps"
        try:
            entries = sorted(steamapps.iterdir(), key=lambda item: item.name.lower())
        except OSError:
            continue
        for entry in entries:
            if not entry.is_file() or not _APPMANIFEST_RE.match(entry.name):
                continue
            manifest = _read_appmanifest(entry)
            if manifest:
                yield Path(library), manifest

def _candidate_keys(process_name: str = "", game_name: str = "") -> Set[str]:
    keys: Set[str] = set()
    values = [process_name or "", game_name or ""]
    for value in values:
        if not value:
            continue
        stem = Path(str(value)).stem
        keys.add(_normalize_key(stem))
        trimmed = _UE_SHIPPING_SUFFIX_RE.sub("", stem)
        if trimmed:
            keys.add(_normalize_key(trimmed))
        text = str(value).replace(".exe", "").replace(".dll", "")
        keys.add(_normalize_key(text))
        trimmed_text = _UE_SHIPPING_SUFFIX_RE.sub("", text)
        if trimmed_text:
            keys.add(_normalize_key(trimmed_text))
    return {item for item in keys if item}

def _manifest_matches(manifest: Dict[str, str], keys: Iterable[str]) -> bool:
    name_key = _normalize_key(str(manifest.get("name", "") or ""))
    install_key = _normalize_key(str(manifest.get("installdir", "") or ""))
    for key in keys:
        if not key:
            continue
        if key == name_key or key == install_key:
            return True
        if key and (key in name_key or key in install_key or name_key in key or install_key in key):
            return True
    return False

def _exe_exists_with_name(game_dir: Path, process_name: str, max_depth: int = 4) -> bool:
    target = (process_name or "").strip().lower()
    if not target:
        return False
    queue = [(game_dir, 0)]
    while queue:
        current, depth = queue.pop(0)
        try:
            with os.scandir(current) as it:
                for entry in it:
                    path = Path(entry.path)
                    if entry.is_file() and entry.name.lower() == target:
                        return True
                    if entry.is_dir() and depth < max_depth:
                        queue.append((path, depth + 1))
        except OSError:
            continue
    return False

def infer_steam_appid(
    *,
    process_name: str = "",
    game_name: str = "",
    explicit_steam_path: Optional[str] = None,
) -> Optional[int]:
    steam_path = get_steam_install_path(explicit_steam_path)
    if not steam_path:
        return None

    keys = _candidate_keys(process_name=process_name, game_name=game_name)
    if not keys and not process_name:
        return None

    for library_path, manifest in _iter_installed_manifests(steam_path):
        appid_raw = str(manifest.get("appid", "") or "").strip()
        try:
            appid = int(appid_raw)
        except (TypeError, ValueError):
            continue
        if appid <= 0:
            continue

        if _manifest_matches(manifest, keys):
            return appid

        install_dir = str(manifest.get("installdir", "") or "").strip()
        if process_name and install_dir:
            game_dir = library_path / "steamapps" / "common" / install_dir
            if game_dir.is_dir() and _exe_exists_with_name(game_dir, process_name):
                return appid

    return None
