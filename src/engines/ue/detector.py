
import os
from typing import Dict, Optional

from src.core.memory import get_pid_by_name, get_module_base, get_module_size
from src.core.pe_parser import (
    extract_ue_build_info,
    get_pe_rdata_data_scan_ranges,
    get_ue_version_from_pe,
    get_version_info,
    scan_strings_on_disk,
)

_CURATED_UE_PROCESS_HINTS = {
    "back4blood.exe": (
        "ue4",
        "",
        "Back 4 Blood public metadata reports Unreal Engine 4; exact minor version was not exposed by process or PE strings",
    ),
    "gobi-win64-shipping.exe": (
        "ue4",
        "",
        "Back 4 Blood public metadata reports Unreal Engine 4; exact minor version was not exposed by process or PE strings",
    ),
}

def choose_ue_scan_version(engine: str, version: str) -> str:
    if version:
        return version
    if engine == "ue5":
        return "5.2"
    if engine == "ue_unknown":
        return "5.2"
    return "4.27"

def _curated_ue_process_hint(process_name: str) -> Optional[Dict]:
    key = os.path.basename(process_name or "").lower()
    hint = _CURATED_UE_PROCESS_HINTS.get(key)
    if not hint:
        return None

    engine, version, reason = hint
    return {
        "engine": engine,
        "version": version,
        "confidence": "medium",
        "method": "curated_process_hint",
        "details": {"hint": reason},
    }

def _scan_loaded_module_for_ue(handle: int, module_base: int, module_size: int) -> Optional[Dict]:
    from src.core.memory import read_bytes

    ranges = get_pe_rdata_data_scan_ranges(handle, module_base)
    if not ranges:
        ranges = [(module_base, module_base + min(module_size, 8 * 1024 * 1024))]

    bytes_budget = 8 * 1024 * 1024
    chunk_size = 512 * 1024

    for start, end in ranges:
        addr = start
        while addr < end and bytes_budget > 0:
            read_size = min(chunk_size, end - addr, bytes_budget)
            data = read_bytes(handle, addr, read_size)
            bytes_budget -= read_size
            addr += read_size

            if not data:
                continue

            try:
                text = data.decode("latin-1", errors="ignore")
            except Exception:
                continue

            info = extract_ue_build_info(text)
            if not info:
                continue

            engine, version = info
            return {
                "engine": engine,
                "version": version,
                "confidence": "high" if version else "medium",
                "method": "module_string_scan",
                "details": {
                    "hint": "Detected Unreal markers in loaded module memory",
                },
            }

    return None

def _resolve_main_module_range(pid: int, process_name: str) -> tuple[int, int]:
    base = get_module_base(pid, process_name)
    size = get_module_size(pid, process_name)

    if base and size:
        return base, size

    try:
        from src.core.driver import get_module_base_kernel, get_module_size_kernel

        base = base or get_module_base_kernel(pid)
        if base:
            size = size or get_module_size_kernel(pid, base)
    except Exception:
        pass

    return base or 0, size or 0

def detect_engine(
    process_name: str,
    exe_path: Optional[str] = None,
) -> Dict:
    curated_hint = _curated_ue_process_hint(process_name)
    result = {
        "engine": "unknown",
        "version": "",
        "confidence": "low",
        "method": "none",
        "details": {},
    }

    if exe_path and os.path.isfile(exe_path):
        version = get_ue_version_from_pe(exe_path)
        if version:
            major = int(version.split(".")[0])
            result["engine"] = "ue5" if major >= 5 else "ue4"
            result["version"] = version
            result["confidence"] = "high"
            result["method"] = "pe_version_info"
            result["details"]["version_info"] = get_version_info(exe_path)
            return result

        ue_strings = []
        for needle in ("++UE", "UE5", "UE4", "UnrealEngine"):
            ue_strings = scan_strings_on_disk(exe_path, needle, ".rdata")
            if ue_strings:
                break

        if ue_strings:
            matched = ue_strings[0][1]
            info = extract_ue_build_info(matched)
            if info:
                result["engine"], result["version"] = info
                result["confidence"] = "high" if result["version"] else "medium"
            elif curated_hint:
                result.update(curated_hint)
            else:
                result["engine"] = "ue_unknown"
                result["confidence"] = "low"
                result["details"]["hint"] = (
                    "Found generic Unreal string but no UE major/minor marker"
                )
            if result.get("method") == "curated_process_hint":
                result["details"]["string_scan_method"] = "pe_string_scan"
            else:
                result["method"] = "pe_string_scan"
            result["details"]["matched_string"] = matched
            return result

    if not exe_path:
        exe_path = _find_exe_from_process(process_name)
        if exe_path:
            return detect_engine(process_name, exe_path)

    pid = get_pid_by_name(process_name)
    if pid:
        base, size = _resolve_main_module_range(pid, process_name)
        if base and size:
            from src.core.memory import attach, detach

            handle = attach(pid)
            if handle:
                try:
                    mem_result = _scan_loaded_module_for_ue(handle, base, size)
                    if mem_result:
                        return mem_result
                finally:
                    detach(handle)

        if curated_hint:
            return curated_hint

        pname_lower = process_name.lower()
        if "shipping" in pname_lower or "win64" in pname_lower:
            result["engine"] = "ue_unknown"
            result["confidence"] = "low"
            result["method"] = "process_name_heuristic"
            result["details"]["hint"] = "Win64-Shipping naming is shared by UE4 and UE5"
            return result

    if curated_hint:
        return curated_hint

    return result

def _get_exe_path_from_pid(pid: int) -> Optional[str]:
    import ctypes

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    handle = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None

    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = ctypes.c_uint32(1024)
        if k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            path = buf.value
            if os.path.isfile(path):
                return path
    finally:
        k32.CloseHandle(handle)

    return None

def find_il2cpp_module(pid: int, exe_path: Optional[str] = None) -> Optional[str]:
    from src.core.memory import enumerate_modules

    if get_module_base(pid, "GameAssembly.dll"):
        return "GameAssembly.dll"

    game_dir: Optional[str] = None
    if exe_path and os.path.isfile(exe_path):
        game_dir = os.path.dirname(os.path.abspath(exe_path))
    else:
        resolved_exe = _get_exe_path_from_pid(pid)
        if resolved_exe:
            game_dir = os.path.dirname(os.path.abspath(resolved_exe))

    has_il2cpp_data = False
    if game_dir and os.path.isdir(game_dir):
        try:
            for entry in os.listdir(game_dir):
                entry_path = os.path.join(game_dir, entry)
                if os.path.isdir(entry_path):
                    if os.path.isdir(os.path.join(entry_path, "il2cpp_data")):
                        has_il2cpp_data = True
                        break
                if entry == "il2cpp_data" and os.path.isdir(entry_path):
                    has_il2cpp_data = True
                    break
        except OSError:
            pass

    if not has_il2cpp_data:
        return None

    system_root = os.environ.get("SystemRoot", r"C:\Windows").lower()
    game_dir_lower = game_dir.lower() if game_dir else ""

    skip_names = {
        "steam_api64.dll",
        "steam_api.dll",
        "d3d11.dll",
        "d3d12.dll",
        "dxgi.dll",
        "xinput1_3.dll",
        "xinput1_4.dll",
        "xinput9_1_0.dll",
    }

    best_name: Optional[str] = None
    best_size = 0

    for mod_name, _base, mod_size, mod_path in enumerate_modules(pid):
        mod_path_lower = mod_path.lower()
        mod_name_lower = mod_name.lower()

        if mod_path_lower.startswith(system_root):
            continue
        if "steam" in mod_path_lower and "steamapps\\common" not in mod_path_lower:
            continue
        if game_dir_lower and not mod_path_lower.startswith(game_dir_lower):
            continue
        if not mod_name_lower.endswith(".dll"):
            continue
        if mod_name_lower in skip_names:
            continue

        if mod_size > best_size:
            best_size = mod_size
            best_name = mod_name

    return best_name

def _find_exe_from_process(process_name: str) -> Optional[str]:
    import ctypes

    pid = get_pid_by_name(process_name)
    if not pid:
        return None

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)

    handle = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None

    try:
        buf = ctypes.create_unicode_buffer(1024)
        if psapi.GetModuleFileNameExW(handle, None, buf, 1024):
            path = buf.value
            if os.path.isfile(path):
                return path

        size = ctypes.c_uint32(1024)
        if k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            path = buf.value
            if os.path.isfile(path):
                return path
    finally:
        k32.CloseHandle(handle)

    return None

def detect_engine_full(
    process_name: str,
    exe_path: Optional[str] = None,
    probe_layout: bool = False,
) -> Dict:
    from src.core.memory import attach, detach

    pid = get_pid_by_name(process_name)
    if pid:
        il2cpp_mod = find_il2cpp_module(pid, exe_path)
        if il2cpp_mod:
            return {
                "engine": "il2cpp",
                "version": "",
                "confidence": "high",
                "method": f"module_scan_{il2cpp_mod}",
                "details": {"hint": f"{il2cpp_mod} found - Unity IL2CPP build"},
                "case_preserving": None,
                "item_size": 24,
                "il2cpp_module": il2cpp_mod,
            }

        for mono_dll in ("mono.dll", "mono-2.0-bdwgc.dll", "mono-2.0.dll"):
            mono_base = get_module_base(pid, mono_dll)
            if mono_base:
                return {
                    "engine": "mono",
                    "version": "",
                    "confidence": "high",
                    "method": f"module_scan_{mono_dll}",
                    "details": {"hint": f"{mono_dll} found - Unity Mono build"},
                    "case_preserving": None,
                    "item_size": 24,
                }

        from src.engines.source.game_data import identify_game, ALL_GAMES
        _source_procs = set()
        for _g in ALL_GAMES:
            for _p in _g.process_names:
                _source_procs.add(_p.lower())

        is_source_process = process_name.lower() in _source_procs
        has_client_dll = bool(get_module_base(pid, "client.dll"))
        has_schemasystem_dll = bool(get_module_base(pid, "schemasystem.dll"))

        if has_schemasystem_dll or process_name.lower() == "cs2.exe":
            return {
                "engine": "source2",
                "version": "",
                "confidence": "high",
                "method": "source2_module_detect",
                "details": {
                    "hint": f"Source 2 Schema System detected",
                    "game_name": "Counter-Strike 2" if process_name.lower() == "cs2.exe" else "Unknown Source 2 Game",
                    "is_64bit": True,
                    "client_module": "client.dll",
                },
            }

        if is_source_process or has_client_dll:
            game = identify_game(process_name)
            return {
                "engine": "source",
                "version": "",
                "confidence": "high" if is_source_process else "medium",
                "method": "source_module_detect",
                "details": {
                    "hint": f"{game.name} — Source 1 engine detected",
                    "game_name": game.name,
                    "is_64bit": game.is_64bit,
                    "client_module": game.client_module,
                },
            }

    result = detect_engine(process_name, exe_path)

    if result["engine"] in ("ue4", "ue5", "ue_unknown") and pid and probe_layout:
        base, size = _resolve_main_module_range(pid, process_name)
        handle = attach(pid)

        if handle and base:
            try:
                from src.engines.ue.gnames import (
                    find_gnames,
                    get_last_gnames_resolution_meta,
                    validate_gnames,
                )
                from src.engines.ue.gobjects import (
                    find_gobjects,
                    get_last_gobjects_resolution_meta,
                )

                scan_version = choose_ue_scan_version(result["engine"], result["version"])

                gnames, _ = find_gnames(
                    handle,
                    base,
                    size,
                    scan_version,
                    gobjects_hint=0,
                    process_name=process_name,
                )
                if gnames:
                    _is_valid, cp = validate_gnames(handle, gnames, scan_version)
                    result["case_preserving"] = cp
                    result["details"]["gnames_resolution"] = get_last_gnames_resolution_meta()

                gobjects, item_sz = find_gobjects(
                    handle,
                    base,
                    size,
                    scan_version,
                    process_name=process_name,
                    gnames_ptr=gnames,
                    case_preserving=result.get("case_preserving"),
                )
                if gobjects:
                    result["item_size"] = item_sz
                    result["details"]["gobjects_resolution"] = get_last_gobjects_resolution_meta()
                    if gnames:
                        try:
                            from src.engines.ue.sdk_walker import (
                                probe_ffield_layout,
                                ue_version_for_ffield_layout,
                            )

                            layout_probe = probe_ffield_layout(
                                handle,
                                gobjects,
                                gnames,
                                scan_version,
                                bool(result.get("case_preserving")),
                                item_size=item_sz,
                            )
                            result["details"]["ffield_layout_probe"] = layout_probe
                            if layout_probe.get("layout"):
                                result["version"] = ue_version_for_ffield_layout(
                                    str(layout_probe["layout"]),
                                    fallback=scan_version,
                                )
                        except Exception as exc:
                            result["details"]["ffield_layout_probe_error"] = str(exc)
            finally:
                detach(handle)

    return result
