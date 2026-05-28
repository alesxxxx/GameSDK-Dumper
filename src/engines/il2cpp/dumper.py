
import glob
import os
from typing import Optional

from src.core.memory import read_uint64
from src.core.pe_parser import get_unity_version_from_pe
from src.engines.il2cpp.metadata import Metadata, load_metadata
from src.engines.il2cpp.pe_scanner import find_registrations
from src.engines.il2cpp.executor import Il2CppExecutor
from src.core.models import SDKDump
from src.core.debug import dbg

def find_metadata_file(
    process_name: str,
    metadata_path: Optional[str] = None,
    exe_path: Optional[str] = None,
) -> Optional[str]:
    if metadata_path and os.path.isfile(metadata_path):
        return os.path.abspath(metadata_path)

    if exe_path:
        game_install_dir = os.path.dirname(exe_path)
        if os.path.isdir(game_install_dir):
            try:
                for entry in os.listdir(game_install_dir):
                    entry_path = os.path.join(game_install_dir, entry)
                    if not os.path.isdir(entry_path):
                        continue
                    if entry.endswith("_Data") or entry == "Data":
                        candidate = os.path.join(
                            entry_path,
                            "il2cpp_data", "Metadata", "global-metadata.dat",
                        )
                        if os.path.isfile(candidate):
                            print(f"  [OK] Found metadata via exe path: {candidate}")
                            return os.path.abspath(candidate)
            except OSError:
                pass

    game_dir = process_name.replace(".exe", "").replace(".dll", "")

    candidate = os.path.join(
        "games", game_dir, "il2cpp_data", "Metadata", "global-metadata.dat"
    )
    if os.path.isfile(candidate):
        return os.path.abspath(candidate)

    pattern = os.path.join("**", "*_Data", "il2cpp_data", "Metadata", "global-metadata.dat")
    matches = glob.glob(pattern, recursive=True)
    if matches:
        return os.path.abspath(matches[0])

    pattern2 = os.path.join("**", "il2cpp_data", "Metadata", "global-metadata.dat")
    matches2 = glob.glob(pattern2, recursive=True)
    if matches2:
        return os.path.abspath(matches2[0])

    print(
        f"[!!] Could not find global-metadata.dat.\n"
        f"     Expected locations:\n"
        f"       - games/{game_dir}/il2cpp_data/Metadata/global-metadata.dat\n"
        f"       - <game>_Data/il2cpp_data/Metadata/global-metadata.dat\n"
        f"     Use --metadata <path> to specify the file explicitly."
    )
    return None

def dump_il2cpp(
    handle: int,
    base: int,
    size: int,
    process_name: str,
    metadata_path: Optional[str] = None,
    exe_path: Optional[str] = None,
    progress_callback=None,
    log_fn=None,
) -> SDKDump:
    import time as _time

    def _log(msg: str):
        if log_fn:
            log_fn(msg)
        else:
            print(msg)

    if not size and base:
        try:
            from src.core.memory import read_bytes as _rb
            import struct as _struct
            _hdr = _rb(handle, base, 0x400) or b""
            _lfanew = _struct.unpack_from("<I", _hdr, 0x3C)[0] if len(_hdr) >= 0x40 else 0
            if _lfanew and _lfanew + 0x58 < len(_hdr) and _hdr[_lfanew:_lfanew+4] == b"PE\x00\x00":
                _soi = _struct.unpack_from("<I", _hdr, _lfanew + 0x50)[0]
                if 0x100000 < _soi < 0x20000000:
                    size = _soi
                    _log(f"[WARN] modBaseSize=0, using SizeOfImage = {size//(1024*1024)} MB")
        except Exception:
            pass
        if not size:
            size = 200 * 1024 * 1024
            _log("[WARN] Module size unknown — defaulting to 200 MB scan window")

    meta_file = find_metadata_file(process_name, metadata_path, exe_path=exe_path)
    if not meta_file:
        _log("[!!] Cannot find global-metadata.dat")
        return SDKDump()

    _log(f"[OK] Metadata: {os.path.basename(meta_file)}")

    unity_version = ""
    if exe_path:
        try:
            unity_version = get_unity_version_from_pe(exe_path) or ""
        except Exception:
            unity_version = ""

    try:
        metadata = load_metadata(meta_file)
    except (FileNotFoundError, ValueError) as e:
        _log(f"[!!] Metadata parse error: {e}")
        return SDKDump()

    type_count = len(metadata.type_definitions)
    _log(
        f"[OK] Metadata v{metadata.version}: {type_count} types, "
        f"{len(metadata.field_definitions)} fields, {len(metadata.images)} images"
    )
    if unity_version:
        _log(f"[OK] Unity: {unity_version}")

    _t0 = _time.time()
    dbg("dump_il2cpp: Step 2 — Scanning for registrations (base=0x%X, size=%d MB)",
        base, size // (1024*1024))
    _log(f"Scanning for registrations ({size // (1024*1024)} MB)...")
    from src.engines.il2cpp.pe_scanner import find_registrations
    reg_data = find_registrations(
        handle, base, size,
        expected_type_count=type_count,
        image_count=len(metadata.images),
    )
    _log(f"[OK] Scan done in {_time.time() - _t0:.1f}s")
    dbg("dump_il2cpp: Scan complete in %.1fs", _time.time() - _t0)

    meta_reg = reg_data.get("metadata_registration", 0)
    code_reg = reg_data.get("code_registration", 0)

    if meta_reg:
        _log(f"[OK] MetadataRegistration: 0x{meta_reg:X}")
    if code_reg:
        _log(f"[OK] CodeRegistration: 0x{code_reg:X}")
    if not meta_reg and not reg_data.get("field_offsets"):
        _log("[WARN] MetadataRegistration not found — field offsets unavailable")

    _t1 = _time.time()
    _log(f"Walking {type_count} types...")
    dbg("dump_il2cpp: Step 3 — Walking %d types (meta_reg=0x%X, code_reg=0x%X)",
        type_count, meta_reg, code_reg)

    from src.core.memory import (
        USE_DRIVER as _USE_DRIVER,
        read_bytes as _read_bytes,
        add_memory_snapshot,
        clear_memory_snapshots,
    )
    
    def _do_walk():
        executor = Il2CppExecutor(
            metadata, handle, base,
            meta_reg_addr=meta_reg,
            code_reg_addr=code_reg,
            module_size=size,
            reg_data=reg_data
        )
        return executor, executor.walk_types(progress_callback=progress_callback, log_fn=_log)
    
    if _USE_DRIVER:
        from src.core import driver as _drv
        import ctypes as _ctypes
        PAGE_SZ = _drv.COMM_DATA_MAXSIZE
        _log(f"  [Kernel] Snapshotting module ({size // (1024*1024)} MB) into local memory...")
        _t_snap = _time.time()
        total_cached = 0
        pages_ok = 0
        pages_total = 0
        from src.core.memory import TARGET_PID as _snap_pid
        with _drv.bulk_read_mode():
            for off in range(0, size, PAGE_SZ):
                page_addr = base + off
                page_sz = min(PAGE_SZ, size - off)
                pages_total += 1
                if _drv._g_view and _drv._send_command(_snap_pid, page_addr, page_sz, _drv.COMMAND_READ):
                    page_data = _ctypes.string_at(_drv._g_view + _drv.COMM_HEADER_SIZE, page_sz)
                    add_memory_snapshot(page_addr, page_data)
                    total_cached += page_sz
                    pages_ok += 1
        snap_time = _time.time() - _t_snap
        if total_cached > 0:
            _log(f"  [OK] Cached {total_cached / (1024*1024):.1f} MB ({pages_ok}/{pages_total} pages) in {snap_time:.1f}s")
        else:
            _log("  [WARN] Module snapshot failed — walk will use individual kernel reads (slow)")
        try:
            with _drv.bulk_read_mode():
                executor, dump = _do_walk()
        finally:
            clear_memory_snapshots()
    else:
        executor, dump = _do_walk()
    _log(f"[OK] Done in {_time.time() - _t1:.1f}s: {len(dump.structs)} classes, {len(dump.enums)} enums")

    setattr(dump, "code_reg", code_reg)
    setattr(dump, "meta_reg", meta_reg)
    setattr(dump, "s_global", reg_data.get("s_global_metadata", 0))
    setattr(dump, "ga_base", base)
    setattr(dump, "unity_version", unity_version)
    setattr(dump, "metadata_version", str(metadata.version))
    setattr(dump, "static_fields_class_offset", getattr(executor, "_static_fields_off", 0))

    return dump
