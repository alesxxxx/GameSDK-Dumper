
import argparse
import os
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.core.memory import get_pid_by_name, attach, detach, get_module_info
from src.engines.ue.detector import detect_engine_full
from src.engines.ue.gnames import find_gnames, validate_gnames, clear_fname_cache, cache_all_fnames
from src.engines.ue.gobjects import (
    clear_gobjects_scan_state,
    find_gobjects,
    get_object_count,
)
from src.engines.ue.gworld import find_gworld, validate_gworld, get_world_info, find_gengine
from src.engines.ue.sdk_walker import walk_sdk
from src.output.json_writer import write_all

def _maybe_send_webhook(
    args,
    *,
    process_name: str,
    engine: str,
    output_dir: str,
    structs_count: int = 0,
    enums_count: int = 0,
    pe_timestamp: int = 0,
) -> None:
    webhook_url = getattr(args, "webhook_url", None)
    if not webhook_url:
        return

    try:
        from src.output.webhook import (
            collect_offset_statuses,
            format_offset_status_board,
            parse_update_date,
            send_webhook_json,
        )

        overrides = {}
        latest_update_raw = getattr(args, "webhook_latest_update", None)
        if latest_update_raw:
            latest_update = parse_update_date(latest_update_raw)
            if latest_update is None:
                print(
                    f"  [--] Webhook latest update '{latest_update_raw}' is invalid. "
                    "Use YYYY-MM-DD or M/D/YY."
                )
            else:
                key = process_name.lower().replace(".exe", "").replace(".dll", "")
                key = "".join(ch for ch in key if ch.isalnum())
                overrides[key] = latest_update

        inferred_games_root = ""
        try:
            output_abs = os.path.abspath(output_dir or "")
            if output_abs:
                maybe_games_root = os.path.dirname(os.path.dirname(output_abs))
                if maybe_games_root:
                    inferred_games_root = maybe_games_root
        except Exception:
            inferred_games_root = "games"
        statuses = collect_offset_statuses(inferred_games_root or "games", latest_update_overrides=overrides)
        status_board = format_offset_status_board(statuses)

        payload = {
            "event": "dump_complete",
            "tool": "GameSDK-Kit",
            "engine": engine,
            "process": process_name,
            "output_dir": os.path.abspath(output_dir) if output_dir else "",
            "structs_count": int(structs_count),
            "enums_count": int(enums_count),
            "pe_timestamp": int(pe_timestamp or 0),
            "sent_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status_board": status_board,
            "statuses": statuses,
        }

        ok, detail = send_webhook_json(
            webhook_url,
            payload,
            timeout=float(getattr(args, "webhook_timeout", 6.0)),
            secret=(getattr(args, "webhook_secret", None) or "").strip() or None,
        )
        if ok:
            print(f"  [OK] Webhook delivered ({detail})")
        else:
            print(f"  [--] Webhook failed: {detail}")
    except Exception as e:
        print(f"  [--] Webhook error: {e}")

def _run_steam_audit(args):
    from src.core.steam_audit import (
        format_steam_audit_report,
        scan_steam_library,
        write_steam_audit_report,
    )
    from src.core.steam_secrets import load_steam_audit_settings

    print()
    print("=" * 60)
    print("  GameSDK-Kit - Steam Library Audit")
    print("=" * 60)

    total_start = time.time()
    saved = load_steam_audit_settings() if args.steam_owned else {"steam_account": ""}
    report = scan_steam_library(
        args.steam_path,
        limit=args.steam_limit,
        include_owned_games=args.steam_owned,
        steam_account=args.steam_account or saved.get("steam_account"),
    )
    print(format_steam_audit_report(report))

    output_path = args.output or os.path.join("games", "_steam_audit", "steam_library_scan.json")
    written = write_steam_audit_report(report, output_path)
    elapsed = time.time() - total_start

    print("")
    print(f"  JSON report: {os.path.abspath(written)}")
    print(f"  Done in {elapsed:.1f}s")
    return 0

def _run_il2cpp(args):
    from src.engines.il2cpp.dumper import dump_il2cpp
    from src.output.json_writer import write_all as il2cpp_write_all

    print()
    print("=" * 60)
    print("  GameSDK-Kit — Unity IL2CPP SDK Analyzer")
    print("=" * 60)

    total_start = time.time()

    process_name = args.process
    print(f"\n[1/4] Finding {process_name}...")
    pid = get_pid_by_name(process_name)
    if not pid:
        pid = get_pid_by_name("GameAssembly.dll")
        if not pid:
            print(f"  [!!] Process not found. Make sure the game is running.")
            return 1
        if has_fail and args.force_kernel:
            print("  [!!] Forcing kernel attach despite prerequisite failures (--force-kernel)")
    print(f"  [OK] PID: {pid}")

    from src.engines.ue.detector import find_il2cpp_module
    il2cpp_mod = getattr(args, "_il2cpp_module", None) or find_il2cpp_module(pid)
    if not il2cpp_mod:
        il2cpp_mod = "GameAssembly.dll"

    ga_base, ga_size = get_module_info(pid, il2cpp_mod)
    if not ga_base:
        ga_base, ga_size = get_module_info(pid, process_name)
    if not ga_base:
        print(f"  [!!] Could not find IL2CPP module ({il2cpp_mod}). Try running as admin.")
        return 1
    print(f"  [OK] {il2cpp_mod}: 0x{ga_base:X}  Size: {ga_size // (1024*1024)} MB")

    handle = attach(pid)
    if not handle:
        print(f"  [!!] Could not attach. Try running as admin.")
        return 1

    exe_path = None
    try:
        import ctypes as _ct
        import ctypes.wintypes as _wt
        _k = _ct.WinDLL("kernel32", use_last_error=True)
        _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        _ph = _k.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if _ph:
            _buf = _ct.create_unicode_buffer(1024)
            _sz = _wt.DWORD(1024)
            if _k.QueryFullProcessImageNameW(_ph, 0, _buf, _ct.byref(_sz)):
                exe_path = _buf.value
                print(f"  [OK] Exe path: {exe_path}")
            _k.CloseHandle(_ph)
    except Exception:
        pass

    pe_timestamp = 0
    if exe_path:
        try:
            from src.core.pe_parser import get_pe_timestamp
            pe_timestamp = get_pe_timestamp(exe_path)
            if pe_timestamp:
                from datetime import datetime, timezone
                pe_human = datetime.fromtimestamp(pe_timestamp, tz=timezone.utc).strftime("%Y-%m-%d")
                print(f"  [OK] PE timestamp: {pe_timestamp} ({pe_human})")
        except Exception:
            pass

    game_dir = process_name.replace(".exe", "").replace(".dll", "")
    output_dir = os.path.join("games", game_dir, "Offsets")

    print(f"\n[2/4] Loading metadata...")
    metadata_path = getattr(args, "metadata", None)

    print(f"\n[3/4] Running IL2CPP dump...")

    def progress(current, total):
        pct = current * 100 // total if total else 0
        bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
        if sys.stdout.isatty():
            print(f"\r  [{bar}] {pct:3d}% ({current:,}/{total:,})", end="", flush=True)
        elif pct % 25 == 0 and (current == 0 or pct != (current - 1) * 100 // total):
            print(f"  Progress: {pct}% ({current:,}/{total:,})", flush=True)

    dump = dump_il2cpp(
        handle, ga_base, ga_size, process_name,
        metadata_path=metadata_path,
        exe_path=exe_path,
        progress_callback=progress,
    )
    print()

    detach(handle)

    if not dump.structs and not dump.enums:
        print(f"  [!!] No structs or enums found.")
        return 1

    print(f"  [OK] {len(dump.structs)} structs/classes, {len(dump.enums)} enums")

    print(f"\n[4/4] Writing output to {output_dir}/...")
    il2cpp_write_all(
        output_dir,
        dump,
        0,
        0,
        0,
        process_name=process_name,
        engine="il2cpp",
        unity_version=getattr(dump, "unity_version", ""),
        metadata_version=getattr(dump, "metadata_version", ""),
        pe_timestamp=pe_timestamp,
    )

    total_size = 0
    for f in os.listdir(output_dir):
        fp = os.path.join(output_dir, f)
        if os.path.isfile(fp):
            fsize = os.path.getsize(fp)
            total_size += fsize
            print(f"    {f:30s} {fsize // 1024:>6d} KB")

    from src.output.sdk_gen import generate_sdk
    base_game_dir = os.path.dirname(os.path.normpath(output_dir))
    sdk_dir = os.path.join(base_game_dir, "SDK")
    print(f"\n  Generating C++ SDK to {sdk_dir}/...")
    generate_sdk(output_dir, sdk_dir, engine="il2cpp")

    total_elapsed = time.time() - total_start
    print(f"\n{'='*60}")
    print(f"  IL2CPP dump complete!")
    print(f"  Output: {os.path.abspath(output_dir)}/")
    print(f"  SDK:    {os.path.abspath(sdk_dir)}/")
    print(f"  Total:  {total_size // 1024} KB in {total_elapsed:.1f}s")
    print(f"  Structs/Classes: {len(dump.structs)}")
    print(f"  Enums: {len(dump.enums)}")
    print(f"{'='*60}")

    _maybe_send_webhook(
        args,
        process_name=process_name,
        engine="il2cpp",
        output_dir=output_dir,
        structs_count=len(dump.structs),
        enums_count=len(dump.enums),
        pe_timestamp=pe_timestamp,
    )

    return 0

def _run_mono(args):
    from src.engines.mono.dumper import dump_mono, find_managed_dir
    from src.output.json_writer import write_all as mono_write_all

    print()
    print("=" * 60)
    print("  GameSDK-Kit — Unity Mono SDK Analyzer")
    print("=" * 60)

    total_start = time.time()

    process_name = args.process
    print(f"\n[1/3] Finding {process_name}...")
    pid = get_pid_by_name(process_name)
    if not pid:
        print(f"  [!!] Process not found. Make sure the game is running.")
        return 1
    print(f"  [OK] PID: {pid}")

    handle = attach(pid)
    if not handle:
        print(f"  [!!] Could not attach. Try running as admin.")
        return 1

    game_dir = process_name.replace(".exe", "")
    output_dir = os.path.join("games", game_dir, "Offsets")

    pe_timestamp = 0
    try:
        from src.engines.ue.detector import _find_exe_from_process
        from src.core.pe_parser import get_pe_timestamp
        exe_path = _find_exe_from_process(process_name)
        if exe_path:
            pe_timestamp = get_pe_timestamp(exe_path)
            if pe_timestamp:
                from datetime import datetime, timezone
                pe_human = datetime.fromtimestamp(pe_timestamp, tz=timezone.utc).strftime("%Y-%m-%d")
                print(f"  [OK] PE timestamp: {pe_timestamp} ({pe_human})")
    except Exception:
        pass

    print(f"\n[2/3] Running Mono dump...")
    managed_path = getattr(args, "managed", None)

    def progress(current, total):
        pct = current * 100 // total if total else 0
        bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
        if sys.stdout.isatty():
            print(f"\r  [{bar}] {pct:3d}% ({current:,}/{total:,})", end="", flush=True)
        elif pct % 25 == 0 and (current == 0 or pct != (current - 1) * 100 // total):
            print(f"  Progress: {pct}% ({current:,}/{total:,})", flush=True)

    dump = dump_mono(
        handle, pid, process_name,
        managed_path=managed_path,
        progress_callback=progress,
    )
    print()

    detach(handle)

    if not dump.structs and not dump.enums:
        print(f"  [!!] No structs or enums found.")
        return 1

    print(f"  [OK] {len(dump.structs)} structs/classes, {len(dump.enums)} enums")

    print(f"\n[3/3] Writing output to {output_dir}/...")
    mono_write_all(output_dir, dump, 0, 0, 0, process_name=process_name, engine="mono", pe_timestamp=pe_timestamp)

    total_size = 0
    for f in os.listdir(output_dir):
        fp = os.path.join(output_dir, f)
        if os.path.isfile(fp):
            fsize = os.path.getsize(fp)
            total_size += fsize
            print(f"    {f:30s} {fsize // 1024:>6d} KB")

    total_elapsed = time.time() - total_start
    print(f"\n{'='*60}")
    print(f"  Mono dump complete!")
    print(f"  Output: {os.path.abspath(output_dir)}/")
    print(f"  Total:  {total_size // 1024} KB in {total_elapsed:.1f}s")
    print(f"  Structs/Classes: {len(dump.structs)}")
    print(f"  Enums: {len(dump.enums)}")
    print(f"{'='*60}")

    _maybe_send_webhook(
        args,
        process_name=process_name,
        engine="mono",
        output_dir=output_dir,
        structs_count=len(dump.structs),
        enums_count=len(dump.enums),
        pe_timestamp=pe_timestamp,
    )

    return 0

def main():
    from src.core.debug import enable_stdout_tee
    enable_stdout_tee()
    
    parser = argparse.ArgumentParser(
        description="GameSDK-Kit — Unreal Engine / Unity / Source SDK analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m src.ui.cli --process Palworld-Win64-Shipping.exe
  python -m src.ui.cli --process Palworld-Win64-Shipping.exe --output my_dump/
  python -m src.ui.cli --process ShooterGame.exe --offsets-only
  python -m src.ui.cli --engine il2cpp --process MyGame.exe
  python -m src.ui.cli --engine il2cpp --process MyGame.exe --metadata path/to/global-metadata.dat
  python -m src.ui.cli --engine mono --process MyUnityGame.exe
  python -m src.ui.cli --engine mono --process MyUnityGame.exe --managed path/to/Managed
  python -m src.ui.cli --process MyGame.exe --kernel
        """,
    )
    parser.add_argument("--process", "-p", required=False, help="Game process name")
    parser.add_argument("--engine", "-e", choices=["ue", "il2cpp", "mono", "source", "source2"], default="ue",
                        help="Engine type (default: ue)")
    parser.add_argument("--steam-audit", action="store_true",
                        help="Scan Steam libraries and classify likely dump targets")
    parser.add_argument("--steam-path", default=None,
                        help="Explicit Steam install path for --steam-audit")
    parser.add_argument("--steam-limit", type=int, default=None,
                        help="Only scan the first N Steam games encountered")
    parser.add_argument("--steam-owned", action="store_true",
                        help="Append owned-account games from the running Steam desktop client")
    parser.add_argument("--steam-account", default=None,
                        help="Preferred local SteamID64 label for --steam-owned output")
    parser.add_argument("--metadata", default=None,
                        help="Explicit path to global-metadata.dat (IL2CPP mode)")
    parser.add_argument("--managed", default=None,
                        help="Explicit path to Managed/ directory (Mono mode)")
    parser.add_argument("--offsets-only", action="store_true", help="Only find GNames/GObjects/GWorld, skip full SDK walk")
    parser.add_argument("--generate-sdk", action="store_true", help="Generate C++ SDK headers after dumping")
    parser.add_argument("--output", "-o", default=None,
                        help="Output directory (default: games/<ProcessName>/Offsets)")
    parser.add_argument("--kernel", action="store_true",
                        help="Route all memory reads through the kernel driver (wdfsvc64.sys must be loaded)")
    parser.add_argument("--memory-backend", choices=["win32", "native", "auto"],
                        default=os.environ.get("GSDK_MEMORY_BACKEND", "win32"),
                        help="User-mode memory backend when --kernel is not used (default: win32)")
    parser.add_argument("--force-kernel", action="store_true",
                        help="Skip kernel prerequisite failures and attempt driver attach anyway")
    parser.add_argument("--webhook-url", default="",
                        help="Optional webhook URL to receive dump completion payloads")
    parser.add_argument("--webhook-secret", default="",
                        help="Optional HMAC secret for webhook authentication")
    parser.add_argument("--webhook-timeout", type=float, default=6.0,
                        help="Webhook HTTP timeout in seconds (default: 6)")
    parser.add_argument("--gworld-timeout", type=float, default=180.0,
                        help="GWorld scan timeout in seconds (default: 180; set 0 to disable)")
    parser.add_argument("--webhook-latest-update", default="",
                        help="Optional latest game update date (YYYY-MM-DD or M/D/YY) for DATED status checks")
    args = parser.parse_args()

    if args.steam_audit:
        return _run_steam_audit(args)

    if not args.process:
        parser.error("--process is required unless --steam-audit is used")

    if args.kernel:
        from src.core.driver import (
            init_driver, check_system_prerequisites, check_driver_health,
        )
        from src.core.memory import set_driver_mode
        from src.core.debug import dbg

        print("[Kernel] Checking system prerequisites...")
        prereqs = check_system_prerequisites()
        has_fail = False
        for status, msg in prereqs:
            icon = {"ok": "[OK]", "warn": "[!!]", "fail": "[XX]"}[status]
            print(f"  {icon} {msg}")
            if status == "fail":
                has_fail = True

        if has_fail and not args.force_kernel:
            print()
            print("[!!] System prerequisites not met. Fix the issues above before loading the driver.")
            print("     If the driver is already loaded, prerequisites don't apply — use --force-kernel to skip checks.")
            return 1

        print("[Kernel] Connecting to kernel driver...")
        if init_driver():
            health = check_driver_health()
            if health["alive"]:
                set_driver_mode(True)
                caps = health["capabilities"]
                print(f"[Kernel] Driver v{health['version']} connected!")
                if caps.get("physical_read"):
                    print("  Physical read (MmCopyMemory): ENABLED")
                if caps.get("tolerant_bulk_read"):
                    print("  Tolerant bulk scan reads: ENABLED")
                else:
                    print("  Tolerant bulk scan reads: UNAVAILABLE (driver older than v2.2; brute scans fall back to strict reads)")
                if caps.get("dtb_validated"):
                    print(f"  DTB offset: 0x{health['dtb_offset']:X} (validated)")
                else:
                    print(f"  DTB offset: 0x{health['dtb_offset']:X} (validates on first attach)")
            else:
                set_driver_mode(True)
                dbg("CLI: Driver section found, health check not supported")
                print("[Kernel] Driver section found but health check failed. The driver may be an older version without health check support. Reads will still be attempted.")
        else:
            dbg("CLI: Kernel driver NOT FOUND")
            print("[!!] Kernel driver not found — shared memory section doesn't exist.")
            print("     Load the driver first (run as Admin):")
            print("       bin\\gsd_mapper.exe bin\\wdfsvc64.sys")
            print("     If iqvw64e.sys is blocklisted, disable the Vulnerable")
            print("     Driver Blocklist. See driver\\BUILD.md for details.")
            return 1
    else:
        from src.core.memory import get_memory_backend_status, set_memory_backend

        set_memory_backend(args.memory_backend)
        if args.memory_backend != "win32":
            backend_status = get_memory_backend_status()
            if backend_status.get("active"):
                print(f"[Memory] Native backend active: {backend_status.get('path', '')}")
            elif args.memory_backend == "native":
                print(
                    "[Memory] Native backend requested but unavailable; "
                    f"falling back to Win32 ({backend_status.get('error', 'unknown error')})"
                )

    if args.engine == "il2cpp":
        return _run_il2cpp(args)

    if args.engine == "mono":
        return _run_mono(args)

    if args.engine == "source2":
        from src.ui.cli_source2 import _run_source2
        return _run_source2(args)

    if args.engine == "ue":
        from src.engines.ue.detector import detect_engine_full as _det
        _pre = _det(args.process)
        if _pre.get("engine") == "il2cpp":
            _mod = _pre.get("il2cpp_module", "GameAssembly.dll")
            print(f"  [AUTO] Detected Unity IL2CPP ({_mod} found) — switching engine")
            args.engine = "il2cpp"
            args._il2cpp_module = _mod
            return _run_il2cpp(args)
        if _pre.get("engine") == "mono":
            print(f"  [AUTO] Detected Unity Mono ({_pre['method'].split('_')[-1]} found) — switching engine")
            args.engine = "mono"
            return _run_mono(args)

    print()
    print("=" * 60)
    print("  GameSDK-Kit — Unreal Engine SDK Analyzer")
    print("=" * 60)

    total_start = time.time()

    print(f"\n[1/6] Finding {args.process}...")
    pid = get_pid_by_name(args.process)
    if not pid:
        print(f"  [!!] Process not found. Make sure the game is running.")
        return 1
    print(f"  [OK] PID: {pid}")

    game_dir = args.process.replace(".exe", "")
    if not getattr(args, "output", None):
        args.output = os.path.join("games", game_dir, "Offsets")

    base, size = get_module_info(pid, args.process)
    if not base:
        print(f"  [!!] Could not get module base. Try running as admin.")
        return 1
    print(f"  [OK] Base: 0x{base:X}  Size: {size // (1024*1024)} MB")

    handle = attach(pid)
    if not handle:
        print(f"  [!!] Could not attach. Try running as admin.")
        return 1

    clear_fname_cache()
    clear_gobjects_scan_state()

    print(f"\n[2/6] Detecting engine...")
    detection = detect_engine_full(args.process)
    from src.engines.ue.detector import choose_ue_scan_version
    ue_version = choose_ue_scan_version(
        detection.get("engine", "unknown"),
        detection.get("version", ""),
    )
    cp = detection.get("case_preserving", False)
    item_size = detection.get("item_size", 24)
    print(f"  [OK] Engine: {detection['engine'].upper()} {ue_version}")
    print(f"  [OK] Confidence: {detection['confidence']}")
    print(f"  [OK] Case preserving: {cp}, Item size (detect): {item_size}")

    pe_timestamp = 0
    try:
        from src.engines.ue.detector import _find_exe_from_process
        from src.core.pe_parser import get_pe_timestamp
        exe_path = _find_exe_from_process(args.process)
        if exe_path:
            pe_timestamp = get_pe_timestamp(exe_path)
            if pe_timestamp:
                from datetime import datetime, timezone
                pe_human = datetime.fromtimestamp(pe_timestamp, tz=timezone.utc).strftime("%Y-%m-%d")
                print(f"  [OK] PE timestamp: {pe_timestamp} ({pe_human})")
    except Exception:
        pass

    from src.core.diagnostics import ScanDiagnostics
    diag = ScanDiagnostics()

    from src.engines.ue.offsets_override import load_game_offsets_override
    from src.engines.ue.gnames import get_last_gnames_resolution_meta
    from src.engines.ue.gobjects import get_last_gobjects_resolution_meta
    from src.core.memory import get_read_telemetry

    use_cached_offsets = not args.kernel
    scan_process_name = args.process if use_cached_offsets else None
    _override = load_game_offsets_override(args.process)
    _ogn_rva = _override[0] if (use_cached_offsets and _override is not None) else None
    _ogw_rva = _override[2] if _override is not None else None
    gworld_override_for_live = _ogw_rva if use_cached_offsets else None
    kernel_cached_gworld_slot = 0
    if not use_cached_offsets:
        print(
            "  [--] Kernel mode: resolving GObjects/GNames live; "
            "cached offsets only remain a validated GWorld fallback."
        )
        diag.info(
            "Kernel live scan skips cached GObjects/GNames OffsetsInfo overrides.",
            "GObjects",
        )
        if _ogw_rva is not None:
            print(
                "  [--] Cached GWorld RVA will be used only as a validated fallback "
                "if live kernel resolution fails."
            )

    print(f"\n[3/6] Finding GNames...")
    gnames, legacy_names = find_gnames(
        handle,
        base,
        size,
        ue_version,
        gobjects_hint=0,
        process_name=scan_process_name,
        override_rva=_ogn_rva,
        diag=diag,
    )
    if not gnames:
        print(f"  [!!] GNames not found")
        for line in diag.format_report():
            print(f"  {line}")
        detach(handle)
        return 1
    gnames_off = gnames - base
    is_valid, cp = validate_gnames(handle, gnames, ue_version)
    print(f"  [OK] GNames: base + 0x{gnames_off:X}  (validated: {is_valid})")
    gnames_meta = get_last_gnames_resolution_meta()
    if gnames_meta:
        print(f"  [--] GNames method: {gnames_meta.get('method', 'unknown')}")

    print(f"\n[4/6] Finding GObjects...")
    gobjects, item_size = find_gobjects(
        handle,
        base,
        size,
        ue_version,
        process_name=scan_process_name,
        diag=diag,
        gnames_ptr=gnames,
        case_preserving=cp,
        legacy_names=legacy_names,
    )
    if not gobjects:
        print(f"  [!!] GObjects not found")
        for line in diag.format_report():
            print(f"  {line}")
        detach(handle)
        return 1
    gobjects_off = gobjects - base
    num_objects = get_object_count(handle, gobjects)
    print(
        f"  [OK] GObjects: base + 0x{gobjects_off:X}  ({num_objects:,} objects, item stride {item_size})"
    )
    gobjects_meta = get_last_gobjects_resolution_meta()
    if gobjects_meta:
        print(
            f"  [--] GObjects method: {gobjects_meta.get('method', 'unknown')} "
            f"(objects +0x{gobjects_meta.get('objects_offset', 0):X})"
        )

    try:
        from src.engines.ue.sdk_walker import (
            probe_ffield_layout,
            ue_version_for_ffield_layout,
        )
        from src.engines.ue.version_matrix import get_ffield_layout

        layout_probe = probe_ffield_layout(
            handle,
            gobjects,
            gnames,
            ue_version,
            cp,
            item_size=item_size,
            legacy_names=legacy_names,
        )
        probed_layout = layout_probe.get("layout")
        if probed_layout in ("ue427", "ue52plus"):
            old_layout = get_ffield_layout(ue_version)
            if probed_layout != old_layout:
                old_version = ue_version
                ue_version = ue_version_for_ffield_layout(probed_layout, fallback=ue_version)
                diag.warn(
                    f"FField layout probe changed SDK walk layout from {old_layout} "
                    f"({old_version}) to {probed_layout} ({ue_version})",
                    "Version",
                )
                diag.set_confidence(
                    "Version",
                    max(0.8, float(layout_probe.get("confidence", 0.0))),
                    f"runtime FField probe selected {probed_layout}",
                )
                print(
                    f"  [!!] FField layout probe: {old_layout} -> {probed_layout}; "
                    f"using UE {ue_version} SDK layout"
                )
            else:
                diag.set_confidence(
                    "Version",
                    max(diag.get_confidence("Version"), 0.8),
                    f"runtime FField probe confirmed {probed_layout}",
                )
                print(
                    f"  [OK] FField layout probe: {probed_layout} confirmed "
                    f"({layout_probe.get('samples', 0)} samples)"
                )
    except Exception as exc:
        diag.warn(f"FField layout probe failed: {exc}", "Version")
        print(f"  [!!] FField layout probe failed: {exc}")

    if _ogw_rva is not None and gnames:
        from src.engines.ue.gworld import validate_gworld_rva
        if not validate_gworld_rva(
            handle,
            base,
            _ogw_rva,
            gnames,
            ue_version,
            cp,
            module_size=size,
        ):
            if args.kernel:
                print(
                    f"  [--] Cached GWorld RVA 0x{_ogw_rva:X} failed kernel validation; "
                    "continuing with live scan only"
                )
            else:
                print(f"  [!!] Cached GWorld RVA 0x{_ogw_rva:X} is stale — rescanning")
                from src.engines.ue.offsets_override import mark_offsets_stale
                mark_offsets_stale(args.process)
            _ogw_rva = None
            gworld_override_for_live = None
        else:
            print(f"  [OK] Cached GWorld RVA 0x{_ogw_rva:X} validated")
            if args.kernel:
                kernel_cached_gworld_slot = base + _ogw_rva
            else:
                gworld_override_for_live = _ogw_rva

    if gnames:
        try:
            cache_all_fnames(handle, gnames, ue_version, cp)
        except Exception as e:
            print(f"  [!!] FName pre-cache failed: {e} (GWorld search may be slow)")

    print(f"\n[5/6] Finding GWorld...")
    gworld_timeout = float(getattr(args, "gworld_timeout", 0.0) or 0.0)
    if gworld_timeout > 0:
        print(f"  [--] GWorld timeout guard: {int(gworld_timeout)}s")
    try:
        gworld = find_gworld(
            handle,
            base,
            size,
            ue_version,
            override_rva=gworld_override_for_live,
            diag=diag,
            gobjects_ptr=gobjects,
            gnames_ptr=gnames,
            case_preserving=cp,
            item_size=item_size,
            timeout_seconds=gworld_timeout,
        )
    except Exception as e:
        print(f"  [!!] GWorld search error: {e}")
        gworld = 0
    gworld_from_cached_fallback = False
    if not gworld and args.kernel and kernel_cached_gworld_slot:
        print("  [--] Live kernel GWorld resolution failed; trying cached fallback...")
        if validate_gworld(
            handle,
            kernel_cached_gworld_slot,
            module_base=base,
            module_size=size,
            gnames_ptr=gnames,
            ue_version=ue_version,
            case_preserving=cp,
        ):
            gworld = kernel_cached_gworld_slot
            gworld_from_cached_fallback = True
            print("  [OK] Cached fallback validated in kernel mode")
        else:
            print("  [--] Cached fallback failed validation in kernel mode")
    gworld_off = (gworld - base) if gworld else 0
    if gworld:
        info = get_world_info(handle, gworld, base, size, gnames, ue_version, cp)
        name = info['name'] if info else "?"
        suffix = " [cached fallback]" if gworld_from_cached_fallback else ""
        print(f"  [OK] GWorld: base + 0x{gworld_off:X}  (name: {name}){suffix}")
    else:
        print(f"  [--] GWorld not found (non-critical)")

    print(f"\n  {'='*50}")
    print(f"  GNames   = 0x{gnames_off:X}")
    print(f"  GObjects = 0x{gobjects_off:X}")
    print(f"  GWorld   = 0x{gworld_off:X}")
    for target in ("Version", "GObjects", "GNames", "GWorld"):
        conf = diag.get_confidence(target)
        reason = diag.get_confidence_reason(target)
        if conf <= 0:
            continue
        label = "HIGH" if conf >= 0.8 else "MEDIUM" if conf >= 0.5 else "LOW"
        icon = "[OK]" if conf >= 0.8 else "[??]" if conf >= 0.5 else "[!!]"
        print(f"  {icon} {target}: {label}" + (f" — {reason}" if reason else ""))
    if args.kernel:
        telemetry = get_read_telemetry()
        print(
            f"  [--] Kernel reads: {telemetry['kernel_command_count']} commands, "
            f"{telemetry['scatter_batches']} scatter batches, "
            f"{telemetry['collapse_rate_pct']:.1f}% request collapse"
        )
        if telemetry.get("translation_cache_lookups"):
            print(
                f"  [--] Translation cache: {telemetry['translation_cache_hit_pct']:.1f}% "
                f"({telemetry['translation_cache_hits']}/{telemetry['translation_cache_lookups']})"
            )
    print(f"  {'='*50}")

    if args.offsets_only:
        os.makedirs(args.output, exist_ok=True)
        from src.output.json_writer import write_offsets_json, write_readme
        from src.output.utils import resolve_standard_chain
        write_offsets_json(os.path.join(args.output, "OffsetsInfo.json"),
                           gnames_off, gobjects_off, gworld_off,
                           process_name=args.process,
                           ue_version=ue_version,
                           pe_timestamp=pe_timestamp)
        write_readme(os.path.join(args.output, "README.txt"),
                     gnames_off, gobjects_off, gworld_off,
                     process_name=args.process,
                     ue_version=ue_version,
                     pe_timestamp=pe_timestamp)
        print(f"\n  Offsets saved to {args.output}/OffsetsInfo.json")
        print(f"  README saved to {args.output}/README.txt")
        _maybe_send_webhook(
            args,
            process_name=args.process,
            engine="ue",
            output_dir=args.output,
            structs_count=0,
            enums_count=0,
            pe_timestamp=pe_timestamp,
        )
        detach(handle)
        elapsed = time.time() - total_start
        print(f"\n  Done in {elapsed:.1f}s")
        return 0

    print(f"\n[6/6] Walking SDK ({num_objects:,} objects)...")
    walk_start = time.time()

    def progress(current, total):
        pct = current * 100 // total if total else 0
        bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
        if sys.stdout.isatty():
            print(f"\r  [{bar}] {pct:3d}% ({current:,}/{total:,})", end="", flush=True)
        elif pct % 25 == 0 and (current == 0 or pct != (current - 1) * 100 // total):
            print(f"  Progress: {pct}% ({current:,}/{total:,})", flush=True)

    dump = walk_sdk(handle, gobjects, gnames, ue_version, cp, legacy_names, item_size,
                    base=base, size=size, progress_callback=progress)
    walk_elapsed = time.time() - walk_start
    print(f"\n  [OK] {len(dump.structs)} structs/classes, {len(dump.enums)} enums in {walk_elapsed:.1f}s")

    gengine_off = 0
    try:
        gengine_off = find_gengine(handle, base, size, gnames, ue_version, cp)
        if gengine_off:
            print(f"  [OK] GEngine: base + 0x{gengine_off:X}")
    except Exception:
        pass

    print(f"\n  Writing output to {args.output}/...")
    write_all(args.output, dump, gnames_off, gobjects_off, gworld_off,
              process_name=args.process, ue_version=ue_version, pe_timestamp=pe_timestamp,
              gengine_off=gengine_off)

    try:
        from src.output.health_check import run_health_check, print_health_report, write_health_sidecar
        health = run_health_check(
            dump, handle=handle,
            gobjects_ptr=gobjects, gnames_ptr=gnames,
            gworld_addr=gworld or 0,
            module_base=base, module_size=size,
            ue_version=ue_version, case_preserving=cp,
            item_size=item_size,
        )
        print_health_report(health, ue_version=ue_version, pe_timestamp=pe_timestamp)
        health_path = write_health_sidecar(args.output, health, ue_version=ue_version, pe_timestamp=pe_timestamp)
        print(f"  health.txt saved to {health_path}")
    except Exception as e:
        print(f"  [--] Health check failed: {e}")

    total_size = 0
    for f in os.listdir(args.output):
        fp = os.path.join(args.output, f)
        if os.path.isfile(fp):
            fsize = os.path.getsize(fp)
            total_size += fsize
            print(f"    {f:30s} {fsize // 1024:>6d} KB")

    detach(handle)

    if getattr(args, "generate_sdk", False):
        from src.output.sdk_gen import generate_sdk
        base_game_dir = os.path.dirname(os.path.normpath(args.output))
        sdk_dir = os.path.join(base_game_dir, "SDK")
        print(f"\n  Generating C++ SDK to {sdk_dir}/...")
        try:
            generate_sdk(args.output, sdk_dir, engine="ue")
        except Exception as exc:
            print(f"  [!!] SDK generation blocked: {exc}")

    total_elapsed = time.time() - total_start
    print(f"\n{'='*60}")
    print(f"  Dump complete!")
    print(f"  Output: {os.path.abspath(args.output)}/")
    print(f"  Total:  {total_size // 1024} KB in {total_elapsed:.1f}s")
    print(f"  Structs/Classes: {len(dump.structs)}")
    print(f"  Enums: {len(dump.enums)}")
    print(f"{'='*60}")

    _maybe_send_webhook(
        args,
        process_name=args.process,
        engine="ue",
        output_dir=args.output,
        structs_count=len(dump.structs),
        enums_count=len(dump.enums),
        pe_timestamp=pe_timestamp,
    )

    return 0

if __name__ == "__main__":
    sys.exit(main())
