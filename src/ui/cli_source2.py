import os
import sys
import time


def _module_inventory(pid: int) -> list:
    from src.core.memory import enumerate_modules

    modules = []
    for name, base, size, path in enumerate_modules(pid):
        modules.append(
            {
                "name": name,
                "base": f"0x{base:X}",
                "base_int": base,
                "size": size,
                "path": path,
            }
        )
    return modules


def _read_build_number(handle: int, pid: int, globals_results: list) -> int:
    from src.core.memory import get_module_info, read_uint32

    result = next(
        (item for item in globals_results if item.found and item.name == "dwBuildNumber"),
        None,
    )
    if result is None:
        return 0
    base, _ = get_module_info(pid, result.module)
    if not base:
        return 0
    return read_uint32(handle, base + result.rva)


def _run_source2(args):
    from src.core.memory import attach, detach, get_pid_by_name
    from src.engines.source2.buttons import find_cs2_buttons
    from src.engines.source2.dumper import dump_source2
    from src.engines.source2.globals import find_cs2_globals
    from src.engines.source2.interfaces import find_cs2_interfaces
    from src.engines.source2.hook_signature_dumper import dump_hook_signatures
    from src.engines.source2.prediction_dumper import dump_prediction
    from src.output.json_writer import write_all as source2_write_all
    from src.output.prediction_writer import write_prediction_header, write_prediction_json
    from src.output.signatures_writer import (
        write_signatures_header,
        write_signatures_json,
        write_signatures_loader_header,
        write_signatures_validation_json,
    )
    from src.output.source2_globals_writer import (
        write_cs2_globals_header,
        write_cs2_globals_json,
    )
    from src.output.source2_runtime_writer import (
        write_cs2_buttons_header,
        write_cs2_buttons_json,
        write_cs2_info_json,
        write_cs2_interfaces_header,
        write_cs2_interfaces_json,
    )
    from src.output.source2_writer import write_source2_header, write_source2_sdk

    print()
    print("=" * 60)
    print("  GameSDK-Kit - Source 2 SDK Analyzer")
    print("=" * 60)

    total_start = time.time()
    process_name = args.process

    print(f"\n[1/7] Finding {process_name}...")
    pid = get_pid_by_name(process_name)
    if not pid:
        print("  [!!] Process not found. Make sure the game is running.")
        return 1
    print(f"  [OK] PID: {pid}")

    game_dir = process_name.replace(".exe", "").replace(".dll", "")
    output_dir = os.path.join("games", game_dir, "Offsets")

    def progress(current_msg: str):
        if sys.stdout.isatty():
            print(f"\r  [>>] {current_msg}", end=" " * 20 + "\r", flush=True)
            print(f"  [>>] {current_msg}", flush=True)
        else:
            print(f"  [>>] {current_msg}", flush=True)

    print("\n[2/7] Running Source 2 schema/classes/enums dump...")
    handle = attach(pid)
    if not handle:
        print("  [!!] Could not attach. Try running as admin.")
        return 1

    try:
        dump = dump_source2(
            handle,
            process_name,
            progress_callback=progress,
        )
    except Exception as e:
        print(f"\n  [!!] Source 2 dump failed: {e}")
        detach(handle)
        return 1
    finally:
        if handle:
            detach(handle)

    if not dump.structs and not dump.enums:
        print("  [!!] No structs or enums found.")
        return 1

    print(f"  [OK] {len(dump.structs)} structs/classes, {len(dump.enums)} enums")

    print(f"\n[3/7] Scanning engine globals for {process_name}...")
    handle_globals = attach(pid)
    if not handle_globals:
        print("  [!!] Could not attach for global scanning.")
        return 1
    try:
        globals_results = find_cs2_globals(
            handle=handle_globals,
            pid=pid,
            progress_callback=progress,
            log_fn=lambda m: print(f"  {m}"),
        )
        build_number = _read_build_number(handle_globals, pid, globals_results)
    finally:
        if handle_globals:
            detach(handle_globals)
    globals_ok = sum(1 for r in globals_results if r.found)
    print(f"  [OK] Engine globals: {globals_ok}/{len(globals_results)} resolved")
    if build_number:
        print(f"  [OK] Build number: {build_number}")

    print("\n[4/7] Scanning key buttons and CreateInterface registries...")
    handle_runtime = attach(pid)
    if not handle_runtime:
        print("  [!!] Could not attach for runtime registry scanning.")
        return 1
    try:
        buttons_results = find_cs2_buttons(
            handle_runtime,
            process_name=process_name,
            progress_callback=progress,
            log_fn=lambda m: print(f"  {m}"),
        )
        interfaces_results = find_cs2_interfaces(
            handle_runtime,
            process_name=process_name,
            progress_callback=progress,
            log_fn=lambda m: print(f"  {m}"),
        )
    finally:
        if handle_runtime:
            detach(handle_runtime)
    buttons_ok = sum(1 for r in buttons_results if r.found and r.name)
    interfaces_ok = sum(len(r.interfaces) for r in interfaces_results)
    print(f"  [OK] Key buttons: {buttons_ok} resolved")
    print(f"  [OK] Interfaces: {interfaces_ok} resolved")

    print(f"\n[5/7] Scanning prediction offsets for {process_name}...")
    handle_prediction = attach(pid)
    if not handle_prediction:
        print("  [!!] Could not attach for prediction scanning.")
        return 1
    try:
        pred_dump = dump_prediction(
            handle=handle_prediction,
            pid=pid,
            progress_callback=progress,
            log_fn=lambda m: print(f"  {m}"),
        )
    finally:
        if handle_prediction:
            detach(handle_prediction)
    pred_ok = sum(1 for r in pred_dump.all_results if r.found)
    print(f"  [OK] Prediction offsets: {pred_ok}/{len(pred_dump.all_results)} resolved")

    print(f"\n[6/7] Scanning hook signatures for {process_name}...")
    handle_hooks = attach(pid)
    if not handle_hooks:
        print("  [!!] Could not attach for hook signature scanning.")
        return 1
    try:
        hook_dump = dump_hook_signatures(
            handle=handle_hooks,
            pid=pid,
            progress_callback=progress,
            log_fn=lambda m: print(f"  {m}"),
        )
    finally:
        if handle_hooks:
            detach(handle_hooks)
    hook_ok = hook_dump.found_count
    hook_total = len(hook_dump.entries)
    print(f"  [OK] Hook signatures: {hook_ok}/{hook_total} matched")
    if hook_dump.required_failed:
        print(f"  [!!] REQUIRED signatures failed: {len(hook_dump.required_failed)}")
        for r in hook_dump.required_failed:
            print(f"      - {r.name}: {r.error}")

    print(f"\n[7/7] Writing output to {output_dir}/...")
    source2_write_all(
        output_dir,
        dump,
        0,
        0,
        0,
        process_name=process_name,
        engine="source2",
        pe_timestamp=0,
    )

    header_path = os.path.join(output_dir, "source2_schemas.hpp")
    write_source2_header(header_path, dump, process_name=process_name)

    sdk_output_dir = (
        os.path.join(os.path.dirname(output_dir), "SDK")
        if os.path.basename(output_dir).lower() == "offsets"
        else os.path.join(output_dir, "SDK")
    )
    write_source2_sdk(sdk_output_dir, dump, process_name=process_name)

    write_cs2_globals_header(
        os.path.join(output_dir, "source2_offsets.hpp"),
        globals_results,
        process_name=process_name,
    )
    write_cs2_globals_json(
        os.path.join(output_dir, "source2_offsets.json"),
        globals_results,
        process_name=process_name,
    )

    write_cs2_buttons_header(
        os.path.join(output_dir, "source2_buttons.hpp"),
        buttons_results,
        process_name=process_name,
    )
    write_cs2_buttons_json(
        os.path.join(output_dir, "source2_buttons.json"),
        buttons_results,
        process_name=process_name,
    )

    write_cs2_interfaces_header(
        os.path.join(output_dir, "source2_interfaces.hpp"),
        interfaces_results,
        process_name=process_name,
    )
    write_cs2_interfaces_json(
        os.path.join(output_dir, "source2_interfaces.json"),
        interfaces_results,
        process_name=process_name,
    )

    write_prediction_header(
        os.path.join(output_dir, "source2_prediction.hpp"),
        pred_dump.functions,
        pred_dump.struct_offsets,
        process_name=process_name,
    )
    write_prediction_json(
        os.path.join(output_dir, "source2_prediction.json"),
        pred_dump.functions,
        pred_dump.struct_offsets,
        process_name=process_name,
    )

    write_signatures_header(
        os.path.join(output_dir, "source2_signatures.hpp"),
        process_name=process_name,
    )
    write_signatures_json(
        os.path.join(output_dir, "source2_signatures.json"),
        process_name=process_name,
    )
    write_signatures_validation_json(
        os.path.join(output_dir, "source2_signatures_validation.json"),
        hook_dump.entries,
        process_name=process_name,
    )
    write_signatures_loader_header(
        os.path.join(output_dir, "source2_signatures_loader.hpp"),
        process_name=process_name,
    )

    total_elapsed = time.time() - total_start
    write_cs2_info_json(
        os.path.join(output_dir, "source2_info.json"),
        process_name=process_name,
        sdk_dump=dump,
        globals_results=globals_results,
        buttons_results=buttons_results,
        interfaces_results=interfaces_results,
        prediction_dump=pred_dump,
        build_number=build_number,
        modules=_module_inventory(pid),
        elapsed_seconds=total_elapsed,
    )

    total_size = 0
    for file_name in os.listdir(output_dir):
        file_path = os.path.join(output_dir, file_name)
        if os.path.isfile(file_path):
            file_size = os.path.getsize(file_path)
            total_size += file_size
            print(f"    {file_name:30s} {file_size // 1024:>6d} KB")

    hard_failures = []
    if not dump.enums:
        hard_failures.append("schema enums")
    if buttons_ok == 0:
        hard_failures.append("key buttons")
    if interfaces_ok == 0:
        hard_failures.append("CreateInterface registry")
    if hard_failures:
        print(f"  [!!] Missing first-class outputs for {process_name}: {', '.join(hard_failures)}")

    print(f"\n{'=' * 60}")
    print("  Source 2 dump complete!")
    print(f"  Output: {os.path.abspath(output_dir)}/")
    print(f"  Total:  {total_size // 1024} KB in {total_elapsed:.1f}s")
    print(f"  Structs/Classes: {len(dump.structs)}")
    print(f"  Enums: {len(dump.enums)}")
    print(f"  Buttons: {buttons_ok}")
    print(f"  Interfaces: {interfaces_ok}")
    print(f"  Hook Sigs: {hook_ok}/{hook_total}")
    print(f"{'=' * 60}")

    return 0
