import argparse
import json
import os
import sys
import time
from typing import Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.re.cli_utils import (
    anchor_rva_from_args,
    load_image_arg,
    make_module_resolver,
    parse_int,
    print_or_write,
    write_json_report,
)
from src.re.engine_profile import analyze_binary
from src.re.pe_image import PEImage
from src.re.signatures import (
    CandidateSignature,
    SignatureHit,
    dump_json,
    generate_masked_patterns,
    score_hit_count,
    to_jsonable,
)
from src.re.validator import ModuleResolver


def cmd_inspect(args) -> int:
    result = analyze_binary(args.binary)
    if not result.get("ok"):
        payload = {"ok": False, "error": result.get("error", "unknown"), "kind": "inspect"}
        print_or_write(args, payload, default_name="inspect.json")
        return 1

    payload = {"ok": True, "kind": "inspect", "result": result}
    print_or_write(args, payload, default_name="inspect.json")
    if not args.json and not args.output:
        r = result
        print(f"Module      : {r['module_name']}")
        print(f"Size        : {r['file_size']:,} bytes")
        print(f"Machine     : {r['machine']}")
        print(f"Entropy     : {r['entropy']}")
        print(f"Compiler    : {r['compiler_hint']}")
        print(f"Engine      : {r['engine']['engine']} (conf={r['engine']['confidence']}, method={r['engine']['method']})")
        if r['engine']['engine_version']:
            print(f"Engine Ver  : {r['engine']['engine_version']}")
        print(f"Sections    : {len(r['sections'])}")
        for sec in r['sections']:
            flags = ""
            if sec.get("executable"):
                flags += "X"
            if sec.get("writable"):
                flags += "W"
            if sec.get("readable"):
                flags += "R"
            print(f"  {sec['name']:12s} rva=0x{sec['virtual_address']:08X} size=0x{sec['virtual_size']:08X} [{flags}]")
        print(f"Imports     : {len(r['imports'])}")
        print(f"Exports     : {r['export_count']}")
    return 0


def cmd_search(args) -> int:
    image = load_image_arg(args)
    if image is None:
        return 1

    results: Dict[str, object] = {
        "ok": True,
        "kind": "search",
        "module": image.module_name,
        "path": image.path,
        "strings": [],
        "pattern_hits": [],
        "export_hits": [],
    }

    if args.query:
        strings = image.find_strings(
            queries=args.query,
            min_len=args.min_len,
            limit=args.limit,
            include_utf16=not args.no_utf16,
        )
        results["strings"] = strings

    if args.pattern:
        hits = image.scan_pattern(args.pattern, max_results=args.limit)
        results["pattern_hits"] = hits

    if args.export:
        hit = image.get_export(args.export)
        if hit:
            results["export_hits"] = [hit]

    print_or_write(args, results, default_name="search.json")
    if not args.json and not args.output:
        for item in results["strings"]:
            print(f"[STR] 0x{item.rva:X} {item.section:8s} {item.encoding:7s} {item.value}")
        for item in results["pattern_hits"]:
            resolved = ""
            if item.resolved_rva is not None:
                resolved = f" -> 0x{item.resolved_rva:X}"
            print(f"[PAT] 0x{item.rva:X} {item.section:8s}{resolved}")
        for item in results["export_hits"]:
            print(f"[EXP] 0x{item.rva:X} {item.name if hasattr(item, 'name') else args.export}")
    return 0


def cmd_analyze(args) -> int:
    image = load_image_arg(args)
    if image is None:
        return 1

    rva = anchor_rva_from_args(image, args)
    if rva is None:
        return 1

    rows = image.disassemble(rva, before=args.before, size=args.size)
    nearby_strings = image.find_strings(min_len=4, limit=50)
    # Filter to strings within a reasonable window
    window_start = rva - args.before
    window_end = rva + args.size
    nearby_strings = [s for s in nearby_strings if window_start <= s.rva <= window_end]

    # Generate candidate signatures at anchor
    offset = image.rva_to_offset(rva)
    candidates: List[CandidateSignature] = []
    if offset >= 0:
        lengths = [int(item) for item in args.lengths.split(",") if item.strip()]
        candidates = generate_masked_patterns(
            image.module_name,
            image.image_base,
            image.data,
            rva,
            offset,
            lengths=lengths,
        )

    # Xrefs to anchor
    xrefs = image.find_rip_xrefs([rva], tolerance=0, limit=50)

    payload = {
        "ok": True,
        "kind": "analyze",
        "module": image.module_name,
        "path": image.path,
        "anchor": {
            "rva": f"0x{rva:X}",
            "va": f"0x{image.rva_to_va(rva):X}",
        },
        "disassembly": rows,
        "nearby_strings": nearby_strings,
        "candidate_signatures": candidates,
        "xrefs_to_anchor": xrefs,
    }

    if args.ghidra:
        from src.re.ghidra_bridge import decompile_function_best_effort
        payload["ghidra"] = decompile_function_best_effort(
            image.path, rva, timeout_secs=args.ghidra_timeout
        )

    print_or_write(args, payload, default_name="analyze.json")
    if not args.json and not args.output:
        for row in rows:
            marker = " <==" if row["rva"] == rva else ""
            print(f"0x{row['rva']:08X}: {row['bytes']:<28s} {row['mnemonic']:<8s} {row['op_str']}{marker}")
        if nearby_strings:
            print("\n[Nearby strings]")
            for s in nearby_strings:
                print(f"  0x{s.rva:X} {s.value!r}")
        if xrefs:
            print("\n[Xrefs to anchor]")
            for xr in xrefs:
                print(f"  0x{xr.source_rva:X} -> 0x{xr.target_rva:X} {xr.instruction}")
        if candidates:
            print("\n[Candidate signatures]")
            for c in candidates:
                print(f"  [{c.score:6s}] len={c.length} hits={c.hit_count} {c.pattern}")
        ghidra = payload.get("ghidra")
        if ghidra:
            print("\n[Ghidra]")
            print(ghidra.get("decompiled") if ghidra.get("ok") else ghidra.get("error"))
    return 0


def cmd_live(args) -> int:
    from src.core.memory import (
        attach,
        detach,
        enumerate_modules,
        get_pid_by_name,
        iter_readable_regions,
        read_bytes,
    )
    from src.core.scanner import scan_pattern

    pid = get_pid_by_name(args.process)
    if not pid:
        payload = {"ok": False, "error": f"process {args.process!r} not found", "kind": "live"}
        print_or_write(args, payload, default_name="live.json")
        return 1

    handle = attach(pid)
    if not handle:
        payload = {"ok": False, "error": "could not attach to process (need admin?)", "kind": "live"}
        print_or_write(args, payload, default_name="live.json")
        return 1

    try:
        modules = []
        for name, base, size, path in enumerate_modules(pid):
            modules.append({"name": name, "base": f"0x{base:X}", "base_int": base, "size": size, "path": path})

        payload = {
            "ok": True,
            "kind": "live",
            "process": args.process,
            "pid": pid,
            "modules": modules,
            "scan_hits": [],
            "memory_reads": [],
        }

        if args.scan_pattern:
            # Scan module(s) for the pattern
            filter_name = (args.module_filter or "").lower()
            all_hits = []
            for mod in modules:
                base = mod["base_int"]
                size = mod["size"]
                if not base or not size:
                    continue
                if filter_name and mod["name"].lower() != filter_name:
                    continue
                try:
                    addrs = scan_pattern(handle, base, size, args.scan_pattern, max_results=args.max_hits + 1)
                    for addr in addrs[: args.max_hits]:
                        all_hits.append({
                            "module": mod["name"],
                            "va": f"0x{addr:X}",
                            "rva": f"0x{addr - base:X}",
                        })
                except Exception:
                    pass
            payload["scan_hits"] = all_hits

        if args.read_va:
            addr = parse_int(args.read_va)
            data = read_bytes(handle, addr, args.read_size)
            payload["memory_reads"].append({
                "va": f"0x{addr:X}",
                "size": len(data),
                "hex": data.hex(),
                "ascii": data.decode("latin-1", errors="replace"),
            })

        if args.read_rva and args.read_module:
            mod_info = next((m for m in modules if m["name"].lower() == args.read_module.lower()), None)
            if mod_info:
                addr = mod_info["base_int"] + parse_int(args.read_rva)
                data = read_bytes(handle, addr, args.read_size)
                payload["memory_reads"].append({
                    "module": args.read_module,
                    "rva": args.read_rva,
                    "va": f"0x{addr:X}",
                    "size": len(data),
                    "hex": data.hex(),
                    "ascii": data.decode("latin-1", errors="replace"),
                })

        if args.regions:
            regions = []
            for base, size in iter_readable_regions(handle):
                regions.append({"base": f"0x{base:X}", "size": size})
            payload["regions"] = regions

    finally:
        detach(handle)

    print_or_write(args, payload, default_name="live.json")
    if not args.json and not args.output:
        print(f"Process : {args.process} (PID {pid})")
        print(f"Modules : {len(modules)}")
        for mod in modules:
            print(f"  {mod['name']:30s} base={mod['base']} size={mod['size']:,}")
        if payload["scan_hits"]:
            print(f"\nPattern hits ({len(payload['scan_hits'])}):")
            for hit in payload["scan_hits"]:
                print(f"  {hit['module']}!{hit['rva']} ({hit['va']})")
        if payload.get("memory_reads"):
            for rd in payload["memory_reads"]:
                print(f"\nRead {rd['va']} ({rd['size']} bytes)")
                print(f"  hex: {rd['hex'][:64]}{'...' if len(rd['hex']) > 64 else ''}")
        if payload.get("regions"):
            print(f"\nReadable regions: {len(payload['regions'])}")
    return 0


def cmd_discover(args) -> int:
    image = load_image_arg(args)
    if image is None:
        return 1

    anchor_rvas = []
    if args.string:
        strings = image.find_strings(queries=[args.string], min_len=max(2, len(args.string)), limit=args.limit)
        xrefs = image.find_rip_xrefs([item.rva for item in strings], limit=args.limit)
        anchor_rvas.extend(item.source_rva for item in xrefs)
    else:
        rva = anchor_rva_from_args(image, args)
        if rva is not None:
            anchor_rvas.append(rva)

    if not anchor_rvas:
        payload = {"ok": False, "error": "discover needs an anchor: --rva, --va, --pattern, --export, or --string", "kind": "discover"}
        print_or_write(args, payload, default_name="discover.json")
        return 1

    candidates = []
    lengths = [int(item) for item in args.lengths.split(",") if item.strip()]
    for rva in anchor_rvas[: args.limit]:
        offset = image.rva_to_offset(rva)
        if offset < 0:
            continue
        candidates.extend(
            generate_masked_patterns(
                image.module_name,
                image.image_base,
                image.data,
                rva,
                offset,
                lengths=lengths,
            )
        )

    payload = {"ok": True, "kind": "discover", "module": image.module_name, "path": image.path, "candidates": candidates}
    print_or_write(args, payload, default_name="discover.json")
    if not args.json and not args.output:
        for item in candidates:
            print(f"[{item.score:6s}] rva=0x{item.rva:X} hits={item.hit_count} len={item.length} {item.pattern}")
    return 0


def cmd_compare(args) -> int:
    old_image = PEImage(args.old)
    new_image = PEImage(args.new)
    if args.pattern:
        candidates = [args.pattern]
    elif args.candidates:
        with open(args.candidates, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        candidates = [item["pattern"] for item in payload.get("candidates", [])]
    else:
        payload = {"ok": False, "error": "compare requires --pattern or --candidates", "kind": "compare"}
        print_or_write(args, payload, default_name="compare.json")
        return 1

    rows = []
    for pattern in candidates:
        old_hits = old_image.scan_pattern(pattern, max_results=1000)
        new_hits = new_image.scan_pattern(pattern, max_results=1000)
        rows.append(
            {
                "pattern": pattern,
                "old_hits": len(old_hits),
                "new_hits": len(new_hits),
                "score": score_hit_count(len(new_hits), cross_build=len(old_hits) == 1),
                "old_first_rva": f"0x{old_hits[0].rva:X}" if old_hits else None,
                "new_first_rva": f"0x{new_hits[0].rva:X}" if new_hits else None,
            }
        )

    payload = {"ok": True, "kind": "compare", "old": old_image.path, "new": new_image.path, "results": rows}
    print_or_write(args, payload, default_name="compare.json")
    if not args.json and not args.output:
        for row in rows:
            print(f"[{row['score']:6s}] old={row['old_hits']} new={row['new_hits']} {row['pattern']}")
    return 0


def cmd_report(args) -> int:
    if not args.binary:
        payload = {"ok": False, "error": "report requires --binary", "kind": "report"}
        print_or_write(args, payload, default_name="report.json")
        return 1

    # Static inspect
    inspect_result = analyze_binary(args.binary)

    # Static search (top exports only, no user queries)
    search_payload = {"strings": [], "pattern_hits": [], "export_hits": []}
    if inspect_result.get("ok"):
        try:
            image = PEImage(args.binary)
            exports = image.get_export("")  # No direct way to list all; PEImage has get_export by name only
            # Fallback: use engine_profile exports
            for exp in inspect_result.get("exports", [])[:20]:
                hit = image.get_export(exp["name"])
                if hit:
                    search_payload["export_hits"].append({"name": exp["name"], "rva": hit.rva, "va": hit.va})
        except Exception:
            pass

    # Live snapshot if process requested
    live_payload = None
    if args.process:
        from src.core.memory import attach, detach, enumerate_modules, get_pid_by_name
        pid = get_pid_by_name(args.process)
        if pid:
            handle = attach(pid)
            if handle:
                try:
                    modules = []
                    for name, base, size, path in enumerate_modules(pid):
                        modules.append({"name": name, "base": f"0x{base:X}", "size": size, "path": path})
                    live_payload = {"pid": pid, "modules": modules}
                finally:
                    detach(handle)

    report = {
        "ok": True,
        "kind": "report",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "binary": args.binary,
        "process": args.process or None,
        "inspect": inspect_result,
        "search": search_payload,
        "live": live_payload,
    }

    print_or_write(args, report, default_name="report.json")
    if not args.json and not args.output:
        print(f"Report for {args.binary}")
        if report["process"]:
            print(f"  Process : {report['process']}")
        eng = report["inspect"].get("engine", {})
        print(f"  Engine  : {eng.get('engine', 'unknown')} {eng.get('engine_version', '')}")
        print(f"  Sections: {len(report['inspect'].get('sections', []))}")
        print(f"  Exports : {report['inspect'].get('export_count', 0)}")
        if live_payload:
            print(f"  Live PID: {live_payload['pid']} ({len(live_payload['modules'])} modules)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="GameSDK-Kit - Reverse Engineering CLI for game binaries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m src.ui.recli inspect Palworld-Win64-Shipping.exe --json
  python -m src.ui.recli search Palworld-Win64-Shipping.exe --query HealthComponent --json
  python -m src.ui.recli analyze Palworld-Win64-Shipping.exe --rva 0x123456 --json
  python -m src.ui.recli live --process Palworld-Win64-Shipping.exe --scan-pattern "48 89 5C 24 ?" --json
  python -m src.ui.recli report --binary Palworld-Win64-Shipping.exe --process Palworld-Win64-Shipping.exe --json
        """,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p):
        p.add_argument("--json", action="store_true", help="Emit JSON")
        p.add_argument("--output", "-o", default="", help="Write JSON report to path")

    def add_module_args(p):
        p.add_argument("--module-dir", default="", help="Directory containing target modules")
        p.add_argument("--module", action="append", default=[], help="Explicit module=path mapping; repeatable")

    # inspect
    inspect = sub.add_parser("inspect", help="Static binary profile (PE + engine detection)")
    add_common(inspect)
    inspect.add_argument("binary", help="Path to game executable or DLL")
    inspect.set_defaults(func=cmd_inspect)

    # search
    search = sub.add_parser("search", help="Search strings, patterns, and exports")
    add_common(search)
    add_module_args(search)
    search.add_argument("module_name", help="Module name or path")
    search.add_argument("--query", action="append", default=[], help="String query; repeatable")
    search.add_argument("--pattern", default="", help="IDA-style byte pattern")
    search.add_argument("--export", default="", help="Export symbol name")
    search.add_argument("--min-len", type=int, default=4)
    search.add_argument("--limit", type=int, default=200)
    search.add_argument("--no-utf16", action="store_true")
    search.set_defaults(func=cmd_search)

    # analyze
    analyze = sub.add_parser("analyze", help="Deep disassembly + xrefs + signatures around an anchor")
    add_common(analyze)
    add_module_args(analyze)
    analyze.add_argument("module_name", help="Module name or path")
    analyze.add_argument("--rva", default="")
    analyze.add_argument("--va", default="")
    analyze.add_argument("--pattern", default="")
    analyze.add_argument("--export", default="")
    analyze.add_argument("--string", default="")
    analyze.add_argument("--before", type=int, default=32)
    analyze.add_argument("--size", type=int, default=192)
    analyze.add_argument("--lengths", default="16,24,32,40")
    analyze.add_argument("--ghidra", action="store_true")
    analyze.add_argument("--ghidra-timeout", type=int, default=20)
    analyze.set_defaults(func=cmd_analyze)

    # live
    live = sub.add_parser("live", help="Live process analysis")
    add_common(live)
    live.add_argument("--process", required=True, help="Process name")
    live.add_argument("--scan-pattern", default="", help="Scan all modules for pattern")
    live.add_argument("--max-hits", type=int, default=20)
    live.add_argument("--read-va", default="", help="Read memory at VA")
    live.add_argument("--read-rva", default="", help="Read memory at RVA (requires --read-module)")
    live.add_argument("--read-module", default="", help="Module for --read-rva")
    live.add_argument("--read-size", type=int, default=64)
    live.add_argument("--regions", action="store_true", help="List readable memory regions")
    live.add_argument("--module-filter", default="", help="Only scan this module name (for --scan-pattern)")
    live.set_defaults(func=cmd_live)

    # discover
    discover = sub.add_parser("discover", help="Generate masked candidate signatures from anchors")
    add_common(discover)
    add_module_args(discover)
    discover.add_argument("module_name", help="Module name or path")
    discover.add_argument("--rva", default="")
    discover.add_argument("--va", default="")
    discover.add_argument("--pattern", default="")
    discover.add_argument("--export", default="")
    discover.add_argument("--string", default="")
    discover.add_argument("--lengths", default="16,24,32,40")
    discover.add_argument("--limit", type=int, default=50)
    discover.set_defaults(func=cmd_discover)

    # compare
    compare = sub.add_parser("compare", help="Compare pattern stability across two builds")
    add_common(compare)
    compare.add_argument("--old", required=True)
    compare.add_argument("--new", required=True)
    compare.add_argument("--pattern", default="")
    compare.add_argument("--candidates", default="")
    compare.set_defaults(func=cmd_compare)

    # report
    report = sub.add_parser("report", help="Unified static + live report")
    add_common(report)
    report.add_argument("--binary", required=True)
    report.add_argument("--process", default="")
    report.set_defaults(func=cmd_report)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except RuntimeError as exc:
        payload = {"ok": False, "error": str(exc), "kind": getattr(args, "command", "unknown")}
        if getattr(args, "json", False):
            print(dump_json(payload))
        else:
            print(f"[FAIL] {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
