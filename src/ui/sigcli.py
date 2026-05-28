import argparse
import json
import os
import sys
from typing import Dict, Iterable, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.re.cs2_catalog import get_catalog_entries, researched_signature_path
from src.re.pack_parser import parse_signature_pack_files
from src.re.pe_image import PEImage
from src.re.cli_utils import (
    anchor_rva_from_args,
    load_image_arg,
    make_module_resolver,
    parse_int,
    print_or_write,
    write_json_report,
)
from src.re.signatures import (
    CandidateSignature,
    SignatureEntry,
    generate_masked_patterns,
    score_hit_count,
    to_jsonable,
)
from src.re.validator import (
    validate_entries_live,
    validate_entries_offline,
)


def _load_entries(args) -> List[SignatureEntry]:
    entries: List[SignatureEntry] = []
    if getattr(args, "preset", None):
        entries.extend(get_catalog_entries(args.preset))
    if getattr(args, "pack", None):
        entries.extend(parse_signature_pack_files(args.pack, default_module=getattr(args, "default_module", "client.dll")))
    if getattr(args, "name", None):
        needle = args.name.lower()
        entries = [entry for entry in entries if needle in entry.name.lower()]
    if getattr(args, "module_filter", None):
        mod = args.module_filter.lower()
        entries = [entry for entry in entries if entry.module.lower() == mod]
    return entries


def _print_validation_summary(results) -> int:
    total = len(results)
    found = sum(1 for result in results if result.found)
    required_failed = [result for result in results if result.entry.required and not result.found]
    print(f"[CS2 sigcli] {found}/{total} signatures resolved")
    for result in results:
        marker = "OK" if result.found else "--"
        hit_count = result.evidence.get("hit_count", len(result.hits))
        print(f"  [{marker}] {result.entry.module}!{result.entry.name} {result.score} hits={hit_count}")
        if result.hits:
            first = result.hits[0]
            resolved = ""
            if first.resolved_rva is not None:
                resolved = f" -> 0x{first.resolved_rva:X}"
            print(f"       rva=0x{first.rva:X} section={first.section or '?'}{resolved}")
        elif result.error:
            print(f"       {result.error}")
    if required_failed:
        print(f"[FAIL] Required signatures missing: {len(required_failed)}")
        return 1
    return 0 if found == total or found > 0 else 1


def cmd_validate(args) -> int:
    entries = _load_entries(args)
    if not entries:
        print("[FAIL] No signatures selected. Use --preset, --pack, or both.")
        return 1
    if args.live:
        results = validate_entries_live(args.process, entries, max_hits=args.max_hits)
    else:
        results = validate_entries_offline(entries, make_module_resolver(args), max_hits=args.max_hits)
    payload = {"kind": "validation_report", "results": results}
    print_or_write(args, payload, default_name="validation.json")
    if args.json:
        return 0 if any(result.found for result in results) else 1
    return _print_validation_summary(results)


def cmd_scan(args) -> int:
    if not args.pack:
        print("[FAIL] scan requires --pack FILE or --pack -")
        return 1
    args.preset = None
    return cmd_validate(args)


def cmd_strings(args) -> int:
    image = load_image_arg(args)
    if image is None:
        return 1
    results = image.find_strings(
        queries=args.query or (),
        min_len=args.min_len,
        limit=args.limit,
        include_utf16=not args.no_utf16,
    )
    payload = {"kind": "strings", "module": image.module_name, "path": image.path, "strings": results}
    print_or_write(args, payload, default_name="strings.json")
    if args.json:
        return 0
    for item in results:
        print(f"0x{item.rva:X} {item.section:8s} {item.encoding:7s} {item.value}")
    return 0


def cmd_xrefs(args) -> int:
    image = load_image_arg(args)
    if image is None:
        return 1
    target_rvas: List[int] = []
    string_hits = []
    if args.rva:
        target_rvas.append(parse_int(args.rva))
    if args.va:
        target_rvas.append(image.va_to_rva(parse_int(args.va)))
    if args.string:
        string_hits = image.find_strings(queries=[args.string], min_len=max(2, len(args.string)), limit=args.limit)
        target_rvas.extend(item.rva for item in string_hits)
    if not target_rvas:
        print("[FAIL] xrefs requires --rva, --va, or --string")
        return 1
    xrefs = image.find_rip_xrefs(target_rvas, tolerance=args.tolerance, limit=args.limit)
    payload = {
        "kind": "xrefs",
        "module": image.module_name,
        "path": image.path,
        "targets": [f"0x{rva:X}" for rva in target_rvas],
        "strings": string_hits,
        "xrefs": xrefs,
    }
    print_or_write(args, payload, default_name="xrefs.json")
    if args.json:
        return 0
    for item in xrefs:
        print(f"0x{item.source_rva:X} -> 0x{item.target_rva:X} {item.section} {item.instruction}")
    return 0


def cmd_func(args) -> int:
    image = load_image_arg(args)
    if image is None:
        return 1
    rva = anchor_rva_from_args(image, args)
    if rva is None:
        print("[FAIL] func requires --rva, --va, --pattern, or --export")
        return 1
    rows = image.disassemble(rva, before=args.before, size=args.size)
    payload = {
        "kind": "function_context",
        "module": image.module_name,
        "path": image.path,
        "rva": f"0x{rva:X}",
        "va": f"0x{image.rva_to_va(rva):X}",
        "disassembly": rows,
    }
    if args.ghidra:
        from src.re.ghidra_bridge import decompile_function_best_effort

        payload["ghidra"] = decompile_function_best_effort(image.path, rva, timeout_secs=args.ghidra_timeout)
    print_or_write(args, payload, default_name="func.json")
    if args.json:
        return 0
    for row in rows:
        marker = " <==" if row["rva"] == rva else ""
        print(f"0x{row['rva']:08X}: {row['bytes']:<28s} {row['mnemonic']:<8s} {row['op_str']}{marker}")
    ghidra = payload.get("ghidra")
    if ghidra:
        print("\n[Ghidra]")
        print(ghidra.get("decompiled") if ghidra.get("ok") else ghidra.get("error"))
    return 0


def cmd_discover(args) -> int:
    image = load_image_arg(args)
    if image is None:
        return 1
    anchor_rvas: List[int] = []
    if args.string:
        strings = image.find_strings(queries=[args.string], min_len=max(2, len(args.string)), limit=args.limit)
        xrefs = image.find_rip_xrefs([item.rva for item in strings], limit=args.limit)
        anchor_rvas.extend(item.source_rva for item in xrefs)
    else:
        rva = anchor_rva_from_args(image, args)
        if rva is not None:
            anchor_rvas.append(rva)
    if not anchor_rvas:
        print("[FAIL] discover needs an anchor: --rva, --va, --pattern, --export, or --string")
        return 1
    candidates: List[CandidateSignature] = []
    lengths = [int(item) for item in args.lengths.split(",") if item.strip()]
    for rva in anchor_rvas[: args.limit]:
        offset = image.rva_to_offset(rva)
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
    payload = {"kind": "candidate_signatures", "module": image.module_name, "path": image.path, "candidates": candidates}
    print_or_write(args, payload, default_name="discover.json")
    if args.json:
        return 0
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
        print("[FAIL] compare requires --pattern or --candidates")
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
    payload = {"kind": "signature_compare", "old": old_image.path, "new": new_image.path, "results": rows}
    print_or_write(args, payload, default_name="compare.json")
    if args.json:
        return 0
    for row in rows:
        print(f"[{row['score']:6s}] old={row['old_hits']} new={row['new_hits']} {row['pattern']}")
    return 0


def _entries_from_proposal(path: str) -> List[SignatureEntry]:
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    entries: List[SignatureEntry] = []
    for item in payload.get("signatures", []):
        entries.append(SignatureEntry(**item))
    for item in payload.get("candidates", []):
        name = item.get("name") or f"Candidate_{item.get('rva', '0').replace('0x', '')}"
        entries.append(
            SignatureEntry(
                name=name,
                module=item.get("module", ""),
                kind="pattern",
                pattern=item["pattern"],
                source=path,
            )
        )
    return entries


def cmd_promote(args) -> int:
    entries = _entries_from_proposal(args.input)
    if not entries:
        print("[FAIL] No signatures found in proposal.")
        return 1
    target = args.target or researched_signature_path()
    payload = {
        "schema_version": 1,
        "kind": "researched_signatures",
        "signatures": [to_jsonable(entry) for entry in entries],
    }
    if args.apply:
        os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
        existing: Dict[tuple, SignatureEntry] = {}
        if os.path.exists(target):
            for entry in _entries_from_proposal(target):
                existing[(entry.kind, entry.module.lower(), entry.name.lower())] = entry
        for entry in entries:
            existing[(entry.kind, entry.module.lower(), entry.name.lower())] = entry
        payload["signatures"] = [to_jsonable(entry) for entry in existing.values()]
        write_json_report(target, payload)
        print(f"[OK] Applied {len(entries)} signature(s) to {os.path.abspath(target)}")
    else:
        out = args.output or os.path.join("games", "cs2", "SignatureResearch", "promote_proposal.json")
        write_json_report(out, payload)
        print(f"[OK] Wrote promotion proposal to {os.path.abspath(out)}")
        print("     Re-run with --apply to add it to src/engines/source2/researched_signatures.json")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CS2 Signature Research CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m src.ui.sigcli validate --module-dir "C:\\Steam\\steamapps\\common\\Counter-Strike Global Offensive\\game\\csgo\\bin\\win64"
  python -m src.ui.sigcli scan --pack sigs.hpp --module-dir C:\\cs2\\bin\\win64
  python -m src.ui.sigcli discover client.dll --module-dir C:\\cs2\\bin\\win64 --string SubmitChatText
  python -m src.ui.sigcli func client.dll --module-dir C:\\cs2\\bin\\win64 --rva 0xC5C2A0
        """,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common_scan(p):
        p.add_argument("--module-dir", default="", help="Directory containing target modules")
        p.add_argument("--module", action="append", default=[], help="Explicit module=path mapping; repeatable")
        p.add_argument("--json", action="store_true", help="Emit JSON")
        p.add_argument("--output", "-o", default="", help="Write JSON report to path")

    validate = sub.add_parser("validate", help="Validate built-in/catalog signatures")
    add_common_scan(validate)
    validate.add_argument("--preset", choices=["all", "tables", "globals", "prediction", "hooks", "extended", "researched"], default="all")
    validate.add_argument("--pack", action="append", default=[], help="Additional C/C++ signature pack")
    validate.add_argument("--default-module", default="client.dll")
    validate.add_argument("--name", default="", help="Filter by signature name substring")
    validate.add_argument("--module-filter", default="", help="Filter by module name")
    validate.add_argument("--max-hits", type=int, default=20)
    validate.add_argument("--live", action="store_true", help="Validate against a running process")
    validate.add_argument("--process", default="cs2.exe")
    validate.set_defaults(func=cmd_validate)

    scan = sub.add_parser("scan", help="Validate a #define signature pack")
    add_common_scan(scan)
    scan.add_argument("--pack", action="append", required=True, help="Pack file, or - for stdin")
    scan.add_argument("--default-module", default="client.dll")
    scan.add_argument("--max-hits", type=int, default=20)
    scan.add_argument("--live", action="store_true")
    scan.add_argument("--process", default="cs2.exe")
    scan.set_defaults(func=cmd_scan)

    strings = sub.add_parser("strings", help="Extract strings from a module")
    add_common_scan(strings)
    strings.add_argument("module_name", help="Module name or path")
    strings.add_argument("--query", action="append", default=[])
    strings.add_argument("--min-len", type=int, default=4)
    strings.add_argument("--limit", type=int, default=200)
    strings.add_argument("--no-utf16", action="store_true")
    strings.set_defaults(func=cmd_strings)

    xrefs = sub.add_parser("xrefs", help="Find RIP-relative xrefs to strings/RVAs")
    add_common_scan(xrefs)
    xrefs.add_argument("module_name")
    xrefs.add_argument("--string", default="")
    xrefs.add_argument("--rva", default="")
    xrefs.add_argument("--va", default="")
    xrefs.add_argument("--tolerance", type=int, default=0)
    xrefs.add_argument("--limit", type=int, default=200)
    xrefs.set_defaults(func=cmd_xrefs)

    func = sub.add_parser("func", help="Disassemble/decompile around an anchor")
    add_common_scan(func)
    func.add_argument("module_name")
    func.add_argument("--rva", default="")
    func.add_argument("--va", default="")
    func.add_argument("--pattern", default="")
    func.add_argument("--export", default="")
    func.add_argument("--before", type=int, default=32)
    func.add_argument("--size", type=int, default=192)
    func.add_argument("--ghidra", action="store_true")
    func.add_argument("--ghidra-timeout", type=int, default=20)
    func.set_defaults(func=cmd_func)

    discover = sub.add_parser("discover", help="Generate masked candidate signatures")
    add_common_scan(discover)
    discover.add_argument("module_name")
    discover.add_argument("--rva", default="")
    discover.add_argument("--va", default="")
    discover.add_argument("--pattern", default="")
    discover.add_argument("--export", default="")
    discover.add_argument("--string", default="")
    discover.add_argument("--lengths", default="16,24,32,40")
    discover.add_argument("--limit", type=int, default=50)
    discover.set_defaults(func=cmd_discover)

    compare = sub.add_parser("compare", help="Compare patterns across two module builds")
    compare.add_argument("--old", required=True)
    compare.add_argument("--new", required=True)
    compare.add_argument("--pattern", default="")
    compare.add_argument("--candidates", default="")
    compare.add_argument("--json", action="store_true")
    compare.add_argument("--output", "-o", default="")
    compare.set_defaults(func=cmd_compare)

    promote = sub.add_parser("promote", help="Create/apply researched signature proposals")
    promote.add_argument("--input", required=True)
    promote.add_argument("--output", "-o", default="")
    promote.add_argument("--target", default="")
    promote.add_argument("--apply", action="store_true")
    promote.set_defaults(func=cmd_promote)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except RuntimeError as exc:
        print(f"[FAIL] {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
