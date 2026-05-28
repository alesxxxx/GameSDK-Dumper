import json
import os
import sys
from typing import Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.re.pe_image import PEImage
from src.re.signatures import dump_json, to_jsonable
from src.re.validator import ModuleResolver, parse_module_path_args


def write_json_report(path: str, payload) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(to_jsonable(payload), handle, indent=2)


def print_or_write(args, payload, *, default_name: str) -> None:
    if getattr(args, "json", False):
        text = dump_json(payload)
        if args.output:
            write_json_report(args.output, payload)
            print(f"[OK] Wrote {os.path.abspath(args.output)}")
        else:
            print(text)
        return
    if args.output:
        write_json_report(args.output, payload)
        print(f"[OK] Wrote {os.path.abspath(args.output)}")


def make_module_resolver(args) -> ModuleResolver:
    return ModuleResolver(
        module_dir=getattr(args, "module_dir", "") or "",
        module_paths=parse_module_path_args(getattr(args, "module", []) or []),
    )


def load_image_arg(args) -> Optional[PEImage]:
    resolver = make_module_resolver(args)
    image = resolver.get_image(args.module_name)
    if image is None and os.path.exists(args.module_name):
        image = PEImage(args.module_name)
    if image is None:
        print(f"[FAIL] Could not resolve module/path {args.module_name!r}")
    return image


def parse_int(value: str) -> int:
    return int(value, 0)


def anchor_rva_from_args(image: PEImage, args) -> Optional[int]:
    if args.rva:
        return parse_int(args.rva)
    if args.va:
        return image.va_to_rva(parse_int(args.va))
    if getattr(args, "export", None):
        hit = image.get_export(args.export)
        if not hit:
            print(f"[FAIL] export {args.export!r} not found")
            return None
        return hit.rva
    if getattr(args, "pattern", None):
        hits = image.scan_pattern(args.pattern, max_results=2)
        if not hits:
            print("[FAIL] pattern did not match")
            return None
        if len(hits) > 1:
            print("[--] pattern matched more than once; using first hit")
        return hits[0].rva
    return None
