import re
from typing import Iterable, List, Optional

from src.re.signatures import SignatureEntry, looks_like_ida_pattern, normalize_pattern


_DEFINE_RE = re.compile(r'^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\s+"([^"]*)"', re.MULTILINE)
_MODULE_COMMENT_RE = re.compile(r"//\s*([A-Za-z0-9_.-]+\.dll|[A-Za-z0-9_.-]+\.exe)(?:\s*\([^)]*\))?", re.IGNORECASE)
_MODULE_INLINE_RE = re.compile(r"\b([A-Za-z0-9_.-]+\.dll|[A-Za-z0-9_.-]+\.exe)\b", re.IGNORECASE)


def normalize_define_name(name: str) -> str:
    for suffix in ("_PATTERN", "_PROC_ADDRESS", "_EXPORT", "_SYMBOL"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def infer_kind(define_name: str, value: str) -> str:
    if define_name.endswith(("_PROC_ADDRESS", "_EXPORT", "_SYMBOL")):
        return "export"
    return "pattern" if looks_like_ida_pattern(value) else "export"


def _module_from_line(line: str) -> Optional[str]:
    match = _MODULE_COMMENT_RE.search(line)
    if match:
        return match.group(1)
    return None


def parse_signature_pack(text: str, *, default_module: str = "client.dll", source: str = "pack") -> List[SignatureEntry]:
    """Parse simple C/C++ ``#define NAME_PATTERN "..."`` signature packs.

    Module comments such as ``// client.dll`` set the module for subsequent
    defines.  Export/proc-address defines are detected by suffix or by values
    that are not byte-pattern tokens.
    """
    entries: List[SignatureEntry] = []
    current_module = default_module

    for line in text.splitlines():
        module = _module_from_line(line)
        if module:
            current_module = module
            continue

        match = _DEFINE_RE.match(line)
        if not match:
            continue
        raw_name, value = match.group(1), match.group(2).strip()
        inline_module = _MODULE_INLINE_RE.search(line)
        module_name = inline_module.group(1) if inline_module else current_module
        kind = infer_kind(raw_name, value)
        name = normalize_define_name(raw_name)
        if kind == "pattern":
            entries.append(
                SignatureEntry(
                    name=name,
                    module=module_name,
                    kind="pattern",
                    pattern=normalize_pattern(value),
                    source=source,
                )
            )
        else:
            entries.append(
                SignatureEntry(
                    name=name,
                    module=module_name,
                    kind="export",
                    symbol=value,
                    source=source,
                )
            )

    return entries


def parse_signature_pack_files(paths: Iterable[str], *, default_module: str = "client.dll") -> List[SignatureEntry]:
    entries: List[SignatureEntry] = []
    for path in paths:
        if path == "-":
            import sys

            text = sys.stdin.read()
            source = "stdin"
        else:
            with open(path, "r", encoding="utf-8") as handle:
                text = handle.read()
            source = path
        entries.extend(parse_signature_pack(text, default_module=default_module, source=source))
    return entries
