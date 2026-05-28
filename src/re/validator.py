import os
from typing import Dict, Iterable, List, Optional

from src.re.pe_image import PEImage
from src.re.signatures import SignatureEntry, SignatureHit, ValidationResult, score_hit_count


class ModuleResolver:
    def __init__(self, *, module_dir: str = "", module_paths: Optional[Dict[str, str]] = None):
        self.module_dir = os.path.abspath(module_dir) if module_dir else ""
        self.module_paths = {k.lower(): os.path.abspath(v) for k, v in (module_paths or {}).items()}
        self._cache: Dict[str, PEImage] = {}

    def resolve_path(self, module: str) -> Optional[str]:
        key = module.lower()
        if key in self.module_paths:
            return self.module_paths[key]
        if self.module_dir:
            direct = os.path.join(self.module_dir, module)
            if os.path.exists(direct):
                return direct
            try:
                for name in os.listdir(self.module_dir):
                    if name.lower() == key:
                        return os.path.join(self.module_dir, name)
            except OSError:
                pass
        if os.path.isabs(module) and os.path.exists(module):
            return module
        return None

    def get_image(self, module: str) -> Optional[PEImage]:
        path = self.resolve_path(module)
        if not path:
            return None
        key = path.lower()
        if key not in self._cache:
            self._cache[key] = PEImage(path)
        return self._cache[key]


def parse_module_path_args(values: Iterable[str]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for value in values or []:
        if "=" not in value:
            module = os.path.basename(value)
            path = value
        else:
            module, path = value.split("=", 1)
        mapping[module.strip().lower()] = path.strip().strip('"')
    return mapping


def validate_entry_offline(resolver: ModuleResolver, entry: SignatureEntry, *, max_hits: int = 20) -> ValidationResult:
    image = resolver.get_image(entry.module)
    if image is None:
        return ValidationResult(entry=entry, found=False, error=f"module {entry.module!r} not found")

    if entry.kind == "export":
        hit = image.get_export(entry.symbol)
        if not hit:
            return ValidationResult(entry=entry, found=False, error=f"export {entry.symbol!r} not found")
        return ValidationResult(
            entry=entry,
            found=True,
            hits=[hit],
            score="strong",
            evidence={"module_path": image.path, "image_base": image.image_base},
        )

    hits = []
    matched_pattern = ""
    pattern_errors = []
    for pattern in [entry.pattern] + list(entry.fallbacks or []):
        try:
            hits = image.scan_pattern(pattern, max_results=max_hits + 1)
        except ValueError as exc:
            pattern_errors.append(str(exc))
            continue
        if hits:
            matched_pattern = pattern
            break
    if not hits and pattern_errors and not entry.pattern:
        return ValidationResult(entry=entry, found=False, error="; ".join(pattern_errors))

    if entry.resolve in {"call", "rip", "rip_call"}:
        for hit in hits:
            image.resolve_hit(
                hit,
                disp_offset=1 if entry.resolve == "call" else entry.disp_offset,
                instruction_size=5 if entry.resolve == "call" else entry.instruction_size,
                extra_offset=entry.extra_offset,
            )
    elif entry.extra_offset and entry.resolve == "direct":
        for hit in hits:
            hit.resolved_rva = hit.rva + entry.extra_offset
            hit.resolved_va = hit.va + entry.extra_offset

    section_quality = any((hit.section or "").lower() in {".text", "text"} for hit in hits) or not hits
    score = score_hit_count(len(hits), section_quality=section_quality)
    return ValidationResult(
        entry=entry,
        found=bool(hits),
        hits=hits[:max_hits],
        score=score,
        error="" if hits else "pattern not matched",
        evidence={
            "module_path": image.path,
            "image_base": image.image_base,
            "hit_count": len(hits),
            "truncated": len(hits) > max_hits,
            "pattern_matched": matched_pattern,
        },
    )


def validate_entries_offline(
    entries: Iterable[SignatureEntry],
    resolver: ModuleResolver,
    *,
    max_hits: int = 20,
) -> List[ValidationResult]:
    return [validate_entry_offline(resolver, entry, max_hits=max_hits) for entry in entries]


def validate_entry_live(process_name: str, entry: SignatureEntry, *, max_hits: int = 20) -> ValidationResult:
    from src.core.memory import attach, detach, enumerate_modules, get_module_info, get_pid_by_name
    from src.core.scanner import resolve_rip, scan_pattern

    pid = get_pid_by_name(process_name)
    if not pid:
        return ValidationResult(entry=entry, found=False, error=f"process {process_name!r} not found")
    module_base, module_size = get_module_info(pid, entry.module)
    if not module_base or not module_size:
        return ValidationResult(entry=entry, found=False, error=f"module {entry.module!r} not loaded")

    module_path = ""
    for name, _base, _size, path in enumerate_modules(pid):
        if name.lower() == entry.module.lower():
            module_path = path
            break

    if entry.kind == "export":
        if module_path and os.path.exists(module_path):
            resolver = ModuleResolver(module_paths={entry.module: module_path})
            return validate_entry_offline(resolver, entry, max_hits=max_hits)
        return ValidationResult(entry=entry, found=False, error="live export lookup requires readable module path")

    handle = attach(pid)
    if not handle:
        return ValidationResult(entry=entry, found=False, error="could not attach to process")
    try:
        addrs = []
        matched_pattern = ""
        for pattern in [entry.pattern] + list(entry.fallbacks or []):
            addrs = scan_pattern(handle, module_base, module_size, pattern, max_results=max_hits + 1)
            if addrs:
                matched_pattern = pattern
                break
        hits: List[SignatureHit] = []
        for address in addrs[:max_hits]:
            hit = SignatureHit(rva=address - module_base, va=address, section="")
            if entry.resolve == "call":
                target = resolve_rip(handle, address, disp_offset=1, instruction_size=5)
                if target:
                    hit.resolved_va = target + entry.extra_offset
                    hit.resolved_rva = hit.resolved_va - module_base
            elif entry.resolve in {"rip", "rip_call"}:
                target = resolve_rip(
                    handle,
                    address,
                    disp_offset=entry.disp_offset,
                    instruction_size=entry.instruction_size,
                )
                if target:
                    hit.resolved_va = target + entry.extra_offset
                    hit.resolved_rva = hit.resolved_va - module_base
            hits.append(hit)
    finally:
        detach(handle)

    return ValidationResult(
        entry=entry,
        found=bool(addrs),
        hits=hits,
        score=score_hit_count(len(addrs)),
        error="" if addrs else "pattern not matched",
        evidence={
            "pid": pid,
            "module_base": module_base,
            "module_size": module_size,
            "module_path": module_path,
            "hit_count": len(addrs),
            "truncated": len(addrs) > max_hits,
            "pattern_matched": matched_pattern,
        },
    )


def validate_entries_live(process_name: str, entries: Iterable[SignatureEntry], *, max_hits: int = 20) -> List[ValidationResult]:
    return [validate_entry_live(process_name, entry, max_hits=max_hits) for entry in entries]
