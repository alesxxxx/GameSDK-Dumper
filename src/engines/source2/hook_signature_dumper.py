"""
CS2 hook signature dumper — scans client.dll / engine2.dll / etc. for function
signatures defined in hook_signatures.py.

Usage:
    result = dump_hook_signatures(handle, pid)
    # result.entries -> list of CS2HookSignatureResult

Unlike the prediction dumper, this does NOT emit resolved RVAs as the primary
output. Instead it validates that signatures match and produces BOTH:
    1. A signature database (patterns) for runtime loading by the cheat
    2. A validation report showing which signatures matched / failed
"""

import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from src.core.memory import get_module_info
from src.core.scanner import resolve_rip, scan_pattern
from src.engines.source2.hook_signatures import ALL_HOOK_SIGS, CS2HookSig

logger = logging.getLogger(__name__)


@dataclass
class CS2HookSignatureResult:
    """Result of scanning one hook signature."""
    name: str
    module: str
    pattern_matched: str = ""
    rva: int = 0
    absolute: int = 0
    found: bool = False
    error: str = ""
    required: bool = False
    description: str = ""


@dataclass
class CS2HookSignatureDump:
    """Combined output of the hook signature dump."""
    entries: List[CS2HookSignatureResult] = field(default_factory=list)

    @property
    def found_count(self) -> int:
        return sum(1 for e in self.entries if e.found)

    @property
    def required_failed(self) -> List[CS2HookSignatureResult]:
        return [e for e in self.entries if e.required and not e.found]


def _scan_one_sig(
    handle: int,
    entry: CS2HookSig,
    module_base: int,
    module_size: int,
) -> CS2HookSignatureResult:
    """Scan for a single hook signature using fallback patterns."""

    match_addr = 0
    matched_pattern = ""
    for pattern in entry.patterns:
        hits = scan_pattern(handle, module_base, module_size, pattern, max_results=2)
        if hits:
            match_addr = hits[0]
            matched_pattern = pattern
            break

    if not match_addr:
        return CS2HookSignatureResult(
            name=entry.name,
            module=entry.module,
            found=False,
            error="pattern not matched",
            required=entry.required,
            description=entry.description,
        )

    # Resolve based on mode
    if entry.resolve == "direct":
        target = match_addr
    elif entry.resolve == "call":
        target = resolve_rip(handle, match_addr, disp_offset=1, instruction_size=5)
    elif entry.resolve in ("rip", "rip_call"):
        target = resolve_rip(
            handle, match_addr,
            disp_offset=entry.disp_offset,
            instruction_size=entry.instruction_size,
        )
    else:
        return CS2HookSignatureResult(
            name=entry.name,
            module=entry.module,
            found=False,
            error=f"unknown resolve mode: {entry.resolve}",
            required=entry.required,
            description=entry.description,
        )

    if not target:
        return CS2HookSignatureResult(
            name=entry.name,
            module=entry.module,
            pattern_matched=matched_pattern,
            found=False,
            error="rip resolution returned 0",
            required=entry.required,
            description=entry.description,
        )

    target += entry.extra_offset
    rva = target - module_base

    # Sanity: resolved address should be within (or near) the module
    if rva < 0 or rva >= module_size + 0x400000:
        return CS2HookSignatureResult(
            name=entry.name,
            module=entry.module,
            pattern_matched=matched_pattern,
            found=False,
            error=f"resolved address 0x{target:X} outside {entry.module}",
            required=entry.required,
            description=entry.description,
        )

    return CS2HookSignatureResult(
        name=entry.name,
        module=entry.module,
        pattern_matched=matched_pattern,
        rva=rva,
        absolute=target,
        found=True,
        required=entry.required,
        description=entry.description,
    )


def dump_hook_signatures(
    handle: int,
    pid: int,
    progress_callback: Optional[Callable[[str], None]] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> CS2HookSignatureDump:
    """Scan for all hook function signatures with fallback patterns."""

    def _log(msg: str) -> None:
        logger.info(msg)
        if log_fn:
            log_fn(msg)

    module_cache: Dict[str, tuple] = {}
    results: List[CS2HookSignatureResult] = []

    total = len(ALL_HOOK_SIGS)
    for i, entry in enumerate(ALL_HOOK_SIGS, start=1):
        if progress_callback:
            progress_callback(f"[HookSig {i}/{total}] {entry.module}!{entry.name}")

        if entry.module not in module_cache:
            base, size = get_module_info(pid, entry.module)
            module_cache[entry.module] = (base or 0, size or 0)

        mod_base, mod_size = module_cache[entry.module]
        if not mod_base or not mod_size:
            results.append(CS2HookSignatureResult(
                name=entry.name,
                module=entry.module,
                found=False,
                error=f"module {entry.module} not loaded",
                required=entry.required,
                description=entry.description,
            ))
            continue

        result = _scan_one_sig(handle, entry, mod_base, mod_size)
        results.append(result)

        if result.found:
            _log(f"  [OK] {entry.name} = 0x{result.rva:X}  ({result.pattern_matched[:30]}...)")
        else:
            _log(f"  [--] {entry.name} -- {result.error}")

    ok = sum(1 for r in results if r.found)
    _log(f"[HookSigs] {ok}/{total} signatures resolved.")

    required_fails = [r for r in results if r.required and not r.found]
    if required_fails:
        _log(f"[HookSigs] REQUIRED failures: {len(required_fails)}")
        for r in required_fails:
            _log(f"  [FAIL] {r.name}: {r.error}")

    return CS2HookSignatureDump(entries=results)
