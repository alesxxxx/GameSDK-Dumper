"""
CS2 prediction dumper — scans client.dll / engine2.dll for function signatures
and provides hardcoded struct-field offsets for internal input structures.

Usage:
    result = dump_prediction(handle, pid)
    # result.functions      -> list of CS2PredictionResult (function RVAs)
    # result.struct_offsets  -> list of CS2PredictionResult (field offsets)
"""

import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from src.core.memory import get_module_info, read_bytes
from src.core.scanner import resolve_rip, scan_pattern
from src.engines.source2.prediction_signatures import (
    ALL_PREDICTION_SIGS,
    PREDICTION_STRUCT_FIELDS,
    CS2PredictionSig,
)

logger = logging.getLogger(__name__)

def _find_previous_rip_load(handle: int, start_addr: int, max_back: int = 96) -> int:
    """Scan backwards from an address looking for '48 8B 0D' and resolve the RIP."""
    if not start_addr:
        return 0
    search_start = start_addr - max_back
    chunk = read_bytes(handle, search_start, max_back + 3)
    if not chunk or len(chunk) < 3:
        return 0
        
    for i in range(len(chunk) - 3, -1, -1):
        if chunk[i] == 0x48 and chunk[i+1] == 0x8B and chunk[i+2] == 0x0D:
            match_addr = search_start + i
            return resolve_rip(handle, match_addr, 3, 7)
    return 0


@dataclass
class CS2PredictionResult:
    """One resolved prediction offset (function or struct field)."""
    name: str
    module: str
    rva: int
    absolute: int
    kind: str = "function"          # "function" | "struct_offset"
    struct_name: str = ""
    field_name: str = ""
    description: str = ""
    found: bool = True
    error: str = ""


@dataclass
class CS2PredictionDump:
    """Combined output of the prediction dumper."""
    functions: List[CS2PredictionResult] = field(default_factory=list)
    struct_offsets: List[CS2PredictionResult] = field(default_factory=list)

    @property
    def all_results(self) -> List[CS2PredictionResult]:
        return self.functions + self.struct_offsets


# ---------------------------------------------------------------------------
# Function signature scanning (with fallback pattern chains)
# ---------------------------------------------------------------------------

def _scan_one_sig(
    handle: int,
    entry: CS2PredictionSig,
    module_base: int,
    module_size: int,
) -> CS2PredictionResult:
    """Scan for a single prediction function signature using fallback patterns."""

    # Try each pattern in order until one matches
    match_addr = 0
    for pattern in entry.patterns:
        hits = scan_pattern(handle, module_base, module_size, pattern, max_results=2)
        if hits:
            match_addr = hits[0]
            break

    if not match_addr:
        return CS2PredictionResult(
            name=entry.name, module=entry.module, rva=0, absolute=0,
            kind="function", description=entry.description,
            found=False, error="pattern not matched",
        )

    # Resolve based on mode
    if entry.resolve == "direct":
        # Pattern IS the function address
        rva = match_addr - module_base
        return CS2PredictionResult(
            name=entry.name, module=entry.module,
            rva=rva, absolute=match_addr,
            kind="function", description=entry.description, found=True,
        )

    if entry.resolve == "call":
        # E8 rel32 call resolution
        target = resolve_rip(handle, match_addr, disp_offset=1, instruction_size=5)
    else:
        # Generic RIP-relative (mov/lea with custom disp_offset)
        target = resolve_rip(
            handle, match_addr,
            disp_offset=entry.disp_offset,
            instruction_size=entry.instruction_size,
        )

    if not target:
        return CS2PredictionResult(
            name=entry.name, module=entry.module, rva=0, absolute=0,
            kind="function", description=entry.description,
            found=False, error="rip resolution returned 0",
        )

    target += entry.extra_offset
    rva = target - module_base

    # Sanity: resolved address should be within (or near) the module
    if rva < 0 or rva >= module_size + 0x400000:
        return CS2PredictionResult(
            name=entry.name, module=entry.module, rva=0, absolute=target,
            kind="function", description=entry.description,
            found=False,
            error=f"resolved address 0x{target:X} outside {entry.module}",
        )

    return CS2PredictionResult(
        name=entry.name, module=entry.module,
        rva=rva, absolute=target,
        kind="function", description=entry.description, found=True,
    )


def find_prediction_signatures(
    handle: int,
    pid: int,
    progress_callback: Optional[Callable[[str], None]] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> List[CS2PredictionResult]:
    """Scan for all prediction function signatures with fallback patterns."""

    def _log(msg: str) -> None:
        logger.info(msg)
        if log_fn:
            log_fn(msg)

    module_cache: Dict[str, tuple] = {}
    results: List[CS2PredictionResult] = []

    total = len(ALL_PREDICTION_SIGS)
    for i, entry in enumerate(ALL_PREDICTION_SIGS, start=1):
        if progress_callback:
            progress_callback(f"[Prediction {i}/{total}] {entry.module}!{entry.name}")

        if entry.module not in module_cache:
            base, size = get_module_info(pid, entry.module)
            module_cache[entry.module] = (base or 0, size or 0)

        mod_base, mod_size = module_cache[entry.module]
        if not mod_base or not mod_size:
            results.append(CS2PredictionResult(
                name=entry.name, module=entry.module, rva=0, absolute=0,
                kind="function", description=entry.description,
                found=False, error=f"module {entry.module} not loaded",
            ))
            continue

        result = _scan_one_sig(handle, entry, mod_base, mod_size)

        # Backward scan fallback for fnCommandBase
        if entry.name == "fnCommandBase" and not result.found:
            entry_sig = next((r for r in results if r.name == "fnGetUserCmdEntry"), None)
            if entry_sig and entry_sig.found:
                found_addr = _find_previous_rip_load(handle, entry_sig.absolute)
                if found_addr:
                    result.found = True
                    result.error = ""
                    result.absolute = found_addr
                    result.rva = found_addr - mod_base
                    result.description += " (found via backward scan from fnGetUserCmdEntry)"

        results.append(result)

        if result.found:
            _log(f"  [OK] {entry.name} = 0x{result.rva:X}")
        else:
            _log(f"  [--] {entry.name} -- {result.error}")

    ok = sum(1 for r in results if r.found)
    _log(f"[Prediction] Function signatures: {ok}/{total} resolved.")
    return results


# ---------------------------------------------------------------------------
# Struct-field offsets (hardcoded — NOT from schema)
# ---------------------------------------------------------------------------

def get_prediction_struct_offsets(
    log_fn: Optional[Callable[[str], None]] = None,
) -> List[CS2PredictionResult]:
    """Return hardcoded struct-field offsets for internal prediction structures.

    CCSGOInput, CUserCmd, and CBaseUserCmdPB are protobuf-based internal
    structures that the Source 2 schema system does not expose. Offsets are
    maintained as known values in prediction_signatures.py.
    """

    def _log(msg: str) -> None:
        logger.info(msg)
        if log_fn:
            log_fn(msg)

    results: List[CS2PredictionResult] = []

    for entry in PREDICTION_STRUCT_FIELDS:
        results.append(CS2PredictionResult(
            name=entry.output_key,
            module="client.dll",
            rva=entry.offset,
            absolute=0,
            kind="struct_offset",
            struct_name=entry.struct_name,
            field_name=entry.field_name,
            description=entry.description,
            found=True,
        ))
        _log(f"  [OK] {entry.output_key} = 0x{entry.offset:X}  "
             f"({entry.struct_name}::{entry.field_name})")

    total = len(PREDICTION_STRUCT_FIELDS)
    _log(f"[Prediction] Struct offsets: {total}/{total} (hardcoded).")
    return results


# ---------------------------------------------------------------------------
# Combined orchestrator
# ---------------------------------------------------------------------------

def dump_prediction(
    handle: int,
    pid: int,
    progress_callback: Optional[Callable[[str], None]] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> CS2PredictionDump:
    """Run the full prediction dump: function sigs + struct field offsets."""

    def _log(msg: str) -> None:
        logger.info(msg)
        if log_fn:
            log_fn(msg)

    _log("[Prediction] Scanning function signatures...")
    functions = find_prediction_signatures(
        handle, pid,
        progress_callback=progress_callback,
        log_fn=log_fn,
    )

    _log("[Prediction] Emitting hardcoded struct offsets...")
    struct_offsets = get_prediction_struct_offsets(log_fn=log_fn)

    dump = CS2PredictionDump(functions=functions, struct_offsets=struct_offsets)

    ok_total = sum(1 for r in dump.all_results if r.found)
    all_total = len(dump.all_results)
    _log(f"[Prediction] Complete: {ok_total}/{all_total} total offsets resolved.")

    return dump
