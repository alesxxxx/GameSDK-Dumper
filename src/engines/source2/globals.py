"""
CS2 engine globals - pattern table + scanner.

Mirrors the flat-table shape used by the Source (TF2) engine module
(src/engines/source/signatures.py). To keep this dumper reusable across
CS2 patches, every engine global lives in ALL_CS2_GLOBALS below. When a
pattern breaks after a CS2 update, update the `pattern` string for the
affected entry and re-run -- no other code changes required.

Patterns are translated from a2x/cs2-dumper's analysis (src/analysis/offsets.rs).
That repo uses a bespoke DSL (${'}, u4, save[1], etc.); we translate each
entry into IDA-style `?? ??` form and explicit disp_offset/instruction_size.

Two resolution modes:

    mode="rip"     (default) - match pattern, read 32-bit RIP-relative
                               displacement at disp_offset, compute
                               target = match + instr_size + disp.
    mode="literal_u32"       - match pattern, read plain 32-bit value at
                               disp_offset as a field offset, and add it
                               to the RVA of the global named `base_from`.
                               When base_from is set, the emitted value is the
                               final module-relative address of that field, not
                               the raw field offset.

The scanner yields module-relative offsets (address minus module base),
matching the cs2-dumper community convention.
"""

import logging
import struct
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from src.core.memory import get_module_info, read_uint64
from src.core.scanner import resolve_rip, scan_pattern

logger = logging.getLogger(__name__)


@dataclass
class CS2Global:
    name: str
    module: str
    pattern: str
    disp_offset: int = 3
    instruction_size: int = 7
    extra_offset: int = 0
    mode: str = "rip"
    base_from: Optional[str] = None
    value_kind: str = "address"
    value_type: str = "uintptr_t"
    description: str = ""


ALL_CS2_GLOBALS: List[CS2Global] = [
    # --- client.dll -----------------------------------------------------
    CS2Global(
        name="dwCSGOInput",
        module="client.dll",
        pattern="48 89 05 ?? ?? ?? ?? 0F 57 C0 0F 11 05",
        disp_offset=3, instruction_size=7,
        description="CCSGOInput singleton. Base for dwViewAngles.",
    ),
    CS2Global(
        name="dwEntityList",
        module="client.dll",
        pattern="48 89 0D ?? ?? ?? ?? E9 ?? ?? ?? ?? CC",
        disp_offset=3, instruction_size=7,
        description="Global entity list head pointer.",
    ),
    CS2Global(
        name="dwGameEntitySystem",
        module="client.dll",
        pattern="48 8B 1D ?? ?? ?? ?? 48 89 1D ?? ?? ?? ?? 4C 63 B3",
        disp_offset=3, instruction_size=7,
        description="Global CGameEntitySystem singleton pointer.",
    ),
    CS2Global(
        name="dwGameEntitySystem_highestEntityIndex",
        module="client.dll",
        pattern="FF 81 ?? ?? ?? ?? 48 85 D2",
        disp_offset=2, instruction_size=6,
        mode="literal_u32",
        value_kind="field_offset",
        value_type="uint32_t",
        description="Field offset within CGameEntitySystem to highest_entity_index (u32 count).",
    ),
    CS2Global(
        name="dwGameRules",
        module="client.dll",
        pattern="F6 C1 01 0F 85 ?? ?? ?? ?? 4C 8B 05 ?? ?? ?? ?? 4D 85",
        disp_offset=12, instruction_size=16,
        description="Current round's CCSGameRules singleton.",
    ),
    CS2Global(
        name="dwGlobalVars",
        module="client.dll",
        pattern="48 89 15 ?? ?? ?? ?? 48 89 42",
        disp_offset=3, instruction_size=7,
        description="CGlobalVarsBase (curtime, frametime, tick_count).",
    ),
    CS2Global(
        name="dwGlowManager",
        module="client.dll",
        pattern="48 8B 05 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC 8B 41",
        disp_offset=3, instruction_size=7,
        description="CGlowManager singleton (ESP glow outlines).",
    ),
    CS2Global(
        name="dwInventoryManager",
        module="client.dll",
        pattern="48 8D 05 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC 8B 91",
        disp_offset=3, instruction_size=7,
        value_type="CCSInventoryManager*",
        description="CCSInventoryManager singleton (GetInstance).",
    ),
    CS2Global(
        name="dwLocalPlayerController",
        module="client.dll",
        pattern="48 8B 05 ?? ?? ?? ?? 41 89 BE",
        disp_offset=3, instruction_size=7,
        value_type="CCSPlayerController*",
        description="Local CCSPlayerController pointer.",
    ),
    CS2Global(
        name="dwLocalPlayerPawn",
        module="client.dll",
        pattern="4C 39 B6 ?? ?? ?? ?? 74 ?? 44 88 BE",
        disp_offset=3, instruction_size=0,
        mode="literal_u32",
        base_from="dwPrediction",
        value_type="C_CSPlayerPawn*",
        description=(
            "Local C_CSPlayerPawn pointer. Computed from dwPrediction + field offset; "
            "read the emitted address as uintptr_t, not CHandle."
        ),
    ),
    CS2Global(
        name="dwPlantedC4",
        module="client.dll",
        pattern="48 8B 15 ?? ?? ?? ?? 41 FF C0 48 8D 4C 24 ?? 44 89 05",
        disp_offset=3, instruction_size=7,
        description="Planted C4 list (nullptr when no bomb is planted).",
    ),
    CS2Global(
        name="dwPrediction",
        module="client.dll",
        pattern="48 8D 05 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC 40 53 56 41 54",
        disp_offset=3, instruction_size=7,
        description="CCSGameMovement / prediction singleton. Base used to locate dwLocalPlayerPawn.",
    ),
    CS2Global(
        name="dwSensitivity",
        module="client.dll",
        pattern="48 8D 0D ?? ?? ?? ?? 66 0F 6E CD",
        disp_offset=3, instruction_size=7,
        extra_offset=0x8,
        description="Mouse sensitivity config singleton.",
    ),
    CS2Global(
        name="dwViewAngles",
        module="client.dll",
        pattern="F2 42 0F 10 84 28 ?? ?? ?? ??",
        disp_offset=6, instruction_size=0,
        mode="literal_u32",
        base_from="dwCSGOInput",
        description="Local player view angles (field offset inside dwCSGOInput).",
    ),
    CS2Global(
        name="dwViewMatrix",
        module="client.dll",
        pattern="48 8D 0D ?? ?? ?? ?? 48 C1 E0 06",
        disp_offset=3, instruction_size=7,
        description="World -> screen 4x4 projection matrix.",
    ),
    CS2Global(
        name="dwViewRender",
        module="client.dll",
        pattern="48 89 05 ?? ?? ?? ?? 48 8B C8 48 85 C0",
        disp_offset=3, instruction_size=7,
        description="View renderer singleton (render target / scope).",
    ),
    CS2Global(
        name="dwWeaponC4",
        module="client.dll",
        pattern="48 8B 15 ?? ?? ?? ?? 48 8B 5C 24 ?? FF C0 89 05 ?? ?? ?? ?? 48 8B C6 48 89 34 EA 80 BE",
        disp_offset=3, instruction_size=7,
        description="Carried C4 weapon entity.",
    ),

    # --- engine2.dll ----------------------------------------------------
    CS2Global(
        name="dwBuildNumber",
        module="engine2.dll",
        pattern="89 05 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? FF 15",
        disp_offset=2, instruction_size=6,
        description="Engine build number (sanity-check the dump matches your CS2 build).",
    ),
    CS2Global(
        name="dwNetworkGameClient",
        module="engine2.dll",
        pattern="48 89 3D ?? ?? ?? ?? FF 87",
        disp_offset=3, instruction_size=7,
        description="CNetworkGameClient singleton (max_clients, server_tick, sign_on_state).",
    ),
    CS2Global(
        name="dwWindowHeight",
        module="engine2.dll",
        pattern="8B 05 ?? ?? ?? ?? 89 03",
        disp_offset=2, instruction_size=6,
        description="Current window height in pixels.",
    ),
    CS2Global(
        name="dwWindowWidth",
        module="engine2.dll",
        pattern="8B 05 ?? ?? ?? ?? 89 07",
        disp_offset=2, instruction_size=6,
        description="Current window width in pixels.",
    ),

    # --- input_system.dll -----------------------------------------------
    CS2Global(
        name="dwInputSystem",
        module="inputsystem.dll",
        pattern="48 89 05 ?? ?? ?? ?? 33 C0",
        disp_offset=3, instruction_size=7,
        description="CInputSystem singleton.",
    ),

    # --- matchmaking.dll ------------------------------------------------
    CS2Global(
        name="dwGameTypes",
        module="matchmaking.dll",
        pattern="48 8D 0D ?? ?? ?? ?? FF 90",
        disp_offset=3, instruction_size=7,
        description="Game type / map metadata table.",
    ),

    # --- soundsystem.dll ------------------------------------------------
    CS2Global(
        name="dwSoundSystem",
        module="soundsystem.dll",
        pattern="48 8D 05 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC 48 89 15",
        disp_offset=3, instruction_size=7,
        description="CSoundSystem singleton.",
    ),
]


@dataclass
class CS2GlobalResult:
    name: str
    module: str
    rva: int
    absolute: int
    description: str = ""
    value_kind: str = "address"
    value_type: str = "uintptr_t"
    source_base_from: Optional[str] = None
    source_field_offset: Optional[int] = None
    found: bool = True
    error: str = ""


def _read_literal_u32(handle: int, address: int) -> Optional[int]:
    from src.core.memory import read_bytes
    buf = read_bytes(handle, address, 4)
    if not buf or len(buf) < 4:
        return None
    return struct.unpack_from("<I", buf)[0]


def _scan_rip(
    handle: int,
    entry: CS2Global,
    module_base: int,
    module_size: int,
) -> CS2GlobalResult:
    hits = scan_pattern(handle, module_base, module_size, entry.pattern, max_results=2)
    if not hits:
        return CS2GlobalResult(
            name=entry.name, module=entry.module, rva=0, absolute=0,
            description=entry.description, value_kind=entry.value_kind,
            value_type=entry.value_type, found=False, error="pattern not matched",
        )
    target = resolve_rip(
        handle, hits[0],
        disp_offset=entry.disp_offset,
        instruction_size=entry.instruction_size,
    )
    if not target:
        return CS2GlobalResult(
            name=entry.name, module=entry.module, rva=0, absolute=0,
            description=entry.description, value_kind=entry.value_kind,
            value_type=entry.value_type, found=False, error="rip resolution returned 0",
        )
    target += entry.extra_offset
    rva = target - module_base
    if rva < 0 or rva >= module_size + 0x400000:
        return CS2GlobalResult(
            name=entry.name, module=entry.module, rva=0, absolute=target,
            description=entry.description, value_kind=entry.value_kind,
            value_type=entry.value_type, found=False,
            error=f"resolved address 0x{target:X} outside {entry.module}",
        )
    return CS2GlobalResult(
        name=entry.name, module=entry.module,
        rva=rva, absolute=target, description=entry.description,
        value_kind=entry.value_kind, value_type=entry.value_type, found=True,
    )


def _scan_literal(
    handle: int,
    entry: CS2Global,
    module_base: int,
    module_size: int,
    resolved: Dict[str, CS2GlobalResult],
) -> CS2GlobalResult:
    base_rva = 0
    if entry.base_from:
        base = resolved.get(entry.base_from)
        if base is None or not base.found:
            return CS2GlobalResult(
                name=entry.name, module=entry.module, rva=0, absolute=0,
                description=entry.description, value_kind=entry.value_kind,
                value_type=entry.value_type, source_base_from=entry.base_from,
                found=False,
                error=f"base_from {entry.base_from!r} unresolved",
            )
        base_rva = base.rva

    hits = scan_pattern(handle, module_base, module_size, entry.pattern, max_results=2)
    if not hits:
        return CS2GlobalResult(
            name=entry.name, module=entry.module, rva=0, absolute=0,
            description=entry.description, value_kind=entry.value_kind,
            value_type=entry.value_type, source_base_from=entry.base_from,
            found=False, error="pattern not matched",
        )
    disp = _read_literal_u32(handle, hits[0] + entry.disp_offset)
    if disp is None:
        return CS2GlobalResult(
            name=entry.name, module=entry.module, rva=0, absolute=0,
            description=entry.description, value_kind=entry.value_kind,
            value_type=entry.value_type, source_base_from=entry.base_from,
            found=False, error="literal u32 read failed",
        )
    rva = base_rva + disp + entry.extra_offset
    return CS2GlobalResult(
        name=entry.name, module=entry.module,
        rva=rva, absolute=module_base + rva,
        description=entry.description, value_kind=entry.value_kind,
        value_type=entry.value_type, source_base_from=entry.base_from,
        source_field_offset=disp + entry.extra_offset, found=True,
    )


def _scan_one(
    handle: int, pid: int, entry: CS2Global,
    module_cache: Dict[str, tuple],
    resolved: Dict[str, CS2GlobalResult],
) -> CS2GlobalResult:
    if entry.module not in module_cache:
        base, size = get_module_info(pid, entry.module)
        module_cache[entry.module] = (base or 0, size or 0)
    module_base, module_size = module_cache[entry.module]
    if not module_base or not module_size:
        return CS2GlobalResult(
            name=entry.name, module=entry.module, rva=0, absolute=0,
            description=entry.description, value_kind=entry.value_kind,
            value_type=entry.value_type, found=False,
            error=f"module {entry.module} not loaded",
        )
    if entry.mode == "literal_u32":
        return _scan_literal(handle, entry, module_base, module_size, resolved)
    return _scan_rip(handle, entry, module_base, module_size)


def _sort_key(entries: List[CS2Global]) -> List[CS2Global]:
    # Run mode="rip" first so literal_u32 entries can reference resolved bases.
    return sorted(entries, key=lambda e: (0 if e.mode == "rip" else 1, e.name))


def find_cs2_globals(
    handle: int,
    pid: int,
    progress_callback: Optional[Callable[[str], None]] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> List[CS2GlobalResult]:
    def _log(msg: str) -> None:
        logger.info(msg)
        if log_fn:
            log_fn(msg)

    module_cache: Dict[str, tuple] = {}
    resolved: Dict[str, CS2GlobalResult] = {}
    results_in_order: List[CS2GlobalResult] = []

    ordered = _sort_key(ALL_CS2_GLOBALS)
    total = len(ordered)
    for i, entry in enumerate(ordered, start=1):
        if progress_callback:
            progress_callback(f"[{i}/{total}] {entry.module}!{entry.name}")
        result = _scan_one(handle, pid, entry, module_cache, resolved)
        resolved[entry.name] = result
        if result.found:
            _log(f"  [OK] {entry.module}!{entry.name} = 0x{result.rva:X}")
        else:
            _log(f"  [--] {entry.module}!{entry.name} -- {result.error}")

    # Emit in table order so the output file is stable regardless of scan order.
    for entry in ALL_CS2_GLOBALS:
        results_in_order.append(resolved[entry.name])

    ok_count = sum(1 for r in results_in_order if r.found)
    _log(f"[Source2] Engine globals: {ok_count}/{total} resolved.")
    return results_in_order
