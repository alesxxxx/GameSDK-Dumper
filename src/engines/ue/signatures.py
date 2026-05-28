
from dataclasses import dataclass, field
import re
from typing import List, Optional, Tuple

@dataclass
class Signature:
    name: str
    pattern: str
    disp_offset: (
        int
    )
    instruction_size: int
    ue_versions: List[str]
    description: str
    priority: int = 0

GNAMES_SIGS: List[Signature] = [
    Signature(
        name="GNames_lea_rcx_init",
        pattern="48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 01",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["4.23+", "5.x"],
        description=(
            "lea rcx, [rip+disp32] near FNamePool init. "
            "The LEA loads &NamePoolData into rcx before calling the init function. "
            "The trailing C6 05 XX XX XX XX 01 is 'mov byte [rip+XX], 1' setting "
            "bNamePoolInitialized = true. Very unique signature."
        ),
        priority=0,
    ),
    Signature(
        name="GNames_lea_rax_jmp",
        pattern="48 8D 05 ?? ?? ?? ?? EB ?? 48 8D 0D ?? ?? ?? ?? E8",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["4.23+", "5.x"],
        description=(
            "lea rax, [rip+disp32] followed by jmp, then lea rcx, [rip+XX]. "
            "Alternate form seen in some UE4.25+ builds. The first LEA "
            "loads &NamePoolData."
        ),
        priority=1,
    ),
    Signature(
        name="GNames_lea_r8",
        pattern="4C 8D 05 ?? ?? ?? ?? EB ?? 48 8D 15",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["4.23+", "5.x"],
        description=(
            "lea r8, [rip+disp32]. REX.R prefix (4C) variant. "
            "Some compilers choose r8 as the destination register."
        ),
        priority=2,
    ),
    Signature(
        name="GNames_legacy_mov_rax",
        pattern="48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 63",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["4.19-4.22"],
        description=(
            "mov rax, [rip+disp32] loading GNames pointer (pre-4.23). "
            "For these versions, the resolved address holds a POINTER to the "
            "chunk array, not the array itself — requires one extra dereference."
        ),
        priority=1,
    ),
    Signature(
        name="GNames_legacy_pre423_rax",
        pattern="48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 63 ?? ?? 48 8B",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["4.19-4.22"],
        description=(
            "mov rax,[rip+disp32] / test rax,rax / jz / movsxd — "
            "pre-4.23 GNames pointer load. Resolves to the GNames global "
            "which holds a pointer to the chunk table, requires one extra "
            "dereference vs FNamePool."
        ),
        priority=0,
    ),
    Signature(
        name="GNames_pre419_lea_rcx",
        pattern="48 8D 0D ?? ?? ?? ?? 48 85 C9 74 ?? 8B 41",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["4.13-4.18"],
        description="lea rcx,[rip+disp32] — pre-4.19 GNames load via LEA into rcx",
        priority=0,
    ),
    Signature(
        name="GNames_pre419_mov_rcx",
        pattern="48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? 48 8B 01",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["4.13-4.18"],
        description="mov rcx,[rip+disp32] / test rcx,rcx / jz — pre-4.19 pointer load",
        priority=1,
    ),
    Signature(
        name="GNames_alloc_entry",
        pattern="48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B C8 EB",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["5.x"],
        description=(
            "lea rcx, [rip+XX] / call / mov rcx, rax / jmp short. "
            "FNamePool::AllocateEntry call site — the LEA loads &NamePoolData. "
            "Fallback for UE5 builds where the init-flag pattern is absent."
        ),
        priority=3,
    ),
    Signature(
        name="GNames_lea_rcx_call_mov",
        pattern="48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["4.23+", "5.x"],
        description=(
            "lea rcx, [rip+XX] / call / mov — relaxed form. "
            "Targets any LEA+call sequence where rcx loads &NamePoolData "
            "before a member function call. Common in UE4.26/4.27 EAC builds."
        ),
        priority=4,
    ),
    Signature(
        name="GNames_lea_rcx_test",
        pattern="48 8D 0D ?? ?? ?? ?? 48 85",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["4.23+", "5.x"],
        description=(
            "lea rcx, [rip+XX] / test — catches FNamePool accesses "
            "where the pool address is loaded then null-checked. "
            "Very relaxed, may produce false positives — lowest priority."
        ),
        priority=6,
    ),
]

GOBJECTS_SIGS: List[Signature] = [
    Signature(
        name="GObjects_chunked_primary",
        pattern="48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8D 04 D1",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["4.19+", "5.x"],
        description=(
            "mov rax, [rip+XX] / mov rcx, [rax+rcx*8] / lea rax, [rcx+rdx*8]. "
            "The canonical GObjects chunked array lookup. The RIP load gets "
            "the Objects pointer (array of chunk pointers). This is the MOST "
            "reliable GObjects pattern — present in every UE4/UE5 build."
        ),
        priority=0,
    ),
    Signature(
        name="GObjects_chunked_jmp",
        pattern="48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8D 04 D1 EB",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["4.19+", "5.x"],
        description=(
            "Same as primary but with a trailing EB (jmp short). "
            "The extra byte helps disambiguate in case of false positives."
        ),
        priority=1,
    ),
    Signature(
        name="GObjects_rax_variant",
        pattern="48 8B 05 ?? ?? ?? ?? 48 8B 0C ?? 48 8D 04",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["4.19+", "5.x"],
        description=(
            "Relaxed variant: mov rax, [rip+XX] / mov rcx, [rax+reg*8] / lea rax, [rcx+...]. "
            "The second instruction's index register varies by compiler optimization level."
        ),
        priority=2,
    ),
    Signature(
        name="GObjects_NumElements_store",
        pattern="89 0D ?? ?? ?? ?? 48 8B DF 48 89 5C 24",
        disp_offset=2,
        instruction_size=6,
        ue_versions=["5.x"],
        description=(
            "mov [rip+XX], ecx storing NumElements. "
            "UE5-specific alternate. Resolves to &NumElements, "
            "need to subtract field offset (~0x14-0x1C) to get FUObjectArray base."
        ),
        priority=3,
    ),
    Signature(
        name="GObjects_legacy_mov_rbx",
        pattern="48 8B 1D ?? ?? ?? ?? 48 85 DB 74 ?? 48 8B 0B",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["4.19-4.22"],
        description=(
            "mov rbx, [rip+XX] / test rbx,rbx / jz / mov rcx,[rbx]. "
            "Legacy GObjects pattern found in State of Decay 2."
        ),
        priority=1,
    ),
    Signature(
        name="GObjects_ue5_clang_lea_r8",
        pattern="48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 4C 8D 04 D1",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["5.x"],
        description=(
            "mov rax,[rip+XX] / mov rcx,[rax+rcx*8] / lea r8,[rcx+rdx*8]. "
            "UE5 Clang-compiled chunked array access with R8 destination. "
            "Found in The Finals, FragPunk, and other EA/Epic UE5 titles."
        ),
        priority=0,
    ),
    Signature(
        name="GObjects_ue5_clang_lea_r9",
        pattern="48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 4C 8D 0C D1",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["5.x"],
        description=(
            "mov rax,[rip+XX] / mov rcx,[rax+rcx*8] / lea r9,[rcx+rdx*8]. "
            "Another UE5 Clang variant with R9 destination register."
        ),
        priority=1,
    ),
    Signature(
        name="GObjects_ue5_flat_direct",
        pattern="48 8B 05 ?? ?? ?? ?? 48 8B 04 D0",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["5.x"],
        description=(
            "mov rax,[rip+XX] / mov rax,[rax+rdx*8]. "
            "UE5 flat (non-chunked) object array direct access. "
            "Used when object count fits in a single chunk."
        ),
        priority=2,
    ),
    Signature(
        name="GObjects_ue5_mov_rcx_rax",
        pattern="48 8B 0D ?? ?? ?? ?? 48 8B 04 D1 48 85 C0",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["5.x"],
        description=(
            "mov rcx,[rip+XX] / mov rax,[rcx+rdx*8] / test rax,rax. "
            "UE5 variant loading GObjects into RCX instead of RAX."
        ),
        priority=2,
    ),
    Signature(
        name="GObjects_ue5_add_before_lea",
        pattern="48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8D 44 D1 ??",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["5.x"],
        description=(
            "mov rax,[rip+XX] / mov rcx,[rax+rcx*8] / lea rax,[rcx+rdx*8+imm8]. "
            "UE5 variant with immediate offset in LEA instruction."
        ),
        priority=3,
    ),
]

def _parse_ue_version(version: str) -> Tuple[Optional[int], Optional[int]]:
    match = re.search(r"(\d+)(?:\.(\d+))?", version or "")
    if not match:
        return None, None
    major = int(match.group(1))
    minor = int(match.group(2)) if match.group(2) is not None else None
    return major, minor

def _parse_ue_major(version: str) -> Optional[int]:
    return _parse_ue_version(version)[0]

def _signature_version_matches(versions: List[str], major: int, minor: Optional[int]) -> bool:
    for token in versions:
        if token == f"{major}.x":
            return True
        range_match = re.fullmatch(r"(\d+)\.(\d+)-(\d+)\.(\d+)", token)
        if range_match:
            lo_major = int(range_match.group(1))
            lo_minor = int(range_match.group(2))
            hi_major = int(range_match.group(3))
            hi_minor = int(range_match.group(4))
            if minor is None:
                continue
            if (lo_major, lo_minor) <= (major, minor) <= (hi_major, hi_minor):
                return True
            continue

        min_match = re.fullmatch(r"(\d+)\.(\d+)\+", token)
        if min_match:
            min_major = int(min_match.group(1))
            min_minor = int(min_match.group(2))
            if major != min_major:
                continue
            if minor is None or minor >= min_minor:
                return True
        exact_match = re.fullmatch(r"(\d+)(?:\.(\d+))?", token)
        if exact_match:
            token_major = int(exact_match.group(1))
            token_minor = (
                int(exact_match.group(2))
                if exact_match.group(2) is not None
                else None
            )
            if token_major == major and (token_minor is None or token_minor == minor):
                return True
    return False

def get_gobjects_signatures(ue_version: str = "") -> List[Signature]:
    """Return GObjects signatures that fit a known engine major version."""
    major, minor = _parse_ue_version(ue_version)
    if major is None:
        return list(GOBJECTS_SIGS)
    return [
        sig
        for sig in GOBJECTS_SIGS
        if _signature_version_matches(sig.ue_versions, major, minor)
    ]

GWORLD_SIGS: List[Signature] = [
    Signature(
        name="GWorld_rbx_test_r8b",
        pattern="48 8B 1D ?? ?? ?? ?? 48 85 DB 74 ?? 41 B0 01",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["4.19+", "5.x"],
        description=(
            "mov rbx, [rip+XX] / test rbx,rbx / jz / mov r8b,1. "
            "The most specific GWorld pattern. The r8b=1 is a boolean "
            "argument typically used in tick/GC paths."
        ),
        priority=0,
    ),
    Signature(
        name="GWorld_rax_cmovz",
        pattern="48 8B 05 ?? ?? ?? ?? 48 3B C3 48 0F 44 C6",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["4.19+", "5.x"],
        description=(
            "mov rax, [rip+XX] / cmp rax,rbx / cmovz rax,rsi. "
            "World pointer loaded then compared against another object."
        ),
        priority=1,
    ),
    Signature(
        name="GWorld_rax_test_deref",
        pattern="48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 88",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["4.19+", "5.x"],
        description=(
            "mov rax, [rip+XX] / test rax,rax / jz / mov rcx,[rax+??]. "
            "GWorld loaded then immediately dereferenced to access a field."
        ),
        priority=2,
    ),
    Signature(
        name="GWorld_store",
        pattern="48 89 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 40",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["4.19+", "5.x"],
        description=(
            "mov [rip+XX], rax — GWorld being STORED (set). "
            "This is the world assignment, typically in UEngine::LoadMap. "
            "Same displacement math as a load."
        ),
        priority=3,
    ),
    Signature(
        name="GWorld_store_rdi",
        pattern="48 89 3D ?? ?? ?? ?? 48 85 FF",
        disp_offset=3,
        instruction_size=7,
        ue_versions=["4.19+", "5.x"],
        description=(
            "mov [rip+XX], rdi / test rdi, rdi — GWorld store via rdi. "
            "Fallback for builds using rdi as the world pointer register."
        ),
        priority=4,
    ),
]

ALL_SIGNATURES = {
    "GNames": GNAMES_SIGS,
    "GObjects": GOBJECTS_SIGS,
    "GWorld": GWORLD_SIGS,
}
