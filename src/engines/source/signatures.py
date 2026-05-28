
from dataclasses import dataclass, field
from typing import List

@dataclass
class SourceSignature:
    name: str
    pattern: str
    disp_offset: int
    instruction_size: int
    description: str
    games: List[str] = field(default_factory=lambda: ["tf2", "csgo"])
    is_64bit: bool = True
    priority: int = 0

GETALLCLASSES_SIGS_64: List[SourceSignature] = [
    SourceSignature(
        name="GetAllClasses_lea_rax_ret",
        pattern="48 8D 05 ?? ?? ?? ?? C3",
        disp_offset=3,
        instruction_size=7,
        description=(
            "lea rax, [rip+disp32] / ret — GetAllClasses trivial accessor. "
            "Returns pointer to the static ClientClass linked list head."
        ),
        priority=0,
    ),
    SourceSignature(
        name="GetAllClasses_mov_rax_ret",
        pattern="48 8B 05 ?? ?? ?? ?? C3",
        disp_offset=3,
        instruction_size=7,
        description=(
            "mov rax, [rip+disp32] / ret — GetAllClasses accessor that "
            "directly loads the head pointer."
        ),
        priority=0,
    ),
    SourceSignature(
        name="GetAllClasses_mov_rax_test",
        pattern="48 8B 05 ?? ?? ?? ?? 48 85 C0 74",
        disp_offset=3,
        instruction_size=7,
        description=(
            "mov rax, [rip+XX] / test rax,rax / jz — loads head pointer "
            "then null-checks. Common in iteration sites."
        ),
        priority=1,
    ),
    SourceSignature(
        name="GetAllClasses_lea_rcx_call",
        pattern="48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85",
        disp_offset=3,
        instruction_size=7,
        description=(
            "lea rcx, [rip+XX] / call / test — passes ClientClass head "
            "as argument to a processing function."
        ),
        priority=2,
    ),
]

GETALLCLASSES_SIGS_32: List[SourceSignature] = [
    SourceSignature(
        name="GetAllClasses_32_mov_eax_ret",
        pattern="A1 ?? ?? ?? ?? C3",
        disp_offset=1,
        instruction_size=5,
        description=(
            "mov eax, [addr32] / ret — 32-bit GetAllClasses accessor. "
            "The 4-byte immediate is the absolute address of the head pointer."
        ),
        is_64bit=False,
        priority=0,
    ),
    SourceSignature(
        name="GetAllClasses_32_mov_eax_test",
        pattern="A1 ?? ?? ?? ?? 85 C0 74",
        disp_offset=1,
        instruction_size=5,
        description=(
            "mov eax, [addr32] / test eax,eax / jz — 32-bit iteration "
            "site for the ClientClass linked list."
        ),
        is_64bit=False,
        priority=1,
    ),
]

CREATEINTERFACE_SIGS_64: List[SourceSignature] = [
    SourceSignature(
        name="CreateInterface_internal_head",
        pattern="48 89 5C 24 ?? 57 48 83 EC ?? 48 8B 1D ?? ?? ?? ??",
        disp_offset=12,
        instruction_size=16,
        description=(
            "CreateInterface function prologue loading the interface "
            "registry linked list head. Resolves to s_pInterfaceRegs."
        ),
        priority=0,
    ),
]

ALL_SOURCE_SIGNATURES = {
    "GetAllClasses_64": GETALLCLASSES_SIGS_64,
    "GetAllClasses_32": GETALLCLASSES_SIGS_32,
    "CreateInterface_64": CREATEINTERFACE_SIGS_64,
}
