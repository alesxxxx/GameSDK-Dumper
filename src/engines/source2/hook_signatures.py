"""
CS2 hook/function signatures — pattern table for functions commonly hooked
or called by internal cheats.

Each entry supports multiple fallback patterns (tried in order). When one
pattern breaks after a CS2 update, fallbacks can still match older/newer
instruction layouts.

Resolution modes:
    "direct"    — pattern IS the function address (no resolution)
    "call"      — E8 rel32 call: resolve_rip(match, 1, 5)
    "rip"       — RIP-relative load: resolve_rip(match, disp_offset, instruction_size)
    "rip_call"  — RIP-relative load that points to a function pointer

Usage in dumper:
    from src.engines.source2.hook_signatures import ALL_HOOK_SIGS
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class CS2HookSig:
    """One scannable function signature.

    `patterns` is a list of fallback IDA-style patterns tried in order.
    `resolve` controls how the match address is turned into the final address:
        "direct"    — pattern IS the function address
        "call"      — E8 rel32 call: resolve_rip(match, 1, 5)
        "rip"       — RIP-relative load: resolve_rip(match, disp_offset, instruction_size)
        "rip_call"  — RIP-relative load that yields a function pointer (same math as rip)
    """
    name: str
    module: str
    patterns: List[str]
    resolve: str = "direct"
    disp_offset: int = 3
    instruction_size: int = 7
    extra_offset: int = 0
    required: bool = False
    description: str = ""


# ---------------------------------------------------------------------------
# Rendering / D3D11
# ---------------------------------------------------------------------------
_RENDERING_SIGS: List[CS2HookSig] = [
    CS2HookSig(
        name="Present",
        module="rendersystemvulkan.dll",
        patterns=[
            "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B F1 41 8B F8",
            "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B F9",
        ],
        resolve="direct",
        description="IDXGISwapChain::Present — main render hook point.",
    ),
    CS2HookSig(
        name="ResizeBuffers",
        module="rendersystemvulkan.dll",
        patterns=[
            "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 49 8B F0 48 8B FA",
        ],
        resolve="direct",
        description="IDXGISwapChain::ResizeBuffers — called on resolution change.",
    ),
]

# ---------------------------------------------------------------------------
# Input / CreateMove / Prediction
# ---------------------------------------------------------------------------
_INPUT_SIGS: List[CS2HookSig] = [
    CS2HookSig(
        name="CreateMove",
        module="client.dll",
        patterns=[
            "48 8B C4 4C 89 40 ? 48 89 48 ? 55 53 41 54",
            "40 53 48 83 EC ? 48 8B D9 E8 ? ? ? ? 33 C0 C6 83",
            "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B F2 48 8B F9",
        ],
        resolve="direct",
        required=True,
        description="CCSGOInput::CreateMove — primary tick hook for CUserCmd mutation.",
    ),
    CS2HookSig(
        name="CreateMovePrePrediction",
        module="client.dll",
        patterns=[
            "40 53 48 83 EC ? 48 8B D9 E8 ? ? ? ? 33 C0 C6 83 ? ? ? ? 00",
            "40 53 48 83 EC ? 48 8B D9 E8 ? ? ? ? 33 C0",
        ],
        resolve="direct",
        description="CCSGOInput vtable[5] — pre-prediction CreateMove entry.",
    ),
    CS2HookSig(
        name="FrameStageNotify",
        module="client.dll",
        patterns=[
            "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B F9 E8 ? ? ? ? 8B D3",
            "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B F9 E8",
        ],
        resolve="direct",
        description="IClientMode::FrameStageNotify — frame stage hook point.",
    ),
    CS2HookSig(
        name="OverrideView",
        module="client.dll",
        patterns=[
            "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC ? 48 8B FA E8",
            "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC ? 48 8B FA",
        ],
        resolve="direct",
        description="IClientMode::OverrideView — view setup override (FOV, thirdperson, etc).",
    ),
    CS2HookSig(
        name="AllowCameraAngleChange",
        module="client.dll",
        patterns=[
            "48 89 5C 24 ? 57 48 83 EC ? 48 8B D9 48 8B FA 48 8B CB E8",
        ],
        resolve="direct",
        description="CCSGOInput::AllowCameraAngleChange — blocks view drift while menu open.",
    ),
    CS2HookSig(
        name="IsRelativeMouseMode",
        module="inputsystem.dll",
        patterns=[
            "48 89 5C 24 ? 57 48 83 EC ? 48 8B F9 0F B6 DA 84 D2",
        ],
        resolve="direct",
        description="IInputSystem::IsRelativeMouseMode — frees cursor for menu interaction.",
    ),
    CS2HookSig(
        name="MouseInputEnabled",
        module="client.dll",
        patterns=[
            "48 89 5C 24 ? 57 48 83 EC ? 48 8B F9 0F B6 DA 84 D2 74 ? 80 79",
        ],
        resolve="direct",
        description="CCSGOInput::MouseInputEnabled — blocks game mouse when menu open.",
    ),
]

# ---------------------------------------------------------------------------
# Entity / Game System
# ---------------------------------------------------------------------------
_ENTITY_SIGS: List[CS2HookSig] = [
    CS2HookSig(
        name="OnAddEntity",
        module="client.dll",
        patterns=[
            "48 89 74 24 ? 57 48 83 EC ? 41 B9 ? ? ? ? 41 8B C0 41 23 C1 48 8B F2 41 83 F8 ? 48 8B F9 44 0F 45 C8 41 81 F9 ? ? ? ? 73 ? FF 81",
        ],
        resolve="direct",
        description="CGameEntitySystem::OnAddEntity — called when entities spawn.",
    ),
    CS2HookSig(
        name="OnRemoveEntity",
        module="client.dll",
        patterns=[
            "48 89 74 24 ? 57 48 83 EC ? 41 B9 ? ? ? ? 41 8B C0 41 23 C1 48 8B F2 41 83 F8 ? 48 8B F9 44 0F 45 C8 41 81 F9 ? ? ? ? 73 ? FF 89",
        ],
        resolve="direct",
        description="CGameEntitySystem::OnRemoveEntity — called when entities despawn.",
    ),
    CS2HookSig(
        name="GetMatrixForView",
        module="client.dll",
        patterns=[
            "40 53 48 81 EC ? ? ? ? 49 8B C1",
        ],
        resolve="direct",
        description="CRenderGameSystem::GetMatrixForView — world-to-screen matrix.",
    ),
    CS2HookSig(
        name="LevelInit",
        module="client.dll",
        patterns=[
            "48 89 5C 24 ? 57 48 83 EC ? 48 8B F9 48 8B 0D ?? ?? ?? ?? 48 8B 01",
        ],
        resolve="direct",
        description="IClientMode::LevelInit — map load hook.",
    ),
    CS2HookSig(
        name="LevelShutdown",
        module="client.dll",
        patterns=[
            "48 89 5C 24 ? 57 48 83 EC ? 48 8B F9 48 8B 0D ?? ?? ?? ?? 48 8B 01 FF 50 ? 48 8B CF",
        ],
        resolve="direct",
        description="IClientMode::LevelShutdown — map unload hook.",
    ),
]

# ---------------------------------------------------------------------------
# Trace / Physics / Autowall
# ---------------------------------------------------------------------------
_TRACE_SIGS: List[CS2HookSig] = [
    CS2HookSig(
        name="TraceShape",
        module="client.dll",
        patterns=[
            "48 89 5C 24 ? 48 89 4C 24 ? 55 57",
        ],
        resolve="direct",
        description="CVPhys2World::TraceShape — raycast / trace entry.",
    ),
    CS2HookSig(
        name="ClipRayToEntity",
        module="client.dll",
        patterns=[
            "48 8B C4 48 89 58 ? 55 56 57 41 54 41 56 48 8D 68 ? 48 81 EC ? ? ? ? 48 8B 5D",
        ],
        resolve="direct",
        description="Clip ray to specific entity (used for autowall / hitbox traces).",
    ),
    CS2HookSig(
        name="GetSurfaceData",
        module="client.dll",
        patterns=[
            "E8 ?? ?? ?? ?? 80 78 18 00",
        ],
        resolve="call",
        description="VPhysics2::GetSurfaceData — surface penetration data.",
    ),
    CS2HookSig(
        name="TraceToExit",
        module="client.dll",
        patterns=[
            "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B 09",
        ],
        resolve="direct",
        description="CVPhys2World::TraceToExit — bullet wall penetration trace.",
    ),
]

# ---------------------------------------------------------------------------
# Weapon / Skin / Materials
# ---------------------------------------------------------------------------
_WEAPON_SIGS: List[CS2HookSig] = [
    CS2HookSig(
        name="C_CSWeaponBase_UpdateSkin",
        module="client.dll",
        patterns=[
            "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 8B DA 48 8B F9 E8",
            "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 8B DA 48 8B F9",
        ],
        resolve="direct",
        required=False,
        description="C_CSWeaponBase::UpdateSkin — skin changer core function.",
    ),
    CS2HookSig(
        name="RegenerateWeaponSkin",
        module="client.dll",
        patterns=[
            "40 55 53 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 44 0F B6 FA 48 8B D9 BA ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ?",
        ],
        resolve="direct",
        required=False,
        description="C_CSWeaponBase::RegenerateWeaponSkin — forces skin refresh.",
    ),
    CS2HookSig(
        name="SetModel",
        module="client.dll",
        patterns=[
            "40 53 48 83 EC ? 48 8B D9 4C 8B C2 48 8B 0D ?? ?? ?? ?? 48 8D 54 24",
        ],
        resolve="direct",
        required=False,
        description="C_BaseEntity::SetModel — model swap for knife changer.",
    ),
    CS2HookSig(
        name="UpdateSubClass",
        module="client.dll",
        patterns=[
            "40 53 48 83 EC 30 48 8B 41 10 48 8B D9 8B 50 30",
        ],
        resolve="direct",
        required=False,
        description="C_BaseEntity::UpdateSubClass — subclass hash update.",
    ),
    CS2HookSig(
        name="SetMeshGroupMask",
        module="client.dll",
        patterns=[
            "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8D 99 ? ? ? ? 48 8B 71",
        ],
        resolve="direct",
        required=False,
        description="CSceneObject::SetMeshGroupMask — mesh visibility toggle.",
    ),
    CS2HookSig(
        name="CreateMaterial",
        module="materialsystem2.dll",
        patterns=[
            "48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 56 48 81 EC ? ? ? ? 48 8B 05",
        ],
        resolve="direct",
        required=False,
        description="CMaterialSystem2::CreateMaterial — custom material creation for chams.",
    ),
]

# ---------------------------------------------------------------------------
# Particles / Effects / World Modulation
# ---------------------------------------------------------------------------
_FX_SIGS: List[CS2HookSig] = [
    CS2HookSig(
        name="DrawSmokeVertex",
        module="client.dll",
        patterns=[
            "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC ? 48 8B 9C 24 ? ? ? ? 4D 8B F8",
        ],
        resolve="direct",
        required=False,
        description="Smoke vertex draw — hook to remove smoke.",
    ),
    CS2HookSig(
        name="FlashOverlay",
        module="client.dll",
        patterns=[
            "85 D2 0F 88 ? ? ? ? 48 89 4C 24",
        ],
        resolve="direct",
        required=False,
        description="Flashbang overlay draw — hook to reduce flash.",
    ),
    CS2HookSig(
        name="DrawScopeOverlay",
        module="client.dll",
        patterns=[
            "48 8B C4 53 57 48 83 EC ? 48 8B FA",
        ],
        resolve="direct",
        required=False,
        description="Scope overlay draw — hook for no-scope overlay.",
    ),
    CS2HookSig(
        name="UpdatePostProcessing",
        module="client.dll",
        patterns=[
            "48 89 5C 24 08 57 48 83 EC 60 80",
        ],
        resolve="direct",
        required=False,
        description="Post-processing update — world brightness / night mode.",
    ),
]

# ---------------------------------------------------------------------------
# GC / Network
# ---------------------------------------------------------------------------
_NETWORK_SIGS: List[CS2HookSig] = [
    CS2HookSig(
        name="SendMessageGC",
        module="client.dll",
        patterns=[
            "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B F2 48 8B F9 48 8B 0D",
        ],
        resolve="direct",
        required=False,
        description="ISteamGameCoordinator::SendMessage — GC message hook.",
    ),
    CS2HookSig(
        name="SetPlayerReady",
        module="client.dll",
        patterns=[
            "40 53 48 83 EC 20 48 8B DA 48 8D 15 ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? 85 C0 75 14 BA",
        ],
        resolve="direct",
        required=False,
        description="Auto-accept matchmaking ready signal.",
    ),
]

# ---------------------------------------------------------------------------
# Animation / Scene System
# ---------------------------------------------------------------------------
_ANIM_SIGS: List[CS2HookSig] = [
    CS2HookSig(
        name="ShouldUpdateSequences",
        module="animationsystem.dll",
        patterns=[
            "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 49 8B 40 48",
        ],
        resolve="direct",
        required=False,
        description="Animation sequence update gate — desync / anti-aim related.",
    ),
]

# ---------------------------------------------------------------------------
# Aggregate table
# ---------------------------------------------------------------------------

ALL_HOOK_SIGS: List[CS2HookSig] = (
    _RENDERING_SIGS
    + _INPUT_SIGS
    + _ENTITY_SIGS
    + _TRACE_SIGS
    + _WEAPON_SIGS
    + _FX_SIGS
    + _NETWORK_SIGS
    + _ANIM_SIGS
)
