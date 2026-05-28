"""
CS2 engine prediction signatures — pattern table for functions needed
by the prediction system (EdgeBug, etc.).

Each entry supports multiple fallback patterns (tried in order). This mirrors
the scan_first() approach used by IsaiahHook's prediction.cpp — when one
pattern breaks after a CS2 update, fallbacks can still match older/newer
instruction layouts.

Function signatures are resolved via RIP-relative displacement.
Struct offsets for CCSGOInput / CUserCmd / CBaseUserCmdPB are NOT in the
Source 2 schema system, so we provide known offsets as hardcoded fallbacks.

When a pattern breaks after a CS2 update, update the `patterns` list
for the affected entry here and re-run — no other code changes required.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class CS2PredictionSig:
    """One scannable prediction function or pointer.

    `patterns` is a list of fallback IDA-style patterns tried in order.
    `resolve` controls how the match address is turned into the final address:
        "call"      — E8 rel32 call: resolve_rip(match, 1, 5)
        "rip"       — RIP-relative load: resolve_rip(match, disp_offset, instruction_size)
        "direct"    — pattern IS the function address (no resolution)
    """
    name: str
    module: str
    patterns: List[str]
    resolve: str = "call"                # "call" | "rip" | "direct"
    disp_offset: int = 1                  # only used when resolve="rip"
    instruction_size: int = 5             # only used when resolve="rip"
    extra_offset: int = 0
    description: str = ""


ALL_PREDICTION_SIGS: List[CS2PredictionSig] = [
    # ------------------------------------------------------------------
    # fnGetUserCmd — internal function to fetch CUserCmd at a sequence.
    # Resolved via E8 call.
    # NOTE: Patterns frequently break after CS2 updates. If this fails,
    # use fnCreateMove (direct hook) or fnValidateInput as alternatives.
    # ------------------------------------------------------------------
    CS2PredictionSig(
        name="fnGetUserCmd",
        module="client.dll",
        patterns=[
            "E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 45 33 E4 48 89 44 24",
            "E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 45 33 ?? 48 89 44 24",
            "E8 ?? ?? ?? ?? 48 8B D0 48 8B CE",
            "E8 ?? ?? ?? ?? 44 8B E0 48 8B CF",
        ],
        resolve="call",
        description="GetUserCmd — retrieves CUserCmd at a given sequence number.",
    ),

    # ------------------------------------------------------------------
    # fnGetCommandIndex — gets the index of the currently processing command.
    # Resolved via E8 call.
    # ------------------------------------------------------------------
    CS2PredictionSig(
        name="fnGetCommandIndex",
        module="client.dll",
        patterns=[
            "E8 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 8D 51",
        ],
        resolve="call",
        description="GetCommandIndex — returns the current command index being processed.",
    ),

    # ------------------------------------------------------------------
    # fnGetUserCmdEntry — the E8 call immediately after the command_base
    # load site. Separate sig so we can resolve it independently.
    # ------------------------------------------------------------------
    CS2PredictionSig(
        name="fnGetUserCmdEntry",
        module="client.dll",
        patterns=[
            "E8 ?? ?? ?? ?? 48 8B CF 4C 8B E8 44 8B B8",
            "E8 ?? ?? ?? ?? 48 8B CF 4C 8B E8",
        ],
        resolve="call",
        description="GetUserCmdEntry — fetches user command entry from command base.",
    ),

    # ------------------------------------------------------------------
    # fnCommandBase — global pointer to command storage.
    # 48 8B 0D (mov rcx, [rip+disp32]) resolved via RIP-relative.
    # ------------------------------------------------------------------
    CS2PredictionSig(
        name="fnCommandBase",
        module="client.dll",
        patterns=[
            "48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B CF 4C 8B E8",
            "48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B CF 4C 8B",
            "48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B CF",
        ],
        resolve="rip",
        disp_offset=3,
        instruction_size=7,
        description="CommandBase — global pointer to command array base.",
    ),

    # ------------------------------------------------------------------
    # fnClientSidePrediction — main entry point to force simulated tick.
    # Direct function prologue match (no RIP resolution).
    # ------------------------------------------------------------------
    CS2PredictionSig(
        name="fnClientSidePrediction",
        module="client.dll",
        patterns=[
            "40 55 56 41 57 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 48 8B 01",
            "40 55 56 41 57 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ??",
            "40 55 41 56 48 83 EC ?? 80 B9 ?? ?? ?? ?? ??",
        ],
        resolve="direct",
        description="ClientSidePrediction — function prologue for main tick-simulation entry.",
    ),

    # ------------------------------------------------------------------
    # fnCreateMove — classic client-side tick hook point.
    # Direct function prologue match. Often more stable than
    # fnClientSidePrediction for CUserCmd mutation.
    # ------------------------------------------------------------------
    CS2PredictionSig(
        name="fnCreateMove",
        module="client.dll",
        patterns=[
            "48 8B C4 4C 89 40 ? 48 89 48 ? 55 53 41 54",
        ],
        resolve="direct",
        description="CreateMove — classic client-side tick hook for CUserCmd mutation.",
    ),

    # ------------------------------------------------------------------
    # fnValidateInput — input validation/processing entry.
    # Direct function prologue match.
    # ------------------------------------------------------------------
    CS2PredictionSig(
        name="fnValidateInput",
        module="client.dll",
        patterns=[
            "40 53 48 83 EC ? 48 8B D9 E8 ? ? ? ? 33 C0 C6 83 ? ? ? ? 00",
        ],
        resolve="direct",
        description="ValidateInput — input validation/processing function.",
    ),

    # ------------------------------------------------------------------
    # fnForceButtonsDown — force button state processing.
    # Direct function prologue match.
    # ------------------------------------------------------------------
    CS2PredictionSig(
        name="fnForceButtonsDown",
        module="client.dll",
        patterns=[
            "40 53 57 41 56 48 81 EC ? ? ? ? 48 83 79 ? 00",
        ],
        resolve="direct",
        description="ForceButtonsDown — forces button-down state processing.",
    ),

    # ------------------------------------------------------------------
    # fnProcessMovement — engine movement simulation function.
    # Resolved via E8 call.
    # ------------------------------------------------------------------
    CS2PredictionSig(
        name="fnProcessMovement",
        module="client.dll",
        patterns=[
            "E8 ?? ?? ?? ?? 48 8B 06 48 8B CE FF 90 ?? ?? ?? ?? 44 38 63 45",
            "E8 ?? ?? ?? ?? 48 8B 06 48 8B CE FF 90 ?? ?? ?? ??",
            "E8 ?? ?? ?? ?? 48 8B 06 48 8B CE FF 90",
        ],
        resolve="call",
        description="ProcessMovement — engine movement simulation function.",
    ),

    # ------------------------------------------------------------------
    # fnRunPrediction — engine2.dll prediction runner (optional).
    # Resolved via E8 call.
    # ------------------------------------------------------------------
    CS2PredictionSig(
        name="fnRunPrediction",
        module="engine2.dll",
        patterns=[
            "E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 8D 54 24 ?? 48 8B 01 FF 50 ??",
            "E8 ?? ?? ?? ?? 49 8B D6 48 8B CE E8 ?? ?? ?? ?? 48 8B 06",
        ],
        resolve="call",
        description="RunPrediction — engine2 prediction runner (optional).",
    ),

    # ------------------------------------------------------------------
    # fnTraceShape — engine trace/raycast function.
    # Direct function prologue match. Needed for real Trace::Raycast.
    # ------------------------------------------------------------------
    CS2PredictionSig(
        name="fnTraceShape",
        module="client.dll",
        patterns=[
            "48 89 5C 24 ? 48 89 4C 24 ? 55 57",
        ],
        resolve="direct",
        description="TraceShape — engine trace/raycast entry (replaces stubbed Trace::Raycast).",
    ),

    # ------------------------------------------------------------------
    # fnCalculateShootPosition — shoot position calculator (optional).
    # Direct function prologue match.
    # ------------------------------------------------------------------
    CS2PredictionSig(
        name="fnCalculateShootPosition",
        module="client.dll",
        patterns=[
            "48 89 5C 24 ?? 48 89 6C 24 ?? 56 57 41 56 48 81 EC ?? ?? ?? ?? 44 8B 92 ?? ?? ?? ??",
            "48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 56 48 83 EC ?",
        ],
        resolve="direct",
        description="CalculateShootPosition — computes eye position for shots.",
    ),
]


# ---------------------------------------------------------------------------
# Struct field offsets — NOT from schema (internal protobuf structures)
#
# These are known offsets that must be hardcoded. When they change after a
# CS2 update, update the `offset` value here and re-run.
#
# Each tuple: (output_key, struct_name, field_name, offset, description)
# ---------------------------------------------------------------------------

@dataclass
class CS2PredictionStructField:
    """Known struct-field offset (hardcoded, not from schema)."""
    output_key: str
    struct_name: str
    field_name: str
    offset: int
    description: str = ""


PREDICTION_STRUCT_FIELDS: List[CS2PredictionStructField] = [
    # CCSGOInput
    CS2PredictionStructField(
        output_key="CCSGOInput_m_commands",
        struct_name="CCSGOInput",
        field_name="m_commands",
        offset=0x250,
        description="Offset to CUserCmd ring buffer array inside CCSGOInput.",
    ),
    CS2PredictionStructField(
        output_key="CCSGOInput_m_nSequenceNumber",
        struct_name="CCSGOInput",
        field_name="m_nSequenceNumber",
        offset=0x2A0,
        description="Offset to current sequence number inside CCSGOInput.",
    ),

    # CUserCmd / CCSGOUserCmd
    CS2PredictionStructField(
        output_key="CUserCmd_m_csgoUserCmd",
        struct_name="CUserCmd",
        field_name="m_csgoUserCmd",
        offset=0x68,
        description="Offset to nested protobuf CCSGOUserCmd inside CUserCmd.",
    ),
    CS2PredictionStructField(
        output_key="CUserCmd_m_buttons",
        struct_name="CUserCmd",
        field_name="m_buttons",
        offset=0x20,
        description="Offset to jump/duck button bitmasks inside CUserCmd.",
    ),
    CS2PredictionStructField(
        output_key="CUserCmd_m_subtick_moves",
        struct_name="CUserCmd",
        field_name="m_subtick_moves",
        offset=0x58,
        description="Offset to subtick move actions inside CUserCmd (CUtlVector).",
    ),

    # CBaseUserCmdPB (protobuf struct)
    CS2PredictionStructField(
        output_key="CBaseUserCmdPB_forwardmove",
        struct_name="CBaseUserCmdPB",
        field_name="forwardmove",
        offset=0x50,
        description="Forward movement value inside the base protobuf command.",
    ),
    CS2PredictionStructField(
        output_key="CBaseUserCmdPB_sidemove",
        struct_name="CBaseUserCmdPB",
        field_name="sidemove",
        offset=0x54,
        description="Side movement value inside the base protobuf command.",
    ),
    CS2PredictionStructField(
        output_key="CBaseUserCmdPB_viewangles",
        struct_name="CBaseUserCmdPB",
        field_name="viewangles",
        offset=0x40,
        description="View angles (pitch/yaw/roll) inside the base protobuf command.",
    ),

    # CSubtickMoveStep — individual subtick action (element of CUtlVector at CUserCmd+0x58)
    # Offsets are community-sourced; verify in-game if movement feels off.
    CS2PredictionStructField(
        output_key="CSubtickMoveStep_m_flWhen",
        struct_name="CSubtickMoveStep",
        field_name="m_flWhen",
        offset=0x00,
        description="Subtick timing fraction (0.0-1.0) for this move step.",
    ),
    CS2PredictionStructField(
        output_key="CSubtickMoveStep_m_nButton",
        struct_name="CSubtickMoveStep",
        field_name="m_nButton",
        offset=0x04,
        description="Button mask (e.g. IN_JUMP) for this subtick step.",
    ),
    CS2PredictionStructField(
        output_key="CSubtickMoveStep_m_bPressed",
        struct_name="CSubtickMoveStep",
        field_name="m_bPressed",
        offset=0x08,
        description="True = button pressed, False = button released.",
    ),
]
