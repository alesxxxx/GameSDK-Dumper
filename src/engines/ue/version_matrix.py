
from typing import Dict, Optional, Tuple

VERSION_MATRIX: Dict[str, dict] = {
    "4.19": {
        "ffield_layout": "pre425",
        "fname_layout": "legacy",
        "ustruct_layout": "pre423",
        "fuobjectitem_size": 16,
        "confirmed_games": ["StateOfDecay2-Win64-Shipping"],
        "confirmed": False,
        "notes": "Pre-FNamePool, pre-FField, pre-FStructBaseChain. GNames is TStaticIndirectArrayThreadSafeRead.",
    },
    "4.20": {
        "ffield_layout": "pre425",
        "fname_layout": "legacy",
        "ustruct_layout": "pre423",
        "fuobjectitem_size": 16,
        "confirmed_games": [],
        "confirmed": False,
        "notes": "Inferred from 4.19 layout. Same TNameEntryArray + UProperty path.",
    },
    "4.21": {
        "ffield_layout": "pre425",
        "fname_layout": "legacy",
        "ustruct_layout": "pre423",
        "fuobjectitem_size": 16,
        "confirmed_games": [],
        "confirmed": False,
        "notes": "Inferred. Last version before FStructBaseChain was added in 4.22/4.23.",
    },
    "4.22": {
        "ffield_layout": "pre425",
        "fname_layout": "legacy",
        "ustruct_layout": "pre423",
        "fuobjectitem_size": 16,
        "confirmed_games": [],
        "confirmed": False,
        "notes": "Still pre-FNamePool, pre-FField. FStructBaseChain may be present in late 4.22 builds.",
    },
    "4.23": {
        "ffield_layout": "pre425",
        "fname_layout": "fnamepool",
        "ustruct_layout": "standard",
        "fuobjectitem_size": 24,
        "confirmed_games": [],
        "confirmed": False,
        "notes": "FNamePool introduced. FStructBaseChain added. Still UProperty (pre-FField).",
    },
    "4.24": {
        "ffield_layout": "pre425",
        "fname_layout": "fnamepool",
        "ustruct_layout": "standard",
        "fuobjectitem_size": 24,
        "confirmed_games": [],
        "confirmed": False,
        "notes": "Same as 4.23. Last version before FField system was introduced in 4.25.",
    },
    "4.25": {
        "ffield_layout": "ue427",
        "fname_layout": "fnamepool",
        "ustruct_layout": "standard",
        "fuobjectitem_size": 24,
        "confirmed_games": [],
        "confirmed": False,
        "notes": "FField system introduced. ChildProperties linked list replaces UProperty.",
    },
    "4.26": {
        "ffield_layout": "ue427",
        "fname_layout": "fnamepool",
        "ustruct_layout": "standard",
        "fuobjectitem_size": 24,
        "confirmed_games": [],
        "confirmed": False,
        "notes": "Inferred from 4.25/4.27 — same FField layout.",
    },
    "4.27": {
        "ffield_layout": "ue427",
        "fname_layout": "fnamepool",
        "ustruct_layout": "standard",
        "fuobjectitem_size": 24,
        "confirmed_games": ["Medieval_Dynasty-Win64-Shipping"],
        "confirmed": True,
        "notes": "Live-confirmed on Medieval Dynasty. Canonical UE4 reference build.",
    },
    "5.0": {
        "ffield_layout": "ue427",
        "fname_layout": "fnamepool",
        "ustruct_layout": "standard",
        "fuobjectitem_size": 24,
        "confirmed_games": [],
        "confirmed": False,
        "notes": "UE5.0 uses same layout as UE4.27. FStructBaseChain: SuperStruct=0x40.",
    },
    "5.1": {
        "ffield_layout": "ue427",
        "fname_layout": "fnamepool",
        "ustruct_layout": "standard",
        "fuobjectitem_size": 24,
        "confirmed_games": ["Palworld-Win64-Shipping"],
        "confirmed": True,
        "notes": "Confirmed on Palworld. UE4SS issue #966 confirms SuperStruct=0x40.",
    },
    "5.2": {
        "ffield_layout": "ue52plus",
        "fname_layout": "fnamepool",
        "ustruct_layout": "standard",
        "fuobjectitem_size": 24,
        "confirmed_games": ["ManorLords-Win64-Shipping"],
        "confirmed": True,
        "notes": "FFieldVariant Owner shrank from 16 to 8 bytes. All FField/FProperty fields shift -8. Confirmed via ue5_offset_probe.py on Manor Lords.",
    },
    "5.3": {
        "ffield_layout": "ue52plus",
        "fname_layout": "fnamepool",
        "ustruct_layout": "standard",
        "fuobjectitem_size": 24,
        "confirmed_games": [],
        "confirmed": False,
        "notes": "UE4SS issue #495 PDB data (Everspace 2) confirms FField::Next=0x18, FProperty::Offset=0x44.",
    },
    "5.4": {
        "ffield_layout": "ue52plus",
        "fname_layout": "fnamepool",
        "ustruct_layout": "standard",
        "fuobjectitem_size": 24,
        "confirmed_games": [],
        "confirmed": False,
        "notes": "No known layout changes vs 5.2+. UE 5.4 release notes mention no FField restructuring.",
    },
    "5.5": {
        "ffield_layout": "ue52plus",
        "fname_layout": "fnamepool",
        "ustruct_layout": "standard",
        "fuobjectitem_size": 24,
        "confirmed_games": ["ManorLords-Win64-Shipping", "ArkAscended"],
        "confirmed": True,
        "notes": "Manor Lords + Ark Survival Ascended (UE5.5). Same shifted FField layout as 5.2+. "
                 "ACharacter::Mesh=0x540, CharacterMovement=0x548, CapsuleComponent=0x550 confirmed. "
                 "Note: Wildcard injects ~0x2E8 bytes into UWorld and ~0x208 into APlayerController "
                 "so chain offsets differ from stock UE5 — always use dump-resolved chains.hpp values.",
    },
}

def _parse_version(version_str: str) -> Optional[Tuple[int, int]]:
    if not version_str:
        return None
    try:
        parts = version_str.split(".")
        return (int(parts[0]), int(parts[1])) if len(parts) >= 2 else None
    except (ValueError, IndexError):
        return None

def get_version_config(ue_version: str) -> dict:
    if ue_version in VERSION_MATRIX:
        return dict(VERSION_MATRIX[ue_version])

    parsed = _parse_version(ue_version)
    if parsed:
        key = f"{parsed[0]}.{parsed[1]}"
        if key in VERSION_MATRIX:
            return dict(VERSION_MATRIX[key])

        major = parsed[0]
        minor = parsed[1]
        candidates = []
        for k, v in VERSION_MATRIX.items():
            kp = _parse_version(k)
            if kp and kp[0] == major:
                candidates.append((kp[1], k))
        if candidates:
            candidates.sort(key=lambda t: (abs(t[0] - minor), t[0]))
            return dict(VERSION_MATRIX[candidates[0][1]])

    return dict(VERSION_MATRIX["4.27"])

def is_pre_425(ue_version: str) -> bool:
    config = get_version_config(ue_version)
    return config["ffield_layout"] == "pre425"

def is_pre_423(ue_version: str) -> bool:
    config = get_version_config(ue_version)
    return config["ustruct_layout"] == "pre423"

def is_legacy_names(ue_version: str) -> bool:
    config = get_version_config(ue_version)
    return config["fname_layout"] == "legacy"

def get_ffield_layout(ue_version: str) -> str:
    config = get_version_config(ue_version)
    return config["ffield_layout"]
