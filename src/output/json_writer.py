
import json
import os
import time
from datetime import datetime, timezone
from typing import Dict, Optional

from src.core.pe_parser import get_pe_sections
from src.core.models import BoolMeta, EnumInfo, MemberInfo, SDKDump, StructInfo, StructLayoutMeta, TypeDesc
from src.output.utils import lookup_member_offset, resolve_standard_chain

def write_dump_table(
    path: str,
    *,
    output_dir: str,
    dump: SDKDump,
    engine: str = "ue",
    process_name: str = "",
    ue_version: str = "",
    unity_version: str = "",
    metadata_version: str = "",
    pe_timestamp: int = 0,
    gnames_off: int = 0,
    gobjects_off: int = 0,
    gworld_off: int = 0,
    chain_offsets: Optional[Dict[str, Optional[str]]] = None,
):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out_abs = os.path.abspath(output_dir)

    chain = chain_offsets or {}
    stats = {
        "structs_classes": int(len(dump.structs)),
        "enums": int(len(dump.enums)),
        "members": int(sum(len(s.members) for s in dump.structs)),
    }

    files = {
        "offsets_info": "OffsetsInfo.json",
        "classes_info": "ClassesInfo.json",
        "structs_info": "StructsInfo.json",
        "enums_info": "EnumsInfo.json",
        "fields_csv": "Fields.csv",
        "methods_json": "Methods.json",
        "hierarchy_json": "Hierarchy.json",
        "globals_json": "Globals.json",
        "readme": "README.txt",
    }
    if engine.lower() == "ue":
        files["classes_info_v2"] = "ClassesInfoV2.json"
        files["structs_info_v2"] = "StructsInfoV2.json"

    globals_block = {}
    if engine.lower() == "ue":
        globals_block = {
            "OFFSET_GNAMES": f"0x{gnames_off:X}",
            "OFFSET_GOBJECTS": f"0x{gobjects_off:X}",
            "OFFSET_GWORLD": f"0x{gworld_off:X}",
        }
    elif engine.lower() == "il2cpp":
        globals_block = {
            "GameAssembly_base_hint": f"0x{gnames_off:X}",
            "Il2CppMetadataRegistration_hint": f"0x{gobjects_off:X}",
            "Il2CppCodeRegistration_hint": f"0x{gworld_off:X}",
        }
    elif engine.lower() == "mono":
        globals_block = {"mono_base_hint": f"0x{gnames_off:X}"}

    table_entries = []
    if engine.lower() == "ue" and gworld_off:
        table_entries.append(
            {
                "id": "uworld",
                "label": "UWorld",
                "kind": "pointer",
                "expression": f"[module_base + 0x{gworld_off:X}]",
                "note": "Read pointer once.",
            }
        )
        chain_map = [
            ("UWorld_OwningGameInstance", "game_instance", "UGameInstance", "uworld"),
            ("UGameInstance_LocalPlayers", "local_players", "TArray<ULocalPlayer*>", "game_instance"),
            ("UPlayer_PlayerController", "player_controller", "APlayerController", "local_player_0"),
            ("APlayerController_AcknowledgedPawn", "acknowledged_pawn", "APawn", "player_controller"),
            ("AController_PlayerState", "player_state", "APlayerState", "player_controller"),
            ("ACharacter_CharacterMovement", "character_movement", "UCharacterMovementComponent", "acknowledged_pawn"),
        ]
        for key, entry_id, label, parent in chain_map:
            off = chain.get(key)
            if not off:
                continue
            table_entries.append(
                {
                    "id": entry_id,
                    "label": label,
                    "kind": "pointer",
                    "from": parent,
                    "offset": off,
                    "deref": True,
                }
            )

    payload = {
        "schema_version": 1,
        "kind": "dump_table",
        "generated_at": now_iso,
        "target": {
            "process": process_name,
            "engine": engine,
            "ue_version": ue_version,
            "unity_version": unity_version,
            "metadata_version": metadata_version,
            "pe_timestamp": int(pe_timestamp) if pe_timestamp else 0,
        },
        "stats": stats,
        "globals": globals_block,
        "pointer_chain": chain,
        "table_entries": table_entries,
        "paths": {
            "output_root": out_abs,
            "files": files,
        },
        "notes": [
            "This profile is generated after a successful dump.",
            "Use OffsetsInfo.json as the source of truth for current RVAs.",
            "Regenerate after game updates to keep pointers and metadata fresh.",
        ],
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

def write_offsets_json(
    path: str,
    gnames_off: int,
    gobjects_off: int,
    gworld_off: int,
    *,
    process_name: str = "",
    ue_version: str = "",
    unity_version: str = "",
    metadata_version: str = "",
    pe_timestamp: int = 0,
    classes_data: list = None,
    structs_data: list = None,
    engine: str = "ue",
    steam_appid: Optional[int] = None,
):
    _RESERVED_KEYS = {"credit", "data", "updated_at", "version",
                  "game", "globals", "pointer_chain", "usage", "engine"}
    preserved: Dict[str, object] = {}
    existing_game: Dict[str, object] = {}
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                existing = json.load(f)
            if isinstance(existing, dict):
                preserved = {k: v for k, v in existing.items() if k not in _RESERVED_KEYS}
                if isinstance(existing.get("game"), dict):
                    existing_game = dict(existing["game"])
        except (OSError, json.JSONDecodeError, TypeError):
            pass

    os.makedirs(os.path.dirname(path), exist_ok=True)

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    data = {
        "credit": {
            "dumper": "GameSDK-Kit",
            "link": "https://github.com/alesxxxx/game-sdk-kit",
        },
    }

    has_steam_appid = steam_appid is not None
    if not has_steam_appid and existing_game.get("steam_appid") is not None:
        steam_appid = existing_game.get("steam_appid")
        has_steam_appid = True

    if process_name or ue_version or unity_version or metadata_version or pe_timestamp or has_steam_appid:
        game_block = {}
        preserved_game_extras = {
            key: value
            for key, value in existing_game.items()
            if key
            not in {
                "process",
                "ue_version",
                "unity_version",
                "metadata_version",
                "pe_timestamp",
                "pe_timestamp_human",
                "dump_timestamp",
                "stale_detection",
                "steam_appid",
            }
        }
        game_block.update(preserved_game_extras)
        if process_name:
            game_block["process"] = process_name
        if ue_version:
            game_block["ue_version"] = ue_version
        if unity_version:
            game_block["unity_version"] = unity_version
        if metadata_version:
            game_block["metadata_version"] = metadata_version
        if has_steam_appid:
            try:
                appid_val = int(str(steam_appid).strip())
                if appid_val > 0:
                    game_block["steam_appid"] = appid_val
            except (TypeError, ValueError):
                pass
        if pe_timestamp:
            game_block["pe_timestamp"] = pe_timestamp
            try:
                game_block["pe_timestamp_human"] = datetime.fromtimestamp(
                    pe_timestamp, tz=timezone.utc
                ).strftime("%Y-%m-%d")
            except (OSError, ValueError, OverflowError):
                pass
        game_block["dump_timestamp"] = now_iso
        game_block["stale_detection"] = {
            "check_field":        "pe_timestamp",
            "redump_recommended": False,
            "note": (
                "Compare the running game EXE timestamp to pe_timestamp above. "
                "If the EXE is newer, GWorld RVA has likely changed — redump."
            ),
        }
        data["game"] = game_block

    if gnames_off or gobjects_off or gworld_off:
        data["globals"] = {
            "OFFSET_GNAMES":   {"rva_dec": gnames_off,   "rva_hex": f"0x{gnames_off:X}"},
            "OFFSET_GOBJECTS": {"rva_dec": gobjects_off,  "rva_hex": f"0x{gobjects_off:X}"},
            "OFFSET_GWORLD":   {"rva_dec": gworld_off,    "rva_hex": f"0x{gworld_off:X}"},
        }
    else:
        data["globals"] = {}

    classes_data = classes_data or []
    structs_data = structs_data or []
    if (classes_data or structs_data) and (gworld_off or gobjects_off):
        chain = resolve_standard_chain(classes_data, structs_data)
        resolved = {k: v for k, v in chain.items() if v is not None}
        if resolved:
            resolved["note"] = "All offsets confirmed from ClassesInfo dump for this game/version."
            data["pointer_chain"] = resolved

    if gworld_off:
        data["usage"] = {
            "cpp": "uintptr_t uworld = rpm<uintptr_t>(base + OFFSET_GWORLD);",
            "note": "OFFSET_GWORLD is an RVA. Add to module base address at runtime. Re-dump if game updates.",
        }
    else:
        data["usage"] = {}

    if gnames_off or gobjects_off or gworld_off:
        data["data"] = [
            ["OFFSET_GNAMES", gnames_off],
            ["OFFSET_GOBJECTS", gobjects_off],
            ["OFFSET_GWORLD", gworld_off],
        ]
    else:
        data["data"] = []

    data["engine"] = engine
    data["updated_at"] = str(int(time.time() * 1000))
    data["version"] = 10201

    data.update(preserved)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def write_readme(
    path: str,
    gnames_off: int,
    gobjects_off: int,
    gworld_off: int,
    *,
    process_name: str = "",
    ue_version: str = "",
    pe_timestamp: int = 0,
    chain_offsets: dict = None,
    classes_data: list = None,
    structs_data: list = None,
):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    pe_human = ""
    if pe_timestamp:
        try:
            pe_human = datetime.fromtimestamp(
                pe_timestamp, tz=timezone.utc
            ).strftime("%Y-%m-%d")
        except (OSError, ValueError, OverflowError):
            pe_human = "unknown"

    chain = chain_offsets or {}

    def _c(key):
        return chain.get(key) or "??"

    lines = []
    lines.append(f"Dump — {process_name or 'Unknown Game'}")
    lines.append(f"UE Version : {ue_version or 'unknown'}")
    lines.append(f"Dumped at   : {now_str}")
    lines.append(f"Module base : (changes per run — use RVAs below)")
    lines.append("")
    lines.append("GLOBAL POINTERS (RVA from module base)")
    lines.append(f"  GNames   : 0x{gnames_off:X}")
    lines.append(f"  GObjects : 0x{gobjects_off:X}")
    lines.append(f"  GWorld   : 0x{gworld_off:X}   <-- dereference once to get UWorld*")
    lines.append("")
    lines.append("POINTER CHAIN (verified from ClassesInfo)")
    lines.append(f"  base + GWorld              -> read ptr -> UWorld")
    lines.append(f"  UWorld   + {_c('UWorld_OwningGameInstance'):10s}    -> read ptr -> UGameInstance")
    lines.append(f"  UGameInstance + {_c('UGameInstance_LocalPlayers'):10s}-> read ptr -> LocalPlayers[0] (TArray.Data first element)")
    lines.append(f"  LocalPlayers[0] + {_c('UPlayer_PlayerController'):10s}-> read ptr -> APlayerController")
    lines.append(f"  APlayerController + {_c('APlayerController_AcknowledgedPawn')}-> read ptr -> APawn (AcknowledgedPawn — your actively controlled character)")
    if chain.get("ACharacter_CharacterMovement"):
        lines.append(f"  APawn + {_c('ACharacter_CharacterMovement'):10s}        -> read ptr -> UCharacterMovementComponent")
    
    def _find_health_paths() -> list:
        results = []
        _FIELD_KEYWORDS = {"hp", "health", "sp", "stamina", "muteki", "shield", "maxhp", "dying", "immortal"}
        _COMPONENT_KEYWORDS = {"CharacterParameterComponent", "HealthComponent", "StatusComponent",
                               "AttributeSet", "VitalityComponent"}
        
        added_palworld_note = False
        
        for dataset in (classes_data or [], structs_data or []):
            for entry in dataset:
                if not entry:
                    continue
                for full_name, details in entry.items():
                    uq = full_name.split(".")[-1] if "." in full_name else full_name
                    is_component = any(kw in uq for kw in _COMPONENT_KEYWORDS)
                    for item in details:
                        if not isinstance(item, dict):
                            continue
                        for field_name, val in item.items():
                            if field_name.startswith("__"):
                                continue
                            if isinstance(val, list) and len(val) >= 2:
                                offset = val[1]
                                fn_lower = field_name.lower()
                                if is_component and any(kw in fn_lower for kw in _FIELD_KEYWORDS):
                                    type_str = val[0][0] if isinstance(val[0], list) and len(val[0]) > 0 else "unknown"
                                    comp_short = "CPC" if "CharacterParameterComponent" in uq else "IndvP" if "IndividualCharacterParameter" in uq else uq
                                    
                                    if comp_short == "IndvP" and not added_palworld_note:
                                        results.append("  [!] Palworld HP encoding: raw int64, divide by 1000 for display value")
                                        added_palworld_note = True
                                        
                                    results.append(f"  {comp_short:<20s} + 0x{offset:<5X} -> {field_name} ({type_str})")
        return results

    health_paths = _find_health_paths()
    if health_paths:
        lines.append("")
        lines.append("HEALTH PATH (GAME SPECIFIC from ClassesInfo)")
        lines.extend(health_paths[:15])

    lines.append("")

    lines.append("STALE DUMP DETECTION")
    if pe_timestamp and pe_human:
        lines.append(f"  PE timestamp in this dump : {pe_timestamp}  ({pe_human})")
    else:
        lines.append(f"  PE timestamp in this dump : not available")
    if process_name:
        lines.append(f"  To check if game updated  : (Get-Item \"{process_name}\").LastWriteTime")
    else:
        lines.append(f"  To check if game updated  : compare EXE LastWriteTime with dump date above")
    lines.append(f"  If the EXE date is newer than the dump date, re-run the toolkit before using these offsets.")
    lines.append(f"  GWorld RVA changes on every update. Chain offsets ({_c('UWorld_OwningGameInstance')}, {_c('UGameInstance_LocalPlayers')}, {_c('UPlayer_PlayerController')}, {_c('APlayerController_AcknowledgedPawn')}) do not.")
    lines.append("")

    lines.append("IF THE GAME UPDATES")
    lines.append("  GWorld RVA will change. Re-run the dumper to get the new value.")
    lines.append("  All other chain offsets are stable across updates")
    lines.append("  because they come from the UE engine source, not game code.")
    lines.append("")

    lines.append("USING THE SDK")
    lines.append("  1. Include ../SDK/SDK.hpp in your trainer")
    lines.append("  2. Include ../SDK/chains.hpp for ready-to-use pointer chain functions")
    lines.append("  3. Read ../SDK/Offsets.hpp for the three global RVAs")
    lines.append("  4. chains.hpp offsets are resolved from THIS dump — they are correct for this game version")
    lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def write_unity_readme(
    path: str,
    engine: str,
    process_name: str = "",
    unity_version: str = "",
    metadata_version: str = "",
    pe_timestamp: int = 0,
):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    pe_human = ""
    if pe_timestamp:
        try:
            pe_human = datetime.fromtimestamp(
                pe_timestamp, tz=timezone.utc
            ).strftime("%Y-%m-%d")
        except (OSError, ValueError, OverflowError):
            pe_human = "unknown"

    lines = []
    lines.append(f"Dump — {process_name or 'Unknown Game'}")
    lines.append(f"Engine     : {'Unity IL2CPP' if engine == 'il2cpp' else 'Unity Mono'}")
    if unity_version:
        lines.append(f"Unity      : {unity_version}")
    if metadata_version:
        lines.append(f"Metadata   : {metadata_version}")
    lines.append(f"Dumped at  : {now_str}")
    lines.append("")
    lines.append("MODULE BASE")
    if engine == "il2cpp":
        lines.append("  Main Module: GameAssembly.dll")
    else:
        lines.append("  Main Module: mono-2.0-bdwgc.dll (or similar)")
    lines.append("")

    lines.append("STALE DUMP DETECTION")
    if pe_timestamp and pe_human:
        lines.append(f"  PE timestamp in this dump : {pe_timestamp}  ({pe_human})")
    else:
        lines.append(f"  PE timestamp in this dump : not available")
    if process_name:
        lines.append(f"  To check if game updated  : (Get-Item \"{process_name}\").LastWriteTime")
    else:
        lines.append(f"  To check if game updated  : compare EXE LastWriteTime with dump date above")
    lines.append("  If the game has updated, the static offsets in the SDK may be outdated. Re-run the dumper.")
    lines.append("")

    lines.append("USING THE SDK")
    lines.append("  1. Include ../SDK/SDK.hpp in your trainer")
    lines.append("  2. If using C++, SDK provides struct definitions suitable for memory reading")
    lines.append("  3. For finding instances, look for unity specific signature scanning or hooks")
    lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def write_classes_json(path: str, dump: SDKDump):
    classes = [s for s in dump.structs if s.is_class]
    _write_structs_file(path, classes)

def write_structs_json(path: str, dump: SDKDump):
    structs = [s for s in dump.structs if not s.is_class]
    _write_structs_file(path, structs)

def write_classes_json_v2(path: str, dump: SDKDump):
    classes = [s for s in dump.structs if s.is_class]
    _write_structs_file_v2(path, classes)

def write_structs_json_v2(path: str, dump: SDKDump):
    structs = [s for s in dump.structs if not s.is_class]
    _write_structs_file_v2(path, structs)

def _primitive_type_desc(display_name: str, size: int, align: int) -> TypeDesc:
    return TypeDesc(
        kind="primitive",
        display_name=display_name,
        signature_name=display_name,
        size=int(size or 0),
        align=int(align or 0),
    )

def _fallback_type_desc(property_class: str, size_hint: int = 0) -> Optional[TypeDesc]:
    property_class = str(property_class or "")
    size_hint = int(size_hint or 0)

    primitive_map = {
        "BoolProperty": ("bool", 1, 1),
        "ByteProperty": ("uint8_t", 1, 1),
        "Int8Property": ("int8_t", 1, 1),
        "Int16Property": ("int16_t", 2, 2),
        "IntProperty": ("int32_t", 4, 4),
        "Int64Property": ("int64_t", 8, 8),
        "UInt16Property": ("uint16_t", 2, 2),
        "UInt32Property": ("uint32_t", 4, 4),
        "UInt64Property": ("uint64_t", 8, 8),
        "FloatProperty": ("float", 4, 4),
        "DoubleProperty": ("double", 8, 8),
        "NameProperty": ("FName", 0x8, 0x4),
        "StrProperty": ("FString", 0x10, 0x8),
        "TextProperty": ("FText", 0x18, 0x8),
    }
    if property_class in primitive_map:
        display_name, size_value, align_value = primitive_map[property_class]
        return _primitive_type_desc(display_name, size_value, align_value)

    root_object = TypeDesc(
        kind="named_struct",
        display_name="Object",
        signature_name="Object",
        full_name="CoreUObject.Object",
        package="CoreUObject",
        size=0,
        align=8,
    )
    if property_class == "EnumProperty":
        integral = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}.get(size_hint or 1, "uint8_t")
        return _primitive_type_desc(integral, size_hint or 1, min(size_hint or 1, 8))
    if property_class in {"ObjectProperty", "AssetObjectProperty"}:
        return TypeDesc(kind="object", pointee=root_object, size=size_hint or 8, align=8)
    if property_class == "ObjectPtrProperty":
        return TypeDesc(kind="object_ptr", pointee=root_object, size=size_hint or 8, align=8)
    if property_class == "ClassProperty":
        return TypeDesc(kind="class", pointee=root_object, size=size_hint or 8, align=8)
    if property_class == "ClassPtrProperty":
        return TypeDesc(kind="class_ptr", pointee=root_object, size=size_hint or 8, align=8)
    if property_class in {"SoftClassProperty", "AssetClassProperty"}:
        return TypeDesc(kind="soft_class", pointee=root_object, size=size_hint or 0x28, align=8)
    if property_class == "SoftObjectProperty":
        return TypeDesc(kind="soft_object", pointee=root_object, size=size_hint or 0x28, align=8)
    if property_class == "WeakObjectProperty":
        return TypeDesc(kind="weak_object", pointee=root_object, size=size_hint or 8, align=8)
    if property_class == "LazyObjectProperty":
        return TypeDesc(kind="lazy_object", pointee=root_object, size=size_hint or 8, align=8)
    if property_class == "InterfaceProperty":
        interface_root = TypeDesc(
            kind="named_struct",
            display_name="Interface",
            signature_name="Interface",
            full_name="CoreUObject.Interface",
            package="CoreUObject",
            size=0,
            align=8,
        )
        return TypeDesc(kind="interface", pointee=interface_root, size=size_hint or 0x10, align=8)
    if property_class == "ArrayProperty":
        return TypeDesc(kind="array", inner=_primitive_type_desc("uint8_t", 1, 1), size=size_hint or 0x10, align=8)
    if property_class == "SetProperty":
        return TypeDesc(kind="set", inner=_primitive_type_desc("uint8_t", 1, 1), size=size_hint or 0x50, align=8)
    if property_class == "MapProperty":
        return TypeDesc(
            kind="map",
            key=_primitive_type_desc("uint8_t", 1, 1),
            value=_primitive_type_desc("uint8_t", 1, 1),
            size=size_hint or 0x50,
            align=8,
        )
    if property_class == "DelegateProperty":
        return TypeDesc(kind="delegate", display_name="FScriptDelegate", signature_name="FScriptDelegate", size=size_hint or 0x10, align=8)
    if property_class in {
        "MulticastDelegateProperty",
        "MulticastInlineDelegateProperty",
        "MulticastSparseDelegateProperty",
    }:
        return TypeDesc(
            kind="multicast_delegate",
            display_name="FMulticastScriptDelegate",
            signature_name="FMulticastScriptDelegate",
            size=size_hint or 0x10,
            align=8,
        )
    if property_class == "FieldPathProperty":
        return TypeDesc(kind="field_path", pointee=root_object, size=size_hint or 0x10, align=8)
    if property_class == "StructProperty":
        return TypeDesc(kind="opaque", display_name="uint8_t", signature_name="uint8_t", size=size_hint or 1, align=1)
    return None

def _type_desc_to_json(desc: Optional[TypeDesc]) -> Optional[dict]:
    if desc is None:
        return None
    payload = {
        "kind": desc.kind,
        "display_name": desc.display_name,
        "signature_name": desc.signature_name or desc.display_name,
        "full_name": (desc.full_name or "").replace("/Script/", ""),
        "package": (desc.package or "").replace("/Script/", ""),
        "size": int(desc.size or 0),
        "align": int(desc.align or 0),
        "is_const": bool(desc.is_const),
        "is_ref": bool(desc.is_ref),
    }
    if desc.metadata:
        payload["metadata"] = dict(desc.metadata)
    if desc.pointee is not None:
        payload["pointee"] = _type_desc_to_json(desc.pointee)
    if desc.inner is not None:
        payload["inner"] = _type_desc_to_json(desc.inner)
    if desc.key is not None:
        payload["key"] = _type_desc_to_json(desc.key)
    if desc.value is not None:
        payload["value"] = _type_desc_to_json(desc.value)
    if desc.enum_underlying is not None:
        payload["enum_underlying"] = _type_desc_to_json(desc.enum_underlying)
    return payload

def _bool_meta_to_json(meta: Optional[BoolMeta]) -> Optional[dict]:
    if meta is None:
        return None
    return {
        "is_native": bool(meta.is_native),
        "field_mask": int(meta.field_mask),
        "field_mask_hex": f"0x{int(meta.field_mask) & 0xFF:02X}",
        "byte_offset": int(meta.byte_offset),
        "bit_index": int(meta.bit_index),
    }

def _layout_meta_to_json(layout: Optional[StructLayoutMeta]) -> Optional[dict]:
    if layout is None:
        return None
    return {
        "min_alignment": int(layout.min_alignment),
        "aligned_size": int(layout.aligned_size),
        "unaligned_size": int(layout.unaligned_size),
        "highest_member_alignment": int(layout.highest_member_alignment),
        "last_member_end": int(layout.last_member_end),
        "super_size": int(layout.super_size),
        "reuses_super_tail_padding": bool(layout.reuses_super_tail_padding),
    }

def _qualifiers_from_flags(flags: int) -> dict:
    return {
        "const": bool(flags & 0x2),
        "out": bool(flags & 0x100),
        "ref": bool(flags & 0x800),
        "return": bool(flags & 0x400),
        "param": bool(flags & 0x80),
    }

def _param_signature_fragment(param, *, for_return: bool = False) -> str:
    type_text = (
        param.type_desc.signature_name
        if getattr(param, "type_desc", None) and getattr(param.type_desc, "signature_name", "")
        else _property_type_to_cpp(param.type_name)
    )
    quals = _qualifiers_from_flags(getattr(param, "flags", 0))
    if quals["const"] and not type_text.startswith("const "):
        type_text = f"const {type_text}"
    if not for_return and (quals["ref"] or quals["out"]):
        type_text = f"{type_text}&"
    if for_return:
        return type_text
    return f"{type_text} {param.name}"

def _build_function_signature(func) -> str:
    return_param = getattr(func, "return_param", None)
    return_type = "void"
    if return_param is not None:
        return_type = _param_signature_fragment(return_param, for_return=True)
    params = [
        _param_signature_fragment(param)
        for param in getattr(func, "params", [])
        if not (getattr(param, "flags", 0) & 0x400)
    ]
    return f"{return_type} {func.name}({', '.join(params)})"

def _write_structs_file_v2(path: str, items: list):
    entries = []
    for s in items:
        members = []
        for m in sorted(
            s.members,
            key=lambda item: (
                getattr(item, "storage_offset", item.offset),
                (item.bool_meta.bit_index if getattr(item, "bool_meta", None) and item.bool_meta.bit_index >= 0 else 0),
                item.name,
            ),
        ):
            members.append(
                {
                    "name": m.name,
                    "offset": int(m.offset),
                    "storage_offset": int(getattr(m, "storage_offset", m.offset)),
                    "size": int(m.size),
                    "array_dim": int(m.array_dim),
                    "flags": f"0x{int(m.flags):X}",
                    "property_class": m.type_name,
                    "type": _type_desc_to_json(getattr(m, "type_desc", None) or _fallback_type_desc(m.type_name, m.size)),
                    "bool_meta": _bool_meta_to_json(getattr(m, "bool_meta", None)),
                }
            )

        functions = []
        for f in getattr(s, "functions", []):
            params = []
            for p in getattr(f, "params", []):
                params.append(
                    {
                        "name": p.name,
                        "offset": int(p.offset),
                        "storage_offset": int(getattr(p, "storage_offset", p.offset)),
                        "size": int(p.size),
                        "flags": f"0x{int(p.flags):X}",
                        "qualifiers": _qualifiers_from_flags(getattr(p, "flags", 0)),
                        "property_class": p.type_name,
                        "type": _type_desc_to_json(getattr(p, "type_desc", None) or _fallback_type_desc(p.type_name, p.size)),
                        "bool_meta": _bool_meta_to_json(getattr(p, "bool_meta", None)),
                    }
                )
            functions.append(
                {
                    "name": f.name,
                    "address": f"0x{int(f.address):X}",
                    "rva": f"0x{int(getattr(f, 'rva', 0)):X}",
                    "exec_func": f"0x{int(getattr(f, 'exec_func', 0)):X}",
                    "flags": f"0x{int(getattr(f, 'flags', 0)):X}",
                    "signature": _build_function_signature(f),
                    "return": (
                        {
                            "name": f.return_param.name,
                            "offset": int(f.return_param.offset),
                            "size": int(f.return_param.size),
                            "flags": f"0x{int(f.return_param.flags):X}",
                            "qualifiers": _qualifiers_from_flags(getattr(f.return_param, "flags", 0)),
                            "property_class": f.return_param.type_name,
                            "type": _type_desc_to_json(getattr(f.return_param, "type_desc", None) or _fallback_type_desc(f.return_param.type_name, f.return_param.size)),
                            "bool_meta": _bool_meta_to_json(getattr(f.return_param, "bool_meta", None)),
                        }
                        if getattr(f, "return_param", None) is not None
                        else None
                    ),
                    "params": params,
                }
            )

        entries.append(
            {
                "name": s.name,
                "full_name": s.full_name.replace("/Script/", ""),
                "package": s.package,
                "kind": "class" if s.is_class else "struct",
                "size": int(s.size),
                "super_name": s.super_name,
                "super_full_name": s.super_full_name.replace("/Script/", "") if getattr(s, "super_full_name", "") else "",
                "super_chain": list(s.super_chain or []),
                "layout": _layout_meta_to_json(getattr(s, "layout", None)),
                "members": members,
                "functions": functions,
            }
        )

    output = {"schema_version": 2, "kind": "ue_structs", "data": entries}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

def _build_legacy_struct_entries(items: list) -> list:
    data_list = []
    for s in items:
        entry = {}
        entry_data = []

        supers = [s.super_name] if s.super_name else []
        entry_data.append({"__InheritInfo": supers})
        entry_data.append({"__MDKClassSize": s.size})
        if s.package:
            entry_data.append({"__Assembly": s.package})
        if s.super_chain:
            entry_data.append({"__SuperChain": s.super_chain})

        for m in s.members:
            type_str = _property_type_to_cpp(m.type_name)
            member_entry = {
                m.name: [[type_str, "D", "", []], m.offset, m.size]
            }
            entry_data.append(member_entry)

        for f in getattr(s, "functions", []):
            params = []
            for p in f.params:
                ptype = _property_type_to_cpp(p.type_name)
                params.append([ptype, p.name, f"0x{p.flags:X}", p.size, p.offset])

            func_entry = {
                f.name: [["void", f"0x{f.flags:X}", f"0x{f.address:X}", params]]
            }
            entry_data.append(func_entry)

        entry[s.full_name.replace("/Script/", "")] = entry_data
        data_list.append(entry)
    return data_list

def _write_structs_file(path: str, items: list):
    output = {"data": _build_legacy_struct_entries(items)}
    with open(path, "w") as f:
        json.dump(output, f, separators=(",", ":"))

def write_enums_json(path: str, dump: SDKDump):
    data_list = []
    for e in dump.enums:
        entry = {}
        values = [[name, val] for name, val in e.values]
        clean_name = e.full_name.replace("/Script/", "")
        entry[clean_name] = values
        data_list.append(entry)

    output = {"data": data_list}
    with open(path, "w") as f:
        json.dump(output, f, separators=(",", ":"))

def write_methods_json(path: str, dump: SDKDump):
    methods = {}
    for s in dump.structs:
        for f in getattr(s, "functions", []):
            full_name = f"{s.name}.{f.name}"
            methods[full_name] = {
                "address": f"0x{f.address:X}",
                "rva": f"0x{getattr(f, 'rva', 0):X}",
                "pattern": getattr(f, "pattern", ""),
                "exec_func": f"0x{f.exec_func:X}" if getattr(f, "exec_func", 0) else "0x0",
                "flags": f"0x{f.flags:X}"
            }
    
    with open(path, "w", encoding="utf-8") as f:
        json.dump(methods, f, indent=2)

def write_fields_csv(path: str, dump: SDKDump):
    lines = ["ClassName,FieldName,Offset,Type,IsStatic,Address"]
    for s in dump.structs:
        sf_ptr = getattr(s, "static_fields_ptr", 0)
        for m in s.members:
            is_stat = "true" if getattr(m, "is_static", False) else "false"
            type_str = _property_type_to_cpp(m.type_name) if hasattr(m, 'type_name') else "Unknown"
            type_str = type_str.replace(",", ";")
            addr = ""
            if getattr(m, "is_static", False) and sf_ptr and m.offset >= 0:
                addr = f"0x{sf_ptr + m.offset:X}"
            lines.append(f"{s.name},{m.name},0x{m.offset:X},{type_str},{is_stat},{addr}")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def write_statics_json(path: str, dump: SDKDump):
    statics = {}
    for s in dump.structs:
        typeinfo_ptr = getattr(s, "static_typeinfo_ptr", 0)
        klass_ptr = getattr(s, "klass_ptr", 0)
        sf_ptr = getattr(s, "static_fields_ptr", 0)
        has_static = any(getattr(m, "is_static", False) for m in s.members)

        if has_static or typeinfo_ptr or klass_ptr:
            class_statics = {}
            for m in s.members:
                if getattr(m, "is_static", False):
                    field_entry = {
                        "offset": f"0x{m.offset:X}",
                        "type": m.type_name,
                    }
                    if sf_ptr and m.offset >= 0:
                        field_entry["address"] = f"0x{sf_ptr + m.offset:X}"
                    class_statics[m.name] = field_entry

            entry = {
                "klass": s.full_name,
                "statics": class_statics,
            }

            if klass_ptr:
                entry["klass_ptr"] = f"0x{klass_ptr:X}"
            if sf_ptr:
                entry["static_fields_ptr"] = f"0x{sf_ptr:X}"
            if typeinfo_ptr:
                entry["TypeInfo"] = f"0x{typeinfo_ptr:X}"

            statics[s.name] = entry

    with open(path, "w", encoding="utf-8") as f:
        json.dump(statics, f, indent=2)

def write_hierarchy_json(path: str, dump: SDKDump):
    hier = {}
    for s in dump.structs:
        hier[s.name] = {
            "super": s.super_name,
            "size": s.size,
            "members_count": len(s.members),
            "is_class": s.is_class,
            "package": s.package
        }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(hier, f, indent=2)

def write_globals_json(path: str, gnames_off: int, gobjects_off: int, gworld_off: int, engine: str = "ue", dump: SDKDump = None, gengine_off: int = 0):
    globals_data = {}
    if engine.lower() == "il2cpp":
        code_reg = getattr(dump, "code_reg", 0) if dump else 0
        meta_reg = getattr(dump, "meta_reg", 0) if dump else 0
        s_meta = getattr(dump, "s_global", 0) if dump else 0
        ga_base = getattr(dump, "ga_base", 0) if dump else 0

        globals_data["GameAssembly_base"] = f"0x{ga_base:X}"
        globals_data["il2cpp_codegen_registration"] = f"0x{code_reg:X}"
        globals_data["g_MetadataRegistration"] = f"0x{meta_reg:X}"
        globals_data["s_GlobalMetadata"] = f"0x{s_meta:X}"

        sf_off = getattr(dump, "static_fields_class_offset", 0) if dump else 0
        if sf_off:
            globals_data["Il2CppClass_static_fields_offset"] = f"0x{sf_off:X}"

    elif engine.lower() == "mono":
        globals_data["mono_base"] = f"0x{gnames_off:X}" if gnames_off else "0x0"

    else:
        globals_data = {
            "GNames": f"0x{gnames_off:X}",
            "GObjects": f"0x{gobjects_off:X}",
            "GWorld": f"0x{gworld_off:X}",
            "GEngine": f"0x{gengine_off:X}",
        }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(globals_data, f, indent=2)

def write_rvamap_json(path: str, process_name: str):
    mapping = {}
    if os.path.exists(process_name):
        try:
            sections = get_pe_sections(process_name)
            for sec in sections:
                sname = sec["name"].strip("\x00")
                mapping[sname] = {
                    "virtual_address": f"0x{sec['virtual_address']:X}",
                    "virtual_size": f"0x{sec['virtual_size']:X}",
                    "raw_offset": f"0x{sec['raw_offset']:X}",
                    "executable": sec["executable"]
                }
        except Exception:
            pass

    with open(path, "w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2)

def write_all(
    output_dir: str,
    dump: SDKDump,
    gnames_off: int,
    gobjects_off: int,
    gworld_off: int,
    *,
    process_name: str = "",
    ue_version: str = "",
    unity_version: str = "",
    metadata_version: str = "",
    pe_timestamp: int = 0,
    engine: str = "ue",
    steam_appid: Optional[int] = None,
    gengine_off: int = 0,
):
    os.makedirs(output_dir, exist_ok=True)

    class_items = [s for s in dump.structs if s.is_class]
    struct_items = [s for s in dump.structs if not s.is_class]
    classes_path = os.path.join(output_dir, "ClassesInfo.json")
    structs_path = os.path.join(output_dir, "StructsInfo.json")
    write_classes_json(classes_path, dump)
    write_structs_json(structs_path, dump)
    write_enums_json(os.path.join(output_dir, "EnumsInfo.json"), dump)
    if engine == "ue":
        write_classes_json_v2(os.path.join(output_dir, "ClassesInfoV2.json"), dump)
        write_structs_json_v2(os.path.join(output_dir, "StructsInfoV2.json"), dump)

    classes_data = _build_legacy_struct_entries(class_items)
    structs_data = _build_legacy_struct_entries(struct_items)

    write_offsets_json(
        os.path.join(output_dir, "OffsetsInfo.json"),
        gnames_off, gobjects_off, gworld_off,
        process_name=process_name,
        ue_version=ue_version,
        unity_version=unity_version,
        metadata_version=metadata_version,
        pe_timestamp=pe_timestamp,
        classes_data=classes_data,
        structs_data=structs_data,
        engine=engine,
        steam_appid=steam_appid,
    )
    
    write_methods_json(os.path.join(output_dir, "Methods.json"), dump)
    write_fields_csv(os.path.join(output_dir, "Fields.csv"), dump)
    write_statics_json(os.path.join(output_dir, "Statics.json"), dump)
    write_hierarchy_json(os.path.join(output_dir, "Hierarchy.json"), dump)
    write_globals_json(os.path.join(output_dir, "Globals.json"), gnames_off, gobjects_off, gworld_off, engine=engine, dump=dump, gengine_off=gengine_off)
    write_rvamap_json(os.path.join(output_dir, "RVAMap.json"), process_name)

    chain = {}
    if engine == "ue":
        chain = resolve_standard_chain(classes_data, structs_data)
    if engine == "ue" and (gworld_off or process_name):
        write_readme(
            os.path.join(output_dir, "README.txt"),
            gnames_off, gobjects_off, gworld_off,
            process_name=process_name,
            ue_version=ue_version,
            pe_timestamp=pe_timestamp,
            chain_offsets=chain,
            classes_data=classes_data,
            structs_data=structs_data,
        )
    elif engine in ("il2cpp", "mono"):
        write_unity_readme(
            os.path.join(output_dir, "README.txt"),
            engine=engine,
            process_name=process_name,
            unity_version=unity_version,
            metadata_version=metadata_version,
            pe_timestamp=pe_timestamp,
        )

    write_dump_table(
        os.path.join(output_dir, "Dump_Table.json"),
        output_dir=output_dir,
        dump=dump,
        engine=engine,
        process_name=process_name,
        ue_version=ue_version,
        unity_version=unity_version,
        metadata_version=metadata_version,
        pe_timestamp=pe_timestamp,
        gnames_off=gnames_off,
        gobjects_off=gobjects_off,
        gworld_off=gworld_off,
        chain_offsets=chain,
    )

def write_source_dump_json(
    path: str,
    dump: SDKDump,
    *,
    process_name: str = "",
):
    from src.output.source_writer import write_source_dump_json as _write_source_dump_json

    _write_source_dump_json(path, dump, process_name=process_name)

def _property_type_to_cpp(type_name: str) -> str:
    _ue_map = {
        "BoolProperty": "bool",
        "ByteProperty": "uint8_t",
        "Int8Property": "int8_t",
        "Int16Property": "int16_t",
        "IntProperty": "int32_t",
        "Int64Property": "int64_t",
        "UInt16Property": "uint16_t",
        "UInt32Property": "uint32_t",
        "UInt64Property": "uint64_t",
        "FloatProperty": "float",
        "DoubleProperty": "double",
        "NameProperty": "FName",
        "StrProperty": "FString",
        "TextProperty": "FText",
        "ObjectProperty": "UObject*",
        "ClassProperty": "UClass*",
        "WeakObjectProperty": "TWeakObjectPtr",
        "SoftObjectProperty": "TSoftObjectPtr",
        "SoftClassProperty": "TSoftClassPtr",
        "LazyObjectProperty": "TLazyObjectPtr",
        "InterfaceProperty": "FScriptInterface",
        "StructProperty": "FStruct",
        "ArrayProperty": "TArray",
        "MapProperty": "TMap",
        "SetProperty": "TSet",
        "DelegateProperty": "FDelegate",
        "MulticastDelegateProperty": "FMulticastDelegate",
        "MulticastInlineDelegateProperty": "FMulticastInlineDelegate",
        "MulticastSparseDelegateProperty": "FMulticastSparseDelegate",
        "EnumProperty": "TEnumAsByte",
        "FieldPathProperty": "FFieldPath",
    }
    if type_name in _ue_map:
        return _ue_map[type_name]

    _il2cpp_map = {
        "void": "void",
        "bool": "bool",
        "char": "char16_t",
        "int8": "int8_t",
        "uint8": "uint8_t",
        "int16": "int16_t",
        "uint16": "uint16_t",
        "int32": "int32_t",
        "uint32": "uint32_t",
        "int64": "int64_t",
        "uint64": "uint64_t",
        "float": "float",
        "double": "double",
        "string": "Il2CppString*",
        "IntPtr": "intptr_t",
        "UIntPtr": "uintptr_t",
        "Array": "Il2CppArray*",
        "SZArray": "Il2CppArray*",
        "Generic": "void*",
        "GenericInst": "void*",
        "Ptr": "void*",
        "ByRef": "void*",
        "ValueType": "uint8_t",
        "Class": "Il2CppObject*",
        "Enum": "int32_t",
        "object": "Il2CppObject*",
    }
    if type_name in _il2cpp_map:
        return _il2cpp_map[type_name]

    return type_name
