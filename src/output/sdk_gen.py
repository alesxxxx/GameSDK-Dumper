
import argparse
import json
import os
import re
import sys

def map_type(ue_type: str, size: int = 0) -> str:
    _primitive = {
        "int32_t", "uint32_t", "int64_t", "uint64_t",
        "float", "double", "bool",
        "uint8_t", "int8_t", "int16_t", "uint16_t",
    }
    if ue_type in _primitive:
        return ue_type

    if ue_type.endswith("*"):
        return "uintptr_t"

    _ue_prop = {
        "FloatProperty":        "float",
        "DoubleProperty":       "double",
        "IntProperty":          "int32_t",
        "Int8Property":         "int8_t",
        "Int16Property":        "int16_t",
        "Int64Property":        "int64_t",
        "UInt16Property":       "uint16_t",
        "UInt32Property":       "uint32_t",
        "UInt64Property":       "uint64_t",
        "ByteProperty":         "uint8_t",
        "BoolProperty":         "bool",
        "NameProperty":         "uint64_t",
        "StrProperty":          "uint8_t[0x10]",
        "TextProperty":         "uint8_t[0x18]",
        "ObjectProperty":       "uintptr_t",
        "ClassProperty":        "uintptr_t",
        "SoftObjectProperty":   "uintptr_t",
        "SoftClassProperty":    "uintptr_t",
        "WeakObjectProperty":   "uintptr_t",
        "LazyObjectProperty":   "uintptr_t",
        "ObjectPtrProperty":    "uintptr_t",
        "ClassPtrProperty":     "uintptr_t",
        "ArrayProperty":        "uint8_t[0x10]",
        "MapProperty":          "uint8_t[0x50]",
        "SetProperty":          "uint8_t[0x50]",
        "DelegateProperty":         "uint8_t[0x0C]",
        "MulticastDelegateProperty": "uint8_t[0x10]",
        "MulticastInlineDelegateProperty": "uint8_t[0x10]",
        "MulticastSparseDelegateProperty": "uint8_t[0x10]",
        "EnumProperty":         "uint8_t",
        "InterfaceProperty":    "uint8_t[0x10]",
        "FieldPathProperty":    "uint8_t[0x10]",
        "StructProperty":       None,
    }

    mapped = _ue_prop.get(ue_type)
    if mapped is not None:
        return mapped

    if size > 0:
        return f"uint8_t[0x{size:X}]"
    return "uint8_t"

def _type_byte_size(cpp_type: str, field_size: int) -> int:
    _known = {
        "float": 4, "double": 8, "bool": 1,
        "int8_t": 1, "uint8_t": 1,
        "int16_t": 2, "uint16_t": 2,
        "int32_t": 4, "uint32_t": 4,
        "int64_t": 8, "uint64_t": 8,
        "uintptr_t": 8,
    }
    if cpp_type in _known:
        return _known[cpp_type]
    if "[" in cpp_type and "]" in cpp_type:
        try:
            inner = cpp_type[cpp_type.index("[") + 1: cpp_type.index("]")]
            return int(inner, 16) if inner.startswith("0x") else int(inner)
        except (ValueError, IndexError):
            pass
    return field_size
def _emit_field(cpp_type: str, field_name: str, comment: str = "") -> str:
    tail = f" // {comment}" if comment else ""
    if "[" in cpp_type and cpp_type.startswith("uint8_t["):
        bracket_start = cpp_type.index("[")
        base   = cpp_type[:bracket_start]
        suffix = cpp_type[bracket_start:]
        return f"    {base} {field_name}{suffix};{tail}\n"
    return f"    {cpp_type} {field_name};{tail}\n"

def _sanitize_identifier(name: str) -> str:
    safe = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    if safe and safe[0].isdigit():
        safe = "_" + safe
    return safe or "Unknown"

def parse_package(full_name: str):
    if "." in full_name:
        parts = full_name.split(".", 1)
        return _sanitize_identifier(parts[0]), _sanitize_identifier(parts[1])
    return "Global", _sanitize_identifier(full_name)

def generate_package_headers(classes, structs, out_dir):
    packages = {}

    class_sizes: dict = {}
    for data in [structs, classes]:
        for entry in data:
            if not entry:
                continue
            for full_name, details in entry.items():
                for item in details:
                    if "__MDKClassSize" in item:
                        _, simple = parse_package(full_name)
                        class_sizes[simple] = item["__MDKClassSize"]

    all_types: dict = {}
    for data in [structs, classes]:
        for entry in data:
            if not entry:
                continue
            for full_name, details in entry.items():
                pkg, clz_name = parse_package(full_name)
                packages.setdefault(pkg, {})[clz_name] = details
                all_types[clz_name] = details

    for pkg, types in packages.items():
        with open(os.path.join(out_dir, f"{pkg}.hpp"), "w", encoding="utf-8") as f:
            f.write("#pragma once\n")
            f.write("#include <cstdint>\n\n")
            f.write("namespace sdk {\n\n")

            for type_name, details in types.items():
                inherit_info = None
                class_size   = 0
                fields       = []
                functions    = []

                for item in details:
                    if "__InheritInfo" in item:
                        inherit_info = item["__InheritInfo"]
                    elif "__MDKClassSize" in item:
                        class_size = item["__MDKClassSize"]
                    elif any(k.startswith("__") for k in item):
                        pass
                    else:
                        for field_name, field_def in item.items():
                            if isinstance(field_def, list) and len(field_def) == 3:
                                fields.append((field_name, field_def))
                            elif (isinstance(field_def, list) and len(field_def) == 1
                                  and isinstance(field_def[0], list)
                                  and len(field_def[0]) == 4):
                                functions.append((field_name, field_def[0]))

                fields.sort(key=lambda x: x[1][1])

                f.write(f"// Size: 0x{class_size:04X} ({class_size} bytes)\n")

                if inherit_info:
                    base_name = inherit_info[0]
                    f.write(f"// Inherits: {base_name}\n")
                    f.write(f"struct {pkg}_{type_name} : {pkg}_{base_name} {{\n")
                    base_size    = class_sizes.get(base_name, 0)
                    if base_size == 0 and fields:
                        base_size = fields[0][1][1]
                    current_offset = base_size
                else:
                    f.write(f"struct {pkg}_{type_name} {{\n")
                    current_offset = 0

                for field_name, field_def in fields:
                    field_type_info, offset, size = field_def
                    ue_type    = field_type_info[0] if field_type_info else "Unknown"
                    cpp_type   = map_type(ue_type, size)

                    if offset < current_offset:
                        f.write(f"    // {cpp_type} {field_name}; "
                                f"// 0x{offset:04X} (overlaps previous field)\n")
                        continue

                    if offset > current_offset:
                        pad = offset - current_offset
                        f.write(f"    uint8_t pad_{current_offset:04X}"
                                f"[0x{pad:X}]; // {pad} bytes padding\n")
                        current_offset = offset

                    f.write(_emit_field(cpp_type, field_name, f"0x{offset:04X}"))
                    current_offset = offset + _type_byte_size(cpp_type, size)

                if class_size > current_offset:
                    pad = class_size - current_offset
                    f.write(f"    uint8_t pad_{current_offset:04X}"
                            f"[0x{pad:X}]; // {pad} bytes trailing padding\n")

                f.write("};\n\n")

                for func_name, func_def in functions:
                    ret_type, flags_str, addr_str, params = func_def
                    if not params:
                        continue

                    f.write(f"// Function {pkg}_{type_name}::{func_name}\n")
                    f.write(f"// Flags: {flags_str}   Address: {addr_str}\n")
                    f.write(f"struct {pkg}_{type_name}_{func_name}_Params {{\n")

                    param_cursor = 0
                    for param in sorted(params, key=lambda x: x[4]):
                        p_type, p_name, p_flags, p_size, p_offset = param
                        m_type = map_type(p_type, p_size)

                        if p_offset < param_cursor:
                            f.write(f"    // {m_type} {p_name}; "
                                    f"// 0x{p_offset:04X} (overlaps) (Flags: {p_flags})\n")
                            continue

                        if p_offset > param_cursor:
                            pad = p_offset - param_cursor
                            f.write(f"    uint8_t pad_{param_cursor:04X}[0x{pad:X}];\n")
                            param_cursor = p_offset

                        f.write(_emit_field(m_type, p_name, f"0x{p_offset:04X} (Flags: {p_flags})"))
                        param_cursor = p_offset + _type_byte_size(m_type, p_size)

                    f.write("};\n\n")

            f.write("} // namespace sdk\n")

    return list(packages.keys())

def generate_master_header(packages, out_dir, offsets_data: dict = None):
    offsets_data = offsets_data or {}
    with open(os.path.join(out_dir, "SDK.hpp"), "w", encoding="utf-8") as f:
        f.write("#pragma once\n\n")
        f.write("// ─────────────────────────────────────────────────────────\n")
        f.write("// Auto-generated Unreal Engine SDK\n")
        f.write("// Do NOT hand-edit. Re-run to refresh after a game update.\n")
        f.write("// ─────────────────────────────────────────────────────────\n\n")
        f.write('#include "Offsets.hpp"\n')
        f.write('#include "chains.hpp"\n\n')
        f.write("// ── Quick-start pointer chain (external / RPM-based) ────\n")
        f.write("//\n")
        f.write("//   uintptr_t base = module_base;   // e.g. from GetModuleBase()\n")
        f.write("//\n")
        f.write("//   // Read a 64-bit pointer from a remote process:\n")
        f.write("//   auto rpm = [&](uintptr_t addr) -> uintptr_t {\n")
        f.write("//       uintptr_t val = 0;\n")
        f.write("//       ReadProcessMemory(hProc, (LPCVOID)addr, &val, 8, nullptr);\n")
        f.write("//       return val;\n")
        f.write("//   };\n")
        f.write("//\n")
        f.write("//   uintptr_t pawn = sdk::get_acknowledged_pawn(base, rpm);\n")
        f.write("//   // pawn + <MemberOffset> = your stat / health / etc.\n")
        f.write("//\n\n")
        for pkg in sorted(packages):
            f.write(f'#include "{pkg}.hpp"\n')

def generate_offsets_header(offsetsInfo, out_dir):
    with open(os.path.join(out_dir, "Offsets.hpp"), "w", encoding="utf-8") as f:
        f.write("#pragma once\n")
        f.write("#include <cstdint>\n\n")
        f.write("namespace sdk {\n\n")
        
        for entry in offsetsInfo.get("data", []):
            name = entry[0]
            val = entry[1]
            f.write(f"constexpr uint64_t {name} = 0x{val:X};\n")
            
        f.write("\n} // namespace sdk\n")

def _lookup_member_offset(classes_data: list, structs_data: list, class_name: str, member_name: str) -> int:
    from src.output.utils import lookup_member_offset
    return lookup_member_offset(classes_data, structs_data, class_name, member_name)

def _find_health_paths(classes_data: list, structs_data: list) -> list:
    results = []
    _HEALTH_FIELD_NAMES = {"HP", "Hp", "Health", "CurrentHealth", "MaxHealth",
                           "HealthPoints", "MaxHP", "MaxHp"}
    _COMPONENT_KEYWORDS = {"CharacterParameterComponent", "HealthComponent",
                           "AttributeSet", "VitalityComponent", "StatsComponent"}

    for dataset in (classes_data, structs_data):
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
                            if is_component or field_name in _HEALTH_FIELD_NAMES:
                                results.append(
                                    f"//   {uq}::{field_name} = 0x{offset:X}"
                                )
    return results

def generate_chains_header(out_dir: str, classes_data: list = None, structs_data: list = None):
    classes_data = classes_data or []
    structs_data = structs_data or []

    def offset_hex(class_name: str, member_name: str, fallback_comment: str) -> str:
        off = _lookup_member_offset(classes_data, structs_data, class_name, member_name)
        if off >= 0:
            return f"0x{off:04X}"
        return f"0x0000 /* UNRESOLVED: {class_name}::{member_name} — check dump */"

    owning_gi      = offset_hex("World",              "OwningGameInstance",  "UWorld::OwningGameInstance")
    local_players  = offset_hex("GameInstance",       "LocalPlayers",        "UGameInstance::LocalPlayers")
    pc_offset      = offset_hex("Player",             "PlayerController",    "UPlayer::PlayerController")
    ack_pawn       = offset_hex("PlayerController",   "AcknowledgedPawn",    "APlayerController::AcknowledgedPawn")
    player_state   = offset_hex("Controller",         "PlayerState",         "AController::PlayerState")
    char_movement  = offset_hex("Character",          "CharacterMovement",   "ACharacter::CharacterMovement")

    with open(os.path.join(out_dir, "chains.hpp"), "w", encoding="utf-8") as f:
        f.write("#pragma once\n")
        f.write("#include <cstdint>\n")
        f.write('#include "Offsets.hpp"\n\n')
        f.write("// chains.hpp — Auto-generated. Offsets resolved from this game's dump.\n")
        f.write("// Do NOT hand-edit. Re-run SDK generation to refresh.\n\n")
        f.write("namespace sdk {\n\n")
        f.write("// Requires a user-provided read_u64(addr) callable.\n\n")
        f.write(f"""\
template<typename Reader>
inline uintptr_t get_uworld(uintptr_t base, Reader rpm_u64) {{
    return rpm_u64(base + OFFSET_GWORLD);
}}

template<typename Reader>
inline uintptr_t get_game_instance(uintptr_t base, Reader rpm_u64) {{
    uintptr_t uworld = get_uworld(base, rpm_u64);
    if (!uworld) return 0;
    return rpm_u64(uworld + {owning_gi}); // UWorld::OwningGameInstance
}}

template<typename Reader>
inline uintptr_t get_local_player(uintptr_t base, Reader rpm_u64) {{
    uintptr_t gi = get_game_instance(base, rpm_u64);
    if (!gi) return 0;
    uintptr_t players_data = rpm_u64(gi + {local_players}); // UGameInstance::LocalPlayers TArray
    if (!players_data) return 0;
    return rpm_u64(players_data); // first element
}}

template<typename Reader>
inline uintptr_t get_player_controller(uintptr_t base, Reader rpm_u64) {{
    uintptr_t lp = get_local_player(base, rpm_u64);
    if (!lp) return 0;
    return rpm_u64(lp + {pc_offset}); // UPlayer::PlayerController
}}

template<typename Reader>
inline uintptr_t get_acknowledged_pawn(uintptr_t base, Reader rpm_u64) {{
    uintptr_t pc = get_player_controller(base, rpm_u64);
    if (!pc) return 0;
    return rpm_u64(pc + {ack_pawn}); // APlayerController::AcknowledgedPawn
}}

template<typename Reader>
inline uintptr_t get_player_state(uintptr_t base, Reader rpm_u64) {{
    uintptr_t pc = get_player_controller(base, rpm_u64);
    if (!pc) return 0;
    return rpm_u64(pc + {player_state}); // AController::PlayerState
}}

// Character movement (for speed, gravity, jump)
template<typename Reader>
inline uintptr_t get_character_movement(uintptr_t base, Reader rpm_u64) {{
    uintptr_t pawn = get_acknowledged_pawn(base, rpm_u64);
    if (!pawn) return 0;
    return rpm_u64(pawn + {char_movement}); // ACharacter::CharacterMovement
}}
""")

        health_lines = _find_health_paths(classes_data, structs_data)
        if health_lines:
            f.write("\n// ── Health / Character Parameter Components found in this dump ──\n")
            f.write("// These are GAME-SPECIFIC. Use the offsets below to build your\n")
            f.write("// health pointer chain from the pawn address.\n")
            for line in health_lines[:30]:
                f.write(f"{line}\n")
            f.write("\n")

        f.write("\n} // namespace sdk\n")

_IL2CPP_TYPE_MAP = {
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
    "Il2CppString*": "Il2CppString*",
    "Il2CppObject*": "Il2CppObject*",
    "Il2CppArray*": "Il2CppArray*",
}

def _map_il2cpp_type(type_name: str, size: int = 0) -> str:
    if type_name in _IL2CPP_TYPE_MAP:
        return _IL2CPP_TYPE_MAP[type_name]

    _cpp_prim = {"int32_t", "uint32_t", "int64_t", "uint64_t", "float", "double",
                 "bool", "uint8_t", "int8_t", "int16_t", "uint16_t", "intptr_t", "uintptr_t"}
    if type_name in _cpp_prim:
        return type_name

    if "." in type_name:
        short = _sanitize_identifier(type_name.split(".")[-1])
        return f"struct {short}*"

    if type_name and type_name[0].isupper():
        return f"struct {_sanitize_identifier(type_name)}*"

    if size > 0:
        return f"uint8_t[0x{size:X}]"
    return "uintptr_t"

def _unity_assembly_name(raw: str) -> str:
    if raw.endswith(".dll"):
        raw = raw[:-4]
    name = _sanitize_identifier(raw) if raw else "Global"
    if len(name) > 60:
        return "Global"
    return name

def generate_unity_package_headers(classes, structs, out_dir):

    assemblies = {}
    class_sizes = {}

    for data in [structs, classes]:
        for entry in data:
            if not entry:
                continue
            for full_name, details in entry.items():
                assembly = "Global"
                for item in details:
                    if "__Assembly" in item:
                        assembly = _unity_assembly_name(item["__Assembly"])
                        break

                if assembly == "Global" and "." in full_name:
                    ns_prefix = _sanitize_identifier(full_name.split(".")[0])
                    if len(ns_prefix) <= 60:
                        assembly = ns_prefix

                _, simple_name = parse_package(full_name)
                assemblies.setdefault(assembly, {})[simple_name] = (full_name, details)

                for item in details:
                    if "__MDKClassSize" in item:
                        class_sizes[simple_name] = item["__MDKClassSize"]

    for asm_name, types in assemblies.items():
        with open(os.path.join(out_dir, f"{asm_name}.hpp"), "w", encoding="utf-8") as f:
            f.write("#pragma once\n")
            f.write("#include <cstdint>\n\n")
            f.write(f"// ─────────────────────────────────────────────────────────\n")
            f.write(f"// Assembly: {asm_name}\n")
            f.write(f"// Auto-generated Unity IL2CPP SDK\n")
            f.write(f"// ─────────────────────────────────────────────────────────\n\n")
            f.write("namespace sdk {\n\n")

            for type_name, (full_name, details) in types.items():
                inherit_info = None
                class_size = 0
                fields = []

                for item in details:
                    if "__InheritInfo" in item:
                        inherit_info = item["__InheritInfo"]
                    elif "__MDKClassSize" in item:
                        class_size = item["__MDKClassSize"]
                    elif any(k.startswith("__") for k in item):
                        pass
                    else:
                        for field_name, field_def in item.items():
                            if isinstance(field_def, list) and len(field_def) == 3:
                                fields.append((field_name, field_def))

                fields.sort(key=lambda x: x[1][1])

                f.write(f"// ── {full_name} ──\n")
                f.write(f"// Size: 0x{class_size:04X} ({class_size} bytes)\n")

                if inherit_info:
                    base_name = _sanitize_identifier(inherit_info[0])
                    f.write(f"// Inherits: {inherit_info[0]}\n")
                    f.write(f"struct {type_name} : {base_name} {{\n")
                    base_size = class_sizes.get(base_name, 0)
                    if base_size == 0 and fields:
                        base_size = fields[0][1][1]
                    current_offset = base_size
                else:
                    f.write(f"struct {type_name} {{\n")
                    current_offset = 0

                for field_name, field_def in fields:
                    field_type_info, offset, size = field_def
                    raw_type = field_type_info[0] if field_type_info else "Unknown"
                    cpp_type = _map_il2cpp_type(raw_type, size)

                    if offset < current_offset:
                        f.write(f"    // {cpp_type} {field_name}; "
                                f"// 0x{offset:04X} (overlaps previous)\n")
                        continue

                    if offset > current_offset:
                        pad = offset - current_offset
                        f.write(f"    uint8_t pad_{current_offset:04X}"
                                f"[0x{pad:X}]; // {pad} bytes padding\n")
                        current_offset = offset

                    f.write(_emit_field(cpp_type, field_name, f"0x{offset:04X}"))
                    current_offset = offset + _type_byte_size(cpp_type, size)

                if class_size > current_offset:
                    pad = class_size - current_offset
                    f.write(f"    uint8_t pad_{current_offset:04X}"
                            f"[0x{pad:X}]; // {pad} bytes trailing padding\n")

                f.write("};\n\n")

            f.write("} // namespace sdk\n")

    return list(assemblies.keys())

def generate_unity_master_header(assemblies, out_dir):
    with open(os.path.join(out_dir, "SDK.hpp"), "w", encoding="utf-8") as f:
        f.write("#pragma once\n\n")
        f.write("// ─────────────────────────────────────────────────────────\n")
        f.write("// Auto-generated Unity IL2CPP SDK\n")
        f.write("// Do NOT hand-edit. Re-run to refresh after a game update.\n")
        f.write("// ─────────────────────────────────────────────────────────\n\n")
        f.write('#include "Offsets.hpp"\n')
        f.write('#include "il2cpp_types.hpp"\n\n')
        f.write("// ── Quick-start (external / RPM-based) ─────────────────\n")
        f.write("//\n")
        f.write("//   Unity IL2CPP does not expose a global object tree like UE's GWorld.\n")
        f.write("//   To find game objects at runtime, use one of these approaches:\n")
        f.write("//\n")
        f.write("//   1. Signature scan GameAssembly.dll for il2cpp_class_from_name\n")
        f.write("//      or il2cpp_domain_get_assemblies to enumerate loaded types.\n")
        f.write("//\n")
        f.write("//   2. Hook il2cpp_runtime_invoke to intercept method calls.\n")
        f.write("//\n")
        f.write("//   3. Pattern scan for static field references in GameAssembly.dll.\n")
        f.write("//      Static fields have fixed RVAs you can read directly.\n")
        f.write("//\n")
        f.write("//   Once you have an object pointer, use the struct layouts below\n")
        f.write("//   to read fields at their correct offsets.\n")
        f.write("//\n\n")
        for asm in sorted(assemblies):
            f.write(f'#include "{asm}.hpp"\n')

def generate_unity_il2cpp_types_header(out_dir):
    with open(os.path.join(out_dir, "il2cpp_types.hpp"), "w", encoding="utf-8") as f:
        f.write("#pragma once\n")
        f.write("#include <cstdint>\n\n")
        f.write("// ─────────────────────────────────────────────────────────\n")
        f.write("// IL2CPP Runtime Types — Common base structs\n")
        f.write("// These match the IL2CPP runtime's internal layout.\n")
        f.write("// ─────────────────────────────────────────────────────────\n\n")
        f.write("namespace sdk {\n\n")
        f.write("""\
// Il2CppObject — base of ALL managed objects (16 bytes header)
struct Il2CppObject {
    uintptr_t klass;      // 0x00 — pointer to Il2CppClass
    uintptr_t monitor;    // 0x08 — sync block / thread lock
};

// Il2CppString — System.String in IL2CPP
// Access: chars at +0x14, length at +0x10
struct Il2CppString {
    Il2CppObject object;  // 0x00 — inherited Il2CppObject header
    int32_t length;       // 0x10 — string length (char count)
    char16_t chars[1];    // 0x14 — UTF-16 character data (variable length)
};

// Il2CppArray — System.Array in IL2CPP
struct Il2CppArray {
    Il2CppObject object;  // 0x00 — inherited Il2CppObject header
    uintptr_t bounds;     // 0x10 — nullptr for SZArray (single-dim, zero-based)
    uint64_t max_length;  // 0x18 — element count
    // items start at +0x20
};

// Il2CppClass (partial) — enough to identify type at runtime
struct Il2CppClass {
    uintptr_t image;          // 0x00
    uintptr_t gc_desc;        // 0x08
    uintptr_t name;           // 0x10 — const char*
    uintptr_t namespaze;      // 0x18 — const char* (namespace)
    // ... many more fields; see il2cpp-class-internals.h for full layout
};

""")
        f.write("} // namespace sdk\n")

def generate_unity_offsets_header(offsets_data, out_dir):
    with open(os.path.join(out_dir, "Offsets.hpp"), "w", encoding="utf-8") as f:
        f.write("#pragma once\n")
        f.write("#include <cstdint>\n\n")
        f.write("// ─────────────────────────────────────────────────────────\n")
        f.write("// Unity IL2CPP — Static Offsets\n")
        f.write("// Unlike Unreal Engine, Unity IL2CPP does not have\n")
        f.write("// GWorld/GObjects/GNames global pointers.\n")
        f.write("// ─────────────────────────────────────────────────────────\n\n")
        f.write("namespace sdk {\n\n")

        for entry in offsets_data.get("data", []):
            name = entry[0]
            val = entry[1]
            if val:
                f.write(f"constexpr uint64_t {name} = 0x{val:X};\n")

        f.write("\n} // namespace sdk\n")

def generate_sdk(dump_dir: str, out_dir: str, engine: str = "auto"):
    os.makedirs(out_dir, exist_ok=True)

    try:
        with open(os.path.join(dump_dir, "ClassesInfo.json"), "r", encoding="utf-8") as f:
            classes_data = json.load(f).get("data", [])
    except FileNotFoundError:
        classes_data = []

    try:
        with open(os.path.join(dump_dir, "StructsInfo.json"), "r", encoding="utf-8") as f:
            structs_data = json.load(f).get("data", [])
    except FileNotFoundError:
        structs_data = []

    try:
        with open(os.path.join(dump_dir, "OffsetsInfo.json"), "r", encoding="utf-8") as f:
            offsets_data = json.load(f)
    except FileNotFoundError:
        offsets_data = {}

    if engine == "auto":
        engine = offsets_data.get("engine", "ue")

    if engine in ("il2cpp", "mono"):
        packages = generate_unity_package_headers(classes_data, structs_data, out_dir)
        generate_unity_master_header(packages, out_dir)
        generate_unity_offsets_header(offsets_data, out_dir)
        generate_unity_il2cpp_types_header(out_dir)
        print(f"Generated Unity IL2CPP SDK in {out_dir}/ ({len(packages)} assemblies)")
    else:
        from src.output.dump_sanity import assert_dump_dir_sane
        from src.output.ue_sdk_v2 import generate_v2_master_header, generate_v2_package_headers, has_v2_dump

        assert_dump_dir_sane(dump_dir, require_chains=True)
        if has_v2_dump(dump_dir):
            packages = generate_v2_package_headers(dump_dir, out_dir)
            generate_v2_master_header(packages, out_dir)
        else:
            packages = generate_package_headers(classes_data, structs_data, out_dir)
            generate_master_header(packages, out_dir, offsets_data=offsets_data)
        generate_offsets_header(offsets_data, out_dir)
        generate_chains_header(out_dir, classes_data=classes_data, structs_data=structs_data)
        print(f"Generated UE SDK in {out_dir}/ ({len(packages)} packages)")

    return packages

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="C++ SDK Generator")
    parser.add_argument("--dump-dir", required=True, help="Directory containing JSON dumps")
    parser.add_argument("--out-dir", required=True, help="Directory to output C++ headers")
    parser.add_argument("--engine", default="auto", choices=["ue", "il2cpp", "mono", "auto"],
                        help="Engine type (default: auto-detect from dump)")
    args = parser.parse_args()

    generate_sdk(args.dump_dir, args.out_dir, engine=args.engine)
