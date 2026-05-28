
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.core.models import MemberInfo, SDKDump, StructInfo

_SOURCE_CPP_KEYWORDS = {
    "alignas", "alignof", "and", "and_eq", "asm", "auto", "bitand", "bitor",
    "bool", "break", "case", "catch", "char", "char8_t", "char16_t", "char32_t",
    "class", "compl", "concept", "const", "consteval", "constexpr", "constinit",
    "const_cast", "continue", "co_await", "co_return", "co_yield", "decltype",
    "default", "delete", "do", "double", "dynamic_cast", "else", "enum",
    "explicit", "export", "extern", "false", "float", "for", "friend", "goto",
    "if", "inline", "int", "long", "mutable", "namespace", "new", "noexcept",
    "not", "not_eq", "nullptr", "operator", "or", "or_eq", "private",
    "protected", "public", "reflexpr", "register", "reinterpret_cast", "requires",
    "return", "short", "signed", "sizeof", "static", "static_assert",
    "static_cast", "struct", "switch", "template", "this", "thread_local",
    "throw", "true", "try", "typedef", "typeid", "typename", "union", "unsigned",
    "using", "virtual", "void", "volatile", "wchar_t", "while", "xor", "xor_eq",
}

_SOURCE_KEY_TABLES = {
    "DT_PlayerResource",
    "DT_TFPlayerResource",
}

_SOURCE_SDK_NON_M_IDENTIFIERS = {
    "deadflag",
    "movecollide",
    "moveparent",
    "movetype",
    "pl",
}

class SourceOutputValidationError(RuntimeError):
    pass

def _source_member_kind(member: MemberInfo) -> str:
    return str((member.metadata or {}).get("kind", "prop"))

def _source_member_raw_name(member: MemberInfo) -> str:
    return str((member.metadata or {}).get("raw_name", member.name))

def _source_member_cpp_name_base(member: MemberInfo) -> str:
    meta = member.metadata or {}
    preferred = meta.get("cpp_name") or member.name or meta.get("raw_name") or "unnamed"
    safe = str(preferred).strip().strip("\"'")
    safe = re.sub(r"[^0-9A-Za-z_]", "_", safe)
    safe = re.sub(r"_+", "_", safe).strip("_")
    if not safe:
        safe = "unnamed"
    if safe[0].isdigit():
        safe = f"unnamed_{safe}"
    if safe in _SOURCE_CPP_KEYWORDS:
        safe = f"{safe}_field"
    return safe

def _assign_source_cpp_names(struct: StructInfo) -> Dict[int, str]:
    used = {}
    names = {}

    for member in sorted(struct.members, key=lambda item: (item.offset, item.name)):
        base = _source_member_cpp_name_base(member)
        candidate = base
        attempt = 0

        while candidate in used:
            if used[candidate] is member:
                break
            suffix = f"_{member.offset:X}"
            if attempt > 0:
                suffix = f"{suffix}_{attempt}"
            candidate = f"{base}{suffix}"
            attempt += 1

        used[candidate] = member
        names[id(member)] = candidate

    return names

def collect_source_members(struct: StructInfo) -> List[Dict[str, Any]]:
    cpp_names = _assign_source_cpp_names(struct)
    members: List[Dict[str, Any]] = []

    for member in sorted(struct.members, key=lambda item: (item.offset, item.name)):
        meta = member.metadata or {}
        record: Dict[str, Any] = {
            "name": member.name,
            "raw_name": meta.get("raw_name", member.name),
            "cpp_name": cpp_names[id(member)],
            "offset": member.offset,
            "offset_hex": f"0x{member.offset:X}",
            "size": member.size,
            "type": member.type_name,
            "recv_type": meta.get("recv_type", member.type_name),
            "cpp_type_hint": meta.get("cpp_type_hint", member.type_name),
            "kind": meta.get("kind", "prop"),
            "flags": member.flags,
            "flags_hex": f"0x{member.flags:X}",
            "array_dim": member.array_dim,
        }

        if record["kind"] == "datatable":
            record["datatable_name"] = meta.get("datatable_name", "")
        if record["kind"] == "array":
            record["elements"] = int(meta.get("elements", member.array_dim or 0) or 0)
            record["element_stride"] = int(meta.get("element_stride", 0) or 0)
            record["element_type_name"] = meta.get("element_type_name", "")
        if meta.get("parent_array_name"):
            record["parent_array_name"] = meta["parent_array_name"]

        members.append(record)

    return members

def _source_header_string(value: str) -> str:
    text = str(value or "")
    return text.replace("\\", "\\\\").replace('"', '\\"')

def _source_table_to_class_name(table_name: str) -> str:
    if table_name.startswith("DT_") and len(table_name) > 3:
        candidate = f"C{table_name[3:]}"
    else:
        candidate = table_name or "Unknown"
    return _source_member_cpp_name_base(
        MemberInfo(name=candidate, offset=0, size=0, type_name="class")
    )

def _source_struct_class_names(struct: StructInfo) -> List[str]:
    aliases = sorted(set(struct.metadata.get("client_classes", [])))
    if aliases:
        return aliases
    return [_source_table_to_class_name(struct.name)]

def _source_sdk_is_vector_name(name: str) -> bool:
    base = str(name or "").split("[", 1)[0]
    return base.startswith(("m_vec", "vec", "m_ang", "ang"))

def _source_sdk_scalar_type(
    prop_name: str,
    recv_type: str,
    cpp_hint: str,
) -> str:
    if prop_name.startswith(("m_clr", "clr")):
        return "Color_t"
    if prop_name.endswith("[0]") and _source_sdk_is_vector_name(prop_name):
        return "Vec3"
    if recv_type == "Vector":
        return "Vec3"
    if recv_type == "VectorXY":
        return "Vec2"
    if cpp_hint == "bool":
        return "bool"
    if cpp_hint == "EHANDLE":
        return "EHANDLE"
    if cpp_hint == "const char*":
        return "const char*"
    if recv_type == "String":
        return "const char*"
    if cpp_hint == "float" or recv_type == "Float":
        return "float"
    if cpp_hint == "std::int64_t" or recv_type == "Int64":
        return "std::int64_t"
    if prop_name.endswith("AccountID") or prop_name == "m_iAccountID":
        return "unsigned"
    if recv_type == "Int" or cpp_hint == "std::int32_t":
        if prop_name.startswith(("m_b", "b")):
            return "bool"
        if prop_name.startswith(("m_h", "h")):
            return "EHANDLE"
        return "int"
    return "void*"

def _source_sdk_member_type(member: Dict[str, Any]) -> str:
    if member["kind"] == "datatable":
        datatable_name = str(member.get("datatable_name", "") or "")
        if datatable_name:
            return f"{_source_table_to_class_name(datatable_name)}*"
        return "void*"

    recv_type = str(member.get("recv_type", member.get("type", "")) or "")
    cpp_hint = str(member.get("cpp_type_hint", member.get("type", "")) or "")
    prop_name = str(member["name"])

    if member["kind"] == "array":
        recv_type = str(member.get("element_type_name", recv_type) or recv_type)
        cpp_hint = cpp_hint if cpp_hint != "array" else recv_type

    return _source_sdk_scalar_type(prop_name, recv_type, cpp_hint)

def _source_sdk_accessor_seed(member: Dict[str, Any]) -> str:
    name = str(member["name"])
    if name.endswith("[0]"):
        return name[:-3]
    return name

def _should_emit_source_sdk_member(member: Dict[str, Any], accessor_seed: str) -> bool:
    if accessor_seed.startswith("unnamed_"):
        return False

    if member["kind"] == "datatable":
        datatable_name = str(member.get("datatable_name", "") or "")
        if datatable_name and not datatable_name.startswith("DT_"):
            return False

    return accessor_seed.startswith("m_") or accessor_seed in _SOURCE_SDK_NON_M_IDENTIFIERS

def _collect_source_sdk_members(struct: StructInfo) -> List[Dict[str, Any]]:
    members = collect_source_members(struct)
    array_names = {member["name"] for member in members if member["kind"] == "array"}
    vector_bases = {
        member["name"][:-3]
        for member in members
        if member["kind"] == "prop"
        and member["name"].endswith("[0]")
        and _source_sdk_is_vector_name(member["name"])
    }

    records: List[Dict[str, Any]] = []
    used_accessor_names = set()

    for member in members:
        parent_array_name = str(member.get("parent_array_name", "") or "")
        if member["kind"] == "prop" and parent_array_name and parent_array_name in array_names:
            continue

        if (
            member["kind"] == "prop"
            and member["name"].endswith(("]"))
            and "[" in member["name"]
        ):
            base_name, index_text = member["name"].rsplit("[", 1)
            index_text = index_text.rstrip("]")
            if base_name in vector_bases and index_text in {"1", "2"}:
                continue

        accessor_seed = _source_sdk_accessor_seed(member)
        if not _should_emit_source_sdk_member(member, accessor_seed):
            continue

        accessor_base = _source_member_cpp_name_base(
            MemberInfo(
                name=accessor_seed,
                offset=member["offset"],
                size=member["size"],
                type_name=str(member.get("type", "")),
            )
        )
        accessor_name = accessor_base
        attempt = 0
        while accessor_name in used_accessor_names:
            suffix = f"_{member['offset']:X}"
            if attempt > 0:
                suffix = f"{suffix}_{attempt}"
            accessor_name = f"{accessor_base}{suffix}"
            attempt += 1
        used_accessor_names.add(accessor_name)

        record = dict(member)
        record["sdk_accessor_name"] = accessor_name
        record["sdk_type"] = _source_sdk_member_type(member)
        record["sdk_lookup_name"] = str(member["name"])
        record["sdk_macro"] = {
            "array": "NETVAR_ARRAY",
            "datatable": "NETVAR_EMBED",
            "prop": "NETVAR",
        }.get(str(member["kind"]), "NETVAR")
        records.append(record)

    return records

def build_source_sdk_header_text(
    struct: StructInfo,
    class_name: str,
    *,
    known_class_names: Optional[set] = None,
    process_name: str = "",
) -> str:
    records = _collect_source_sdk_members(struct)
    base_class = struct.super_name or ""
    known_class_names = known_class_names or set()

    lines = [
        "#pragma once",
    ]

    if base_class and base_class in known_class_names and base_class != class_name:
        lines.extend([f'#include "{base_class}.h"', ""])

    forward_decls = sorted(
        {
            record["sdk_type"][:-1]
            for record in records
            if record["sdk_macro"] == "NETVAR_EMBED"
            and record["sdk_type"].endswith("*")
            and record["sdk_type"] != "void*"
            and record["sdk_type"][:-1] not in {class_name, base_class}
        }
    )
    for decl in forward_decls:
        lines.append(f"class {decl};")
    if forward_decls:
        lines.append("")

    inheritance = f" : public {base_class}" if base_class else ""
    lines.append(f"class {class_name}{inheritance}")
    lines.append("{")
    lines.append("public:")
    if not records:
        lines.append("};")
        return "\n".join(lines) + "\n"

    for record in records:
        lines.append(
            f'\t{record["sdk_macro"]}({record["sdk_accessor_name"]}, '
            f'{record["sdk_type"]}, "{class_name}", "{record["sdk_lookup_name"]}");'
        )
    lines.append("};")
    return "\n".join(lines) + "\n"

def write_source_sdk(
    root_dir: str,
    dump: SDKDump,
    *,
    process_name: str = "",
) -> str:

    validate_source_dump(dump)

    main_dir = os.path.join(root_dir, "Definitions", "Main")
    os.makedirs(main_dir, exist_ok=True)

    class_records = []
    known_class_names = set()
    for struct in sorted(dump.structs, key=lambda item: item.name):
        for class_name in _source_struct_class_names(struct):
            class_records.append((class_name, struct))
            known_class_names.add(class_name)

    for class_name, struct in class_records:
        header_text = build_source_sdk_header_text(
            struct,
            class_name,
            known_class_names=known_class_names,
            process_name=process_name,
        )
        with open(os.path.join(main_dir, f"{class_name}.h"), "w", encoding="utf-8") as handle:
            handle.write(header_text)

    sdk_header_path = os.path.join(root_dir, "SDK.h")
    with open(sdk_header_path, "w", encoding="utf-8") as handle:
        handle.write("#pragma once\n\n")
        for class_name in sorted(known_class_names):
            handle.write(f'#include "Definitions/Main/{class_name}.h"\n')

    return root_dir

def validate_source_dump(dump: SDKDump) -> None:
    for struct in dump.structs:
        if not struct.members:
            continue

        anonymous = 0
        for member in struct.members:
            meta = member.metadata or {}
            raw_name = _source_member_raw_name(member).strip()
            if member.name.startswith("unnamed_"):
                anonymous += 1
                continue
            if raw_name.isdigit():
                parent_array_name = str(meta.get("parent_array_name", "")).strip().strip("\"'")
                if parent_array_name and member.name.startswith(f"{parent_array_name}["):
                    continue
                if "[" in member.name and member.name.endswith("]"):
                    continue
                anonymous += 1

        if struct.name in _SOURCE_KEY_TABLES:
            ratio = anonymous / max(1, len(struct.members))
            has_arrays = any(_source_member_kind(member) == "array" for member in struct.members)
            if ratio >= 0.5 and not has_arrays:
                raise SourceOutputValidationError(
                    f"{struct.name} is still mostly anonymous ({anonymous}/{len(struct.members)} members)."
                )

def validate_source_header_syntax(header_text: str) -> None:
    for line in header_text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("inline constexpr "):
            continue
        if " = " in stripped:
            left = stripped.split(" = ", 1)[0]
        elif "{" in stripped:
            left = stripped.split("{", 1)[0].rstrip()
        else:
            continue
        identifier = left.rsplit(" ", 1)[-1]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", identifier):
            raise SourceOutputValidationError(
                f"Generated header contains an invalid C++ identifier: {identifier}"
            )

def _try_compile_source_header(header_text: str) -> Optional[str]:
    compiler = shutil.which("clang++") or shutil.which("g++")
    cl = None if compiler else shutil.which("cl")
    if not compiler and not cl:
        return None

    with tempfile.TemporaryDirectory() as tmpdir:
        header_path = os.path.join(tmpdir, "source_netvars.hpp")
        test_path = os.path.join(tmpdir, "test.cpp")
        with open(header_path, "w", encoding="utf-8") as header_file:
            header_file.write(header_text)
        with open(test_path, "w", encoding="utf-8") as test_file:
            test_file.write('#include "source_netvars.hpp"\nint main() { return 0; }\n')

        if compiler:
            result = subprocess.run(
                [compiler, "-std=c++17", "-fsyntax-only", test_path],
                capture_output=True,
                text=True,
                cwd=tmpdir,
                timeout=30,
            )
            if result.returncode != 0:
                return result.stderr or result.stdout or "Unknown compiler error"
            return None

        result = subprocess.run(
            ["cmd", "/c", f'cl /nologo /std:c++17 /Zs "{test_path}"'],
            capture_output=True,
            text=True,
            cwd=tmpdir,
            timeout=30,
        )
        if result.returncode != 0:
            return result.stderr or result.stdout or "Unknown compiler error"
        return None

def build_source_header_text(
    dump: SDKDump,
    *,
    process_name: str = "",
) -> str:
    validate_source_dump(dump)

    lines = [
        "// Auto-generated by GameSDK-Kit - Source Engine Netvars",
        f"// Process: {process_name or 'unknown'}",
        f"// Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')}",
        "#pragma once",
        "",
        "#include <cstdint>",
        "",
        "namespace Netvars {",
        "struct PropInfo {",
        "    std::uint32_t offset;",
        "    const char* name;",
        "    const char* raw_name;",
        "    const char* recv_type;",
        "    const char* cpp_type_hint;",
        "    std::uint32_t flags;",
        "};",
        "struct ArrayInfo {",
        "    std::uint32_t offset;",
        "    const char* name;",
        "    const char* raw_name;",
        "    const char* element_type;",
        "    std::uint32_t flags;",
        "    std::uint32_t count;",
        "    std::uint32_t stride;",
        "};",
        "struct TableInfo {",
        "    std::uint32_t offset;",
        "    const char* name;",
        "    const char* raw_name;",
        "    const char* recv_table;",
        "    std::uint32_t flags;",
        "};",
        "",
    ]

    aliases = dict(sorted(((dump.metadata or {}).get("source_aliases", {})).items()))
    if aliases:
        lines.append("namespace ClientClasses {")
        used_aliases = set()
        for class_name, table_name in aliases.items():
            alias = _source_member_cpp_name_base(
                MemberInfo(name=class_name, offset=0, size=0, type_name="alias")
            )
            if alias in used_aliases:
                continue
            used_aliases.add(alias)
            lines.append(
                f'inline constexpr const char* {alias} = "{_source_header_string(table_name)}";'
            )
        lines.extend(["} // namespace ClientClasses", ""])

    for struct in sorted(dump.structs, key=lambda item: item.name):
        namespace_name = _source_member_cpp_name_base(
            MemberInfo(name=struct.name, offset=0, size=0, type_name="table")
        )
        members = collect_source_members(struct)
        lines.append(f"namespace {namespace_name} {{")
        lines.append(f"// RecvTable: {struct.name}")
        client_classes = list(struct.metadata.get("client_classes", []))
        if client_classes:
            lines.append(f"// Client classes: {', '.join(client_classes)}")

        for member in members:
            lines.append(
                f"inline constexpr std::uint32_t {member['cpp_name']} = {member['offset_hex']};"
            )

        lines.append("")
        lines.append("namespace meta {")
        for member in members:
            name = _source_header_string(member["name"])
            raw_name = _source_header_string(member["raw_name"])
            recv_type = _source_header_string(member["recv_type"])
            cpp_hint = _source_header_string(member["cpp_type_hint"])
            if member["kind"] == "array":
                lines.append(
                    "inline constexpr ArrayInfo "
                    f"{member['cpp_name']}{{{member['offset_hex']}, "
                    f"\"{name}\", \"{raw_name}\", "
                    f"\"{_source_header_string(member.get('element_type_name', ''))}\", "
                    f"{member['flags_hex']}, {member.get('elements', 0)}, "
                    f"{member.get('element_stride', 0)}}};"
                )
            elif member["kind"] == "datatable":
                lines.append(
                    "inline constexpr TableInfo "
                    f"{member['cpp_name']}{{{member['offset_hex']}, "
                    f"\"{name}\", \"{raw_name}\", "
                    f"\"{_source_header_string(member.get('datatable_name', ''))}\", "
                    f"{member['flags_hex']}}};"
                )
            else:
                lines.append(
                    "inline constexpr PropInfo "
                    f"{member['cpp_name']}{{{member['offset_hex']}, "
                    f"\"{name}\", \"{raw_name}\", \"{recv_type}\", "
                    f"\"{cpp_hint}\", {member['flags_hex']}}};"
                )
        lines.append("} // namespace meta")
        lines.extend(["", f"}} // namespace {namespace_name}", ""])

    lines.append("} // namespace Netvars")
    header_text = "\n".join(lines) + "\n"

    validate_source_header_syntax(header_text)
    compile_error = _try_compile_source_header(header_text)
    if compile_error:
        raise SourceOutputValidationError(
            f"Generated source_netvars.hpp failed syntax validation:\n{compile_error}"
        )

    return header_text

def write_source_header(
    path: str,
    dump: SDKDump,
    *,
    process_name: str = "",
) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    header_text = build_source_header_text(dump, process_name=process_name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(header_text)

def write_source_dump_json(
    path: str,
    dump: SDKDump,
    *,
    process_name: str = "",
) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    validate_source_dump(dump)

    tables = {}
    total_arrays = 0
    total_datatables = 0
    total_members = 0

    for struct in dump.structs:
        members = collect_source_members(struct)
        total_members += len(members)
        total_arrays += sum(1 for member in members if member["kind"] == "array")
        total_datatables += sum(1 for member in members if member["kind"] == "datatable")

        lookup = {}
        for member in members:
            lookup[member["name"]] = {
                "offset": member["offset"],
                "offset_hex": member["offset_hex"],
                "cpp_name": member["cpp_name"],
                "kind": member["kind"],
                "type": member["type"],
                "flags": member["flags"],
                "flags_hex": member["flags_hex"],
            }

        tables[struct.name] = {
            "client_classes": list(struct.metadata.get("client_classes", [])),
            "members": members,
            "lookup": lookup,
        }

    payload = {
        "credit": {
            "dumper": "GameSDK-Kit",
            "link": "https://github.com/alesxxxx/game-sdk-kit",
        },
        "engine": "source",
        "game": {
            "process": process_name,
            "dump_timestamp": now_iso,
        },
        "summary": {
            "total_tables": len(dump.structs),
            "total_members": total_members,
            "total_arrays": total_arrays,
            "total_datatables": total_datatables,
            "total_aliases": len((dump.metadata or {}).get("source_aliases", {})),
        },
        "aliases": dict(sorted(((dump.metadata or {}).get("source_aliases", {})).items())),
        "netvars": tables,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
