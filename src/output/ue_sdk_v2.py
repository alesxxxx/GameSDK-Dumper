import json
import os
import re
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Set, Tuple


def _sanitize_identifier(name: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_]", "_", str(name or ""))
    if safe and safe[0].isdigit():
        safe = f"_{safe}"
    return safe or "Unknown"


def _align_up(value: int, alignment: int) -> int:
    alignment = max(1, int(alignment or 1))
    return (int(value or 0) + alignment - 1) & ~(alignment - 1)


def _normalize_full_name(full_name: str) -> str:
    text = str(full_name or "").replace("\\", "/").strip()
    text = text.replace("/Script/", "")
    while text.startswith("."):
        text = text[1:]
    return text


def _split_full_name(full_name: str) -> Tuple[str, str]:
    full_name = _normalize_full_name(full_name)
    if "." in full_name:
        package, short_name = full_name.split(".", 1)
        return package, short_name
    return "Global", full_name or "Unknown"


def _symbol_for_full_name(full_name: str) -> str:
    package, short_name = _split_full_name(full_name)
    return f"{_sanitize_identifier(package)}_{_sanitize_identifier(short_name)}"


def _package_symbol(package_name: str) -> str:
    return _sanitize_identifier(package_name or "Global")


def _normalize_type_node(type_node: Optional[dict]) -> None:
    if not type_node:
        return
    if "full_name" in type_node:
        type_node["full_name"] = _normalize_full_name(type_node.get("full_name"))
    if "package" in type_node:
        type_node["package"] = _normalize_full_name(type_node.get("package"))
    for child_key in ("pointee", "inner", "key", "value", "enum_underlying"):
        _normalize_type_node(type_node.get(child_key))


def _infer_enum_underlying(values: List[list]) -> str:
    ints: List[int] = []
    for item in values or []:
        if not isinstance(item, (list, tuple)) or len(item) < 2:
            continue
        try:
            ints.append(int(item[1]))
        except (TypeError, ValueError):
            continue
    if not ints:
        return "uint8_t"
    min_val = min(ints)
    max_val = max(ints)
    if min_val < 0:
        if -0x80 <= min_val and max_val <= 0x7F:
            return "int8_t"
        if -0x8000 <= min_val and max_val <= 0x7FFF:
            return "int16_t"
        if -0x80000000 <= min_val and max_val <= 0x7FFFFFFF:
            return "int32_t"
        return "int64_t"
    if max_val <= 0xFF:
        return "uint8_t"
    if max_val <= 0xFFFF:
        return "uint16_t"
    if max_val <= 0xFFFFFFFF:
        return "uint32_t"
    return "uint64_t"


def _type_width_rank(type_name: str) -> int:
    normalized = str(type_name or "").replace("std::", "")
    ranks = {
        "uint8_t": 1,
        "int8_t": 1,
        "uint16_t": 2,
        "int16_t": 2,
        "uint32_t": 4,
        "int32_t": 4,
        "uint64_t": 8,
        "int64_t": 8,
    }
    return ranks.get(normalized, 0)


def _load_json(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return default


def has_v2_dump(dump_dir: str) -> bool:
    classes = _load_json(os.path.join(dump_dir, "ClassesInfoV2.json"), {})
    structs = _load_json(os.path.join(dump_dir, "StructsInfoV2.json"), {})
    return bool(classes.get("schema_version") == 2 or structs.get("schema_version") == 2)


def _load_v2_struct_entries(dump_dir: str) -> List[dict]:
    entries: List[dict] = []
    for filename in ("ClassesInfoV2.json", "StructsInfoV2.json"):
        payload = _load_json(os.path.join(dump_dir, filename), {})
        if payload.get("schema_version") == 2:
            for entry in payload.get("data", []) or []:
                if not entry:
                    continue
                entry["full_name"] = _normalize_full_name(entry.get("full_name"))
                entry["package"] = _normalize_full_name(entry.get("package"))
                entry["super_full_name"] = _normalize_full_name(entry.get("super_full_name"))
                for member in entry.get("members", []) or []:
                    _normalize_type_node(member.get("type"))
                for function in entry.get("functions", []) or []:
                    _normalize_type_node((function.get("return") or {}).get("type"))
                    for param in function.get("params", []) or []:
                        _normalize_type_node(param.get("type"))
                entries.append(entry)
    return entries


def _load_legacy_enums(dump_dir: str) -> Dict[str, dict]:
    payload = _load_json(os.path.join(dump_dir, "EnumsInfo.json"), {})
    enums: Dict[str, dict] = {}
    for entry in payload.get("data", []) or []:
        if not entry:
            continue
        full_name, values = next(iter(entry.items()))
        full_name = _normalize_full_name(full_name)
        package, short_name = _split_full_name(full_name)
        enums[full_name] = {
            "full_name": full_name,
            "package": package,
            "name": short_name,
            "symbol": _symbol_for_full_name(full_name),
            "values": list(values or []),
            "underlying": _infer_enum_underlying(list(values or [])),
        }
    return enums


def _build_short_name_index(items: Iterable[dict]) -> Dict[str, List[dict]]:
    index: Dict[str, List[dict]] = defaultdict(list)
    for item in items:
        if not item:
            continue
        short_name = item.get("name") or _split_full_name(item.get("full_name", ""))[1]
        if short_name:
            index[short_name].append(item)
    return index


def _unique_short_name_match(short_name: str, index: Dict[str, List[dict]]) -> Optional[dict]:
    matches = index.get(short_name or "", [])
    return matches[0] if len(matches) == 1 else None


def _first_member_offset(entry: dict) -> int:
    members = entry.get("members", []) or []
    if not members:
        return 0
    return min(int(member.get("storage_offset", member.get("offset", 0)) or 0) for member in members)


def _iter_type_refs(type_node: Optional[dict], *, context: str = "direct") -> Iterable[Tuple[str, str, str, Optional[str]]]:
    if not type_node:
        return
    kind = type_node.get("kind", "")
    full_name = type_node.get("full_name", "")
    if kind == "named_struct" and full_name:
        yield ("struct", full_name, context, None)
        return
    if kind == "enum" and full_name:
        enum_underlying = type_node.get("enum_underlying") or {}
        underlying = enum_underlying.get("signature_name") or enum_underlying.get("display_name")
        yield ("enum", full_name, context, underlying)
        return
    if kind in {"object", "class", "soft_object", "soft_class", "weak_object", "lazy_object", "object_ptr", "class_ptr", "interface", "field_path"}:
        yield from _iter_type_refs(type_node.get("pointee"), context="pointer")
        return
    if kind in {"array", "set"}:
        yield from _iter_type_refs(type_node.get("inner"), context="container")
        return
    if kind == "map":
        yield from _iter_type_refs(type_node.get("key"), context="container")
        yield from _iter_type_refs(type_node.get("value"), context="container")


def _tarjan_scc(graph: Dict[str, Set[str]]) -> List[List[str]]:
    index = 0
    stack: List[str] = []
    on_stack: Set[str] = set()
    indexes: Dict[str, int] = {}
    lowlinks: Dict[str, int] = {}
    components: List[List[str]] = []

    def strongconnect(node: str) -> None:
        nonlocal index
        indexes[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)

        for dep in graph.get(node, set()):
            if dep not in indexes:
                strongconnect(dep)
                lowlinks[node] = min(lowlinks[node], lowlinks[dep])
            elif dep in on_stack:
                lowlinks[node] = min(lowlinks[node], indexes[dep])

        if lowlinks[node] == indexes[node]:
            component: List[str] = []
            while stack:
                value = stack.pop()
                on_stack.discard(value)
                component.append(value)
                if value == node:
                    break
            components.append(sorted(component))

    for node in sorted(graph):
        if node not in indexes:
            strongconnect(node)

    return components


def _topological_components(graph: Dict[str, Set[str]]) -> Tuple[List[List[str]], Dict[str, int], Dict[int, Set[int]]]:
    components = _tarjan_scc(graph)
    component_index = {
        node: idx
        for idx, nodes in enumerate(components)
        for node in nodes
    }
    condensed: Dict[int, Set[int]] = defaultdict(set)
    indegree: Dict[int, int] = {idx: 0 for idx in range(len(components))}
    for node, deps in graph.items():
        src = component_index[node]
        for dep in deps:
            dst = component_index[dep]
            if src == dst:
                continue
            if dst not in condensed[src]:
                condensed[src].add(dst)
                indegree[dst] += 1

    ready = sorted(idx for idx, degree in indegree.items() if degree == 0)
    ordered: List[List[str]] = []
    while ready:
        idx = ready.pop(0)
        ordered.append(components[idx])
        for dep in sorted(condensed.get(idx, set())):
            indegree[dep] -= 1
            if indegree[dep] == 0:
                ready.append(dep)
                ready.sort()

    if len(ordered) != len(components):
        ordered = components
    else:
        ordered.reverse()

    # Rebuild component_index so it points into `ordered`, not the pre-sort
    # `components` list. Callers use component_index[node] as an index back into
    # the returned list, so the two must stay in sync after reordering.
    component_index = {
        node: idx
        for idx, nodes in enumerate(ordered)
        for node in nodes
    }

    return ordered, component_index, condensed


def _collect_enum_underlyings(type_entries: List[dict], enums: Dict[str, dict]) -> None:
    def visit_type_node(type_node: Optional[dict]) -> None:
        if not type_node:
            return
        kind = type_node.get("kind")
        if kind == "enum" and type_node.get("full_name") in enums:
            underlying = (
                ((type_node.get("enum_underlying") or {}).get("signature_name"))
                or ((type_node.get("enum_underlying") or {}).get("display_name"))
                or enums[type_node["full_name"]]["underlying"]
            )
            current = enums[type_node["full_name"]]["underlying"]
            enums[type_node["full_name"]]["underlying"] = (
                underlying
                if _type_width_rank(underlying) >= _type_width_rank(current)
                else current
            )
        for child_key in ("pointee", "inner", "key", "value", "enum_underlying"):
            visit_type_node(type_node.get(child_key))

    for entry in type_entries:
        for member in entry.get("members", []) or []:
            visit_type_node(member.get("type"))
        for function in entry.get("functions", []) or []:
            visit_type_node((function.get("return") or {}).get("type"))
            for param in function.get("params", []) or []:
                visit_type_node(param.get("type"))


def _canonical_root_placeholder(name: str) -> str:
    canonical = {
        "Object": "UObject",
        "Class": "UClass",
        "Interface": "UInterface",
        "Function": "UFunction",
    }
    return canonical.get(name or "", "")


def _build_type_index(
    entries: List[dict],
    enums: Dict[str, dict],
) -> Tuple[
    Dict[str, dict],
    Dict[str, List[dict]],
    Dict[str, Set[str]],
    Dict[str, Set[str]],
    Dict[str, Dict[str, str]],
    Dict[str, Dict[str, Set[str]]],
    Dict[str, List[dict]],
    Dict[str, List[dict]],
]:
    types_by_full: Dict[str, dict] = {}
    packages: Dict[str, List[dict]] = defaultdict(list)
    package_graph: Dict[str, Set[str]] = defaultdict(set)
    soft_struct_refs: Dict[str, Set[str]] = defaultdict(set)
    enum_refs: Dict[str, Dict[str, str]] = defaultdict(dict)
    type_graph_by_package: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))

    _collect_enum_underlyings(entries, enums)

    for entry in entries:
        full_name = entry.get("full_name") or ""
        package, short_name = _split_full_name(full_name)
        entry["package"] = package
        entry["name"] = short_name
        entry["symbol"] = _symbol_for_full_name(full_name)
        entry["hard_deps"] = set()
        entry["soft_deps"] = set()
        types_by_full[full_name] = entry
        packages[package].append(entry)

    type_short_index = _build_short_name_index(types_by_full.values())
    enum_short_index = _build_short_name_index(enums.values())

    for entry in entries:
        if entry.get("super_full_name"):
            entry["super_full_name"] = _normalize_full_name(entry.get("super_full_name"))
            continue
        super_name = entry.get("super_name") or ""
        if not super_name:
            continue
        match = _unique_short_name_match(super_name, type_short_index)
        if match is not None:
            entry["super_full_name"] = match["full_name"]

    for entry in entries:
        full_name = entry["full_name"]
        package = entry["package"]
        if entry.get("super_full_name"):
            entry["hard_deps"].add(entry["super_full_name"])
        for member in entry.get("members", []) or []:
            for ref_kind, ref_name, context, underlying in _iter_type_refs(member.get("type")):
                if ref_kind == "enum":
                    enum_refs[package][ref_name] = underlying or enums.get(ref_name, {}).get("underlying", "uint8_t")
                elif context == "direct":
                    entry["hard_deps"].add(ref_name)
                else:
                    entry["soft_deps"].add(ref_name)
        for function in entry.get("functions", []) or []:
            return_type = (function.get("return") or {}).get("type")
            for ref_kind, ref_name, context, underlying in _iter_type_refs(return_type):
                if ref_kind == "enum":
                    enum_refs[package][ref_name] = underlying or enums.get(ref_name, {}).get("underlying", "uint8_t")
                elif context == "direct":
                    entry["hard_deps"].add(ref_name)
                else:
                    entry["soft_deps"].add(ref_name)
            for param in function.get("params", []) or []:
                for ref_kind, ref_name, context, underlying in _iter_type_refs(param.get("type")):
                    if ref_kind == "enum":
                        enum_refs[package][ref_name] = underlying or enums.get(ref_name, {}).get("underlying", "uint8_t")
                    elif context == "direct":
                        entry["hard_deps"].add(ref_name)
                    else:
                        entry["soft_deps"].add(ref_name)

        local_graph = type_graph_by_package[package]
        local_graph.setdefault(full_name, set())
        for dep in sorted(entry["hard_deps"]):
            if dep not in types_by_full:
                continue
            dep_package = types_by_full[dep]["package"]
            if dep_package != package:
                package_graph[package].add(dep_package)
            else:
                local_graph[full_name].add(dep)
        for dep in sorted(entry["soft_deps"]):
            if dep in types_by_full:
                soft_struct_refs[package].add(dep)

    for package in packages:
        package_graph.setdefault(package, set())
        type_graph_by_package.setdefault(package, {})

    return (
        types_by_full,
        packages,
        package_graph,
        soft_struct_refs,
        enum_refs,
        type_graph_by_package,
        type_short_index,
        enum_short_index,
    )


def _opaque_fixup(size_hint: int, align_hint: int) -> str:
    return f"TCycleFixup<0x{max(1, int(size_hint or 1)):X}, 0x{max(1, int(align_hint or 1)):X}>"


def _integral_type_for_size(size_hint: int) -> str:
    size_hint = max(1, int(size_hint or 1))
    return {
        1: "uint8_t",
        2: "uint16_t",
        4: "uint32_t",
        8: "uint64_t",
    }.get(size_hint, _opaque_fixup(size_hint, min(size_hint, 8)))


def _resolve_struct_symbol(
    *,
    full_name: str,
    display_name: str,
    signature_name: str,
    types_by_full: Dict[str, dict],
    type_short_index: Dict[str, List[dict]],
) -> Tuple[str, Optional[dict]]:
    full_name = _normalize_full_name(full_name)
    if full_name and full_name in types_by_full:
        return types_by_full[full_name]["symbol"], types_by_full[full_name]

    candidates: List[str] = []
    if full_name:
        candidates.append(full_name.split(".")[-1])
    for candidate in (signature_name, display_name):
        if candidate and candidate not in candidates:
            candidates.append(candidate)

    for candidate in candidates:
        match = _unique_short_name_match(candidate, type_short_index)
        if match is not None:
            return match["symbol"], match

    for candidate in candidates:
        placeholder = _canonical_root_placeholder(candidate)
        if placeholder:
            return placeholder, None

    return "", None


def _resolve_enum_symbol(
    *,
    full_name: str,
    display_name: str,
    signature_name: str,
    enums: Dict[str, dict],
    enum_short_index: Dict[str, List[dict]],
) -> Tuple[str, Optional[dict]]:
    full_name = _normalize_full_name(full_name)
    if full_name and full_name in enums:
        return enums[full_name]["symbol"], enums[full_name]

    candidates: List[str] = []
    if full_name:
        candidates.append(full_name.split(".")[-1])
    for candidate in (signature_name, display_name):
        if candidate and candidate not in candidates:
            candidates.append(candidate)

    for candidate in candidates:
        match = _unique_short_name_match(candidate, enum_short_index)
        if match is not None:
            return match["symbol"], match

    return "", None


def _fallback_cpp_type(property_class: str, size_hint: int, align_hint: int) -> Tuple[str, bool]:
    property_class = str(property_class or "")
    size_hint = max(0, int(size_hint or 0))
    align_hint = max(1, int(align_hint or 1))

    primitive_fallbacks = {
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
    }
    if property_class in primitive_fallbacks:
        return primitive_fallbacks[property_class], False
    if property_class == "EnumProperty":
        return _integral_type_for_size(size_hint or 1), False
    if property_class == "StructProperty":
        return _opaque_fixup(size_hint or 1, align_hint), True
    if property_class in {"ObjectProperty", "AssetObjectProperty"}:
        return "UObject*", False
    if property_class == "ObjectPtrProperty":
        return "TObjectPtr<UObject>", False
    if property_class == "ClassProperty":
        return "UClass*", False
    if property_class == "ClassPtrProperty":
        return "TObjectPtr<UClass>", False
    if property_class in {"SoftClassProperty", "AssetClassProperty"}:
        return "TSoftClassPtr<UObject>", False
    if property_class == "SoftObjectProperty":
        return "TSoftObjectPtr<UObject>", False
    if property_class == "WeakObjectProperty":
        return "TWeakObjectPtr<UObject>", False
    if property_class == "LazyObjectProperty":
        return "TLazyObjectPtr<UObject>", False
    if property_class == "InterfaceProperty":
        return "TScriptInterface<UInterface>", False
    if property_class == "ArrayProperty":
        return "TArray<uint8_t>", False
    if property_class == "SetProperty":
        return "TSet<uint8_t>", False
    if property_class == "MapProperty":
        return "TMap<uint8_t, uint8_t>", False
    if property_class == "DelegateProperty":
        return "FScriptDelegate", False
    if property_class == "MulticastSparseDelegateProperty":
        return "uint8_t", False
    if property_class in {
        "MulticastDelegateProperty",
        "MulticastInlineDelegateProperty",
    }:
        return "FMulticastScriptDelegate", False
    if property_class == "FieldPathProperty":
        return "TFieldPath<UObject>", False
    if size_hint > 1:
        return _opaque_fixup(size_hint, align_hint), True
    return "uint8_t", False


def _emitted_type_alignment(
    type_node: Optional[dict],
    property_class: str,
    size_hint: int,
    types_by_full: Dict[str, dict],
    type_short_index: Dict[str, List[dict]],
) -> int:
    """Return the natural alignment of the C++ type `_qualified_type_name`
    would emit for this field. This drives the offset-compatibility guard in
    `_emit_struct_body` / `_emit_function_param_structs`: if a dump-reported
    offset cannot satisfy this alignment, the field must be emitted as an
    opaque layout-only wrapper instead.
    """
    if not type_node:
        return 1
    kind = type_node.get("kind") or ""
    size_hint = max(0, int(size_hint or 0))

    if kind == "named_struct":
        full_name = _normalize_full_name(type_node.get("full_name", ""))
        target = types_by_full.get(full_name) if full_name else None
        if target is None:
            # Try short-name match (same resolution path as _resolve_struct_symbol)
            candidates = []
            if full_name:
                candidates.append(full_name.split(".")[-1])
            for cand in (type_node.get("signature_name"), type_node.get("display_name")):
                if cand and cand not in candidates:
                    candidates.append(cand)
            for cand in candidates:
                match = _unique_short_name_match(cand, type_short_index)
                if match is not None:
                    target = match
                    break
        if target is not None:
            layout = target.get("layout") or {}
            return max(1, int(layout.get("min_alignment") or 1))
        return 1

    if kind == "enum":
        # A 1-byte enum (including TEnumAsByte) is 1-aligned; larger enums
        # take the width implied by their size.
        if size_hint <= 1:
            return 1
        if size_hint >= 8:
            return 8
        if size_hint >= 4:
            return 4
        if size_hint >= 2:
            return 2
        return 1

    if kind == "primitive":
        sig = (type_node.get("signature_name") or "").replace("std::", "")
        primitives = {
            "bool": 1, "char": 1, "uint8_t": 1, "int8_t": 1,
            "uint16_t": 2, "int16_t": 2,
            "uint32_t": 4, "int32_t": 4, "float": 4,
            "uint64_t": 8, "int64_t": 8, "double": 8,
            "FName": 4,
            "FString": 8, "FText": 8,
        }
        if sig in primitives:
            return primitives[sig]
        return max(1, int(type_node.get("align") or 1))

    if kind == "opaque":
        if size_hint > 1:
            return max(1, int(type_node.get("align") or 1))
        return 1

    # Pointer-ish or container-ish types
    pointer_like_8 = {
        "object", "object_ptr", "class", "class_ptr",
        "soft_object", "soft_class", "interface", "field_path",
        "array", "set", "map",
    }
    if kind in pointer_like_8:
        return 8
    if kind == "weak_object":
        return 4
    if kind == "lazy_object":
        return 4
    if kind == "delegate":
        return 1 if size_hint <= 1 else 8
    if kind == "multicast_delegate":
        if property_class == "MulticastSparseDelegateProperty" or size_hint <= 1:
            return 1
        return 8

    return max(1, int(type_node.get("align") or 1))


def _effective_field_alignment(type_node: Optional[dict], property_class: str, size_hint: int, default_align: int = 1) -> int:
    property_class = str(property_class or "")
    size_hint = max(1, int(size_hint or 1))
    explicit_align = int((type_node or {}).get("align") or 0)
    primitive_alignments = {
        "BoolProperty": 1,
        "ByteProperty": 1,
        "Int8Property": 1,
        "Int16Property": 2,
        "UInt16Property": 2,
        "IntProperty": 4,
        "UInt32Property": 4,
        "FloatProperty": 4,
        "NameProperty": 4,
        "Int64Property": 8,
        "UInt64Property": 8,
        "DoubleProperty": 8,
        "StrProperty": 8,
        "TextProperty": 8,
    }

    if property_class == "MulticastSparseDelegateProperty":
        return 1
    if property_class == "StructProperty":
        return max(1, explicit_align or int(default_align or 1))
    if property_class == "EnumProperty":
        if size_hint >= 8:
            return 8
        if size_hint >= 4:
            return 4
        if size_hint >= 2:
            return 2
        return 1
    if property_class in primitive_alignments:
        return primitive_alignments[property_class]
    if property_class in {
        "ObjectProperty",
        "AssetObjectProperty",
        "ObjectPtrProperty",
        "ClassProperty",
        "ClassPtrProperty",
        "SoftClassProperty",
        "AssetClassProperty",
        "SoftObjectProperty",
        "WeakObjectProperty",
        "LazyObjectProperty",
        "InterfaceProperty",
        "DelegateProperty",
        "MulticastDelegateProperty",
        "MulticastInlineDelegateProperty",
        "FieldPathProperty",
        "ArrayProperty",
        "SetProperty",
        "MapProperty",
    }:
        return 8
    if explicit_align > 0:
        return explicit_align
    if size_hint >= 8:
        return 8
    if size_hint >= 4:
        return 4
    if size_hint >= 2:
        return 2
    return max(1, int(default_align or 1))


def _qualified_type_name(
    type_node: Optional[dict],
    *,
    current_package: str,
    types_by_full: Dict[str, dict],
    enums: Dict[str, dict],
    type_short_index: Dict[str, List[dict]],
    enum_short_index: Dict[str, List[dict]],
    same_scc_packages: Set[str],
    emitted_symbols: Set[str],
    direct_value_context: bool,
    property_class: str = "",
    size_hint: int = 0,
    align_hint: int = 1,
) -> Tuple[str, bool]:
    if not type_node:
        return _fallback_cpp_type(property_class, size_hint, align_hint)

    kind = type_node.get("kind")
    signature_name = type_node.get("signature_name") or type_node.get("display_name") or "void"
    size_hint = max(int(type_node.get("size") or 0), int(size_hint or 0))
    align_hint = int(type_node.get("align") or align_hint or 1)

    if kind == "named_struct":
        symbol, target = _resolve_struct_symbol(
            full_name=type_node.get("full_name", ""),
            display_name=type_node.get("display_name", ""),
            signature_name=signature_name,
            types_by_full=types_by_full,
            type_short_index=type_short_index,
        )
        if not symbol:
            return _fallback_cpp_type(property_class or "StructProperty", size_hint, align_hint)
        if target is None:
            return symbol, False
        if direct_value_context:
            if target["package"] == current_package:
                if symbol in emitted_symbols:
                    return symbol, False
                return _opaque_fixup(
                    int(target.get("size", 0) or size_hint or 1),
                    int(((target.get("layout") or {}).get("min_alignment") or align_hint or 1)),
                ), True
            if target["package"] in same_scc_packages:
                return _opaque_fixup(
                    int(target.get("size", 0) or size_hint or 1),
                    int(((target.get("layout") or {}).get("min_alignment") or align_hint or 1)),
                ), True
        return symbol, False

    if kind == "enum":
        symbol, enum_info = _resolve_enum_symbol(
            full_name=type_node.get("full_name", ""),
            display_name=type_node.get("display_name", ""),
            signature_name=signature_name,
            enums=enums,
            enum_short_index=enum_short_index,
        )
        if symbol:
            underlying = (enum_info or {}).get("underlying", "uint8_t")
            if int(size_hint or 0) == 1 and _type_width_rank(underlying) > 1:
                return f"TEnumAsByte<{symbol}>", False
            return symbol, False
        if enum_info is not None:
            return enum_info.get("underlying", "uint8_t"), False
        return _fallback_cpp_type(property_class or "EnumProperty", size_hint or 1, align_hint)

    if kind in {"primitive", "opaque"}:
        if kind == "opaque" and size_hint > 1:
            return _opaque_fixup(size_hint, align_hint), True
        if signature_name and signature_name != "void":
            return signature_name, False
        return _fallback_cpp_type(property_class, size_hint, align_hint)

    if kind in {"object", "object_ptr", "class", "class_ptr", "soft_object", "soft_class", "weak_object", "lazy_object", "interface", "field_path"}:
        pointee, _ = _qualified_type_name(
            type_node.get("pointee"),
            current_package=current_package,
            types_by_full=types_by_full,
            enums=enums,
            type_short_index=type_short_index,
            enum_short_index=enum_short_index,
            same_scc_packages=same_scc_packages,
            emitted_symbols=emitted_symbols,
            direct_value_context=False,
            size_hint=8,
            align_hint=8,
        )
        if kind == "object":
            return f"{pointee}*", False
        if kind == "object_ptr":
            return f"TObjectPtr<{pointee}>", False
        if kind == "class_ptr":
            return "TObjectPtr<UClass>", False
        if kind == "class":
            if (type_node.get("metadata") or {}).get("is_subclass_of"):
                return f"TSubclassOf<{pointee}>", False
            return "UClass*", False
        if kind == "soft_object":
            return f"TSoftObjectPtr<{pointee}>", False
        if kind == "soft_class":
            return f"TSoftClassPtr<{pointee}>", False
        if kind == "weak_object":
            return f"TWeakObjectPtr<{pointee}>", False
        if kind == "lazy_object":
            return f"TLazyObjectPtr<{pointee}>", False
        if kind == "interface":
            return f"TScriptInterface<{pointee}>", False
        if kind == "field_path":
            return f"TFieldPath<{pointee}>", False

    if kind == "array":
        inner, _ = _qualified_type_name(
            type_node.get("inner"),
            current_package=current_package,
            types_by_full=types_by_full,
            enums=enums,
            type_short_index=type_short_index,
            enum_short_index=enum_short_index,
            same_scc_packages=same_scc_packages,
            emitted_symbols=emitted_symbols,
            direct_value_context=False,
            size_hint=max(1, size_hint),
            align_hint=align_hint,
        )
        return f"TArray<{inner}>", False

    if kind == "set":
        inner, _ = _qualified_type_name(
            type_node.get("inner"),
            current_package=current_package,
            types_by_full=types_by_full,
            enums=enums,
            type_short_index=type_short_index,
            enum_short_index=enum_short_index,
            same_scc_packages=same_scc_packages,
            emitted_symbols=emitted_symbols,
            direct_value_context=False,
            size_hint=max(1, size_hint),
            align_hint=align_hint,
        )
        return f"TSet<{inner}>", False

    if kind == "map":
        key, _ = _qualified_type_name(
            type_node.get("key"),
            current_package=current_package,
            types_by_full=types_by_full,
            enums=enums,
            type_short_index=type_short_index,
            enum_short_index=enum_short_index,
            same_scc_packages=same_scc_packages,
            emitted_symbols=emitted_symbols,
            direct_value_context=False,
            size_hint=max(1, size_hint),
            align_hint=align_hint,
        )
        value, _ = _qualified_type_name(
            type_node.get("value"),
            current_package=current_package,
            types_by_full=types_by_full,
            enums=enums,
            type_short_index=type_short_index,
            enum_short_index=enum_short_index,
            same_scc_packages=same_scc_packages,
            emitted_symbols=emitted_symbols,
            direct_value_context=False,
            size_hint=max(1, size_hint),
            align_hint=align_hint,
        )
        return f"TMap<{key}, {value}>", False

    if kind == "delegate":
        if size_hint <= 1:
            return _fallback_cpp_type(property_class or "DelegateProperty", size_hint, align_hint)
        return "FScriptDelegate", False
    if kind == "multicast_delegate":
        if property_class == "MulticastSparseDelegateProperty" or size_hint <= 1:
            return _fallback_cpp_type(property_class or "MulticastSparseDelegateProperty", size_hint, align_hint)
        return "FMulticastScriptDelegate", False

    if signature_name and signature_name != "void":
        return signature_name, False
    return _fallback_cpp_type(property_class, size_hint, align_hint)


def _emit_field_declaration(cpp_type: str, field_name: str, *, array_dim: int = 1, comment: str = "") -> str:
    field_name = _sanitize_identifier(field_name)
    suffix = f"[{array_dim}]" if array_dim > 1 else ""
    tail = f" // {comment}" if comment else ""
    return f"    {cpp_type} {field_name}{suffix};{tail}\n"


def _emit_padding(name: str, offset: int, size: int) -> str:
    return f"    uint8_t {name}[0x{size:X}]; // 0x{offset:04X}\n"


def _emit_bitfield_group(group: List[dict], storage_offset: int) -> str:
    lines: List[str] = []
    cursor = 0
    used_names: Set[str] = set()
    group = sorted(group, key=lambda item: (item["bool_meta"]["bit_index"], item["name"]))
    for index, member in enumerate(group):
        bit_index = int((member.get("bool_meta") or {}).get("bit_index", -1))
        if bit_index < 0:
            continue
        if bit_index > cursor:
            lines.append(
                f"    uint8_t pad_bits_{storage_offset:04X}_{index} : {bit_index - cursor};\n"
            )
        field_name = _dedupe_field_name(member["name"], used_names)
        lines.append(
            f"    uint8_t {field_name} : 1; // 0x{storage_offset:04X} bit {bit_index}\n"
        )
        cursor = bit_index + 1
    if cursor < 8:
        lines.append(
            f"    uint8_t pad_bits_{storage_offset:04X}_tail : {8 - cursor};\n"
        )
    return "".join(lines)


def _emit_struct_body(
    type_entry: dict,
    *,
    current_package: str,
    types_by_full: Dict[str, dict],
    enums: Dict[str, dict],
    type_short_index: Dict[str, List[dict]],
    enum_short_index: Dict[str, List[dict]],
    same_scc_packages: Set[str],
    emitted_symbols: Set[str],
) -> Tuple[str, List[Tuple[str, int]]]:
    layout = type_entry.get("layout") or {}
    members = sorted(
        type_entry.get("members", []) or [],
        key=lambda member: (
            int(member.get("storage_offset", member.get("offset", 0))),
            int((member.get("bool_meta") or {}).get("bit_index", 0)),
            member.get("name", ""),
        ),
    )
    lines: List[str] = []
    assertions: List[Tuple[str, int]] = []
    used_field_names: Set[str] = set()

    super_full_name = type_entry.get("super_full_name") or ""
    super_entry = types_by_full.get(super_full_name) if super_full_name else None
    reuse_super_tail = bool(layout.get("reuses_super_tail_padding")) and super_entry is not None
    current_offset = 0
    if super_entry is not None:
        if reuse_super_tail:
            used_size = int((super_entry.get("layout") or {}).get("last_member_end") or super_entry.get("size") or 0)
            lines.append(
                f"    TCycleFixup<0x{used_size:X}, 0x1> Super; // logical base: {super_entry['symbol']}\n"
            )
            current_offset = used_size
        else:
            current_offset = int((super_entry.get("layout") or {}).get("aligned_size") or super_entry.get("size") or 0)

    idx = 0
    while idx < len(members):
        member = members[idx]
        storage_offset = int(member.get("storage_offset", member.get("offset", 0)))
        bool_meta = member.get("bool_meta") or {}
        is_packed_bool = bool_meta and not bool(bool_meta.get("is_native"))

        if storage_offset > current_offset:
            pad = storage_offset - current_offset
            lines.append(_emit_padding(f"pad_{current_offset:04X}", current_offset, pad))
            current_offset = storage_offset

        if is_packed_bool:
            group: List[dict] = []
            group_offset = storage_offset
            while idx < len(members):
                candidate = members[idx]
                candidate_meta = candidate.get("bool_meta") or {}
                if not candidate_meta or bool(candidate_meta.get("is_native")):
                    break
                candidate_offset = int(candidate.get("storage_offset", candidate.get("offset", 0)))
                if candidate_offset != group_offset:
                    break
                group.append(candidate)
                idx += 1
            lines.append(_emit_bitfield_group(group, group_offset))
            current_offset = group_offset + 1
            continue

        type_node = member.get("type") or {}
        member_offset = int(member.get("offset", 0))
        member_size = max(1, int(member.get("size", 1)))
        member_property_class = member.get("property_class", "")
        array_dim = int(member.get("array_dim", 1) or 1)
        # member.size is the TOTAL field size (including array_dim); the type
        # description corresponds to a single element, so derive per-element
        # size for type/alignment computations.
        element_size = max(1, member_size // array_dim) if array_dim > 1 else member_size
        cpp_type, _ = _qualified_type_name(
            type_node,
            current_package=current_package,
            types_by_full=types_by_full,
            enums=enums,
            type_short_index=type_short_index,
            enum_short_index=enum_short_index,
            same_scc_packages=same_scc_packages,
            emitted_symbols=emitted_symbols,
            direct_value_context=True,
            property_class=member_property_class,
            size_hint=element_size,
            align_hint=int((type_node.get("align") if type_node else 0) or 1),
        )
        # Guard: if the emitted C++ type declares an alignment stronger than
        # the real field offset can satisfy, swap in an opaque layout-only
        # wrapper. This handles cases where UE packed a struct with a by-value
        # member whose natural C++ alignment would otherwise push the offset
        # forward (FScriptDelegate@4, by-value nested struct at mis-aligned
        # offset, TFieldPath/TSoftObjectPtr at non-8 offsets, etc.).
        emitted_align = _emitted_type_alignment(
            type_node,
            member_property_class,
            element_size,
            types_by_full,
            type_short_index,
        )
        if emitted_align > 1 and (member_offset % emitted_align) != 0:
            cpp_type = _opaque_fixup(element_size, 1)
        comment = f"0x{member_offset:04X}"
        emitted_name = _dedupe_field_name(member.get("name", "Field"), used_field_names)
        lines.append(
            _emit_field_declaration(
                cpp_type,
                emitted_name,
                array_dim=array_dim,
                comment=comment,
            )
        )
        assertions.append((emitted_name, member_offset))
        current_offset = storage_offset + member_size
        idx += 1

    struct_size = int(type_entry.get("size", 0))
    if struct_size > current_offset:
        lines.append(_emit_padding(f"pad_{current_offset:04X}", current_offset, struct_size - current_offset))

    return "".join(lines), assertions


def _format_signature_param(
    param: dict,
    *,
    current_package: str,
    types_by_full: Dict[str, dict],
    enums: Dict[str, dict],
    type_short_index: Dict[str, List[dict]],
    enum_short_index: Dict[str, List[dict]],
    same_scc_packages: Set[str],
    emitted_symbols: Set[str],
    is_return: bool,
) -> str:
    cpp_type, _ = _qualified_type_name(
        param.get("type"),
        current_package=current_package,
        types_by_full=types_by_full,
        enums=enums,
        type_short_index=type_short_index,
        enum_short_index=enum_short_index,
        same_scc_packages=same_scc_packages,
        emitted_symbols=emitted_symbols,
        direct_value_context=False,
        property_class=param.get("property_class", ""),
        size_hint=int(param.get("size", 0) or 0),
        align_hint=int(((param.get("type") or {}).get("align") or 1)),
    )
    qualifiers = param.get("qualifiers") or {}
    if qualifiers.get("const") and not cpp_type.startswith("const "):
        cpp_type = f"const {cpp_type}"
    if not is_return and (qualifiers.get("ref") or qualifiers.get("out")):
        cpp_type = f"{cpp_type}&"
    if is_return:
        return cpp_type
    return f"{cpp_type} {_sanitize_identifier(param.get('name', 'Param'))}"


def _format_function_signature(
    function: dict,
    *,
    current_package: str,
    types_by_full: Dict[str, dict],
    enums: Dict[str, dict],
    type_short_index: Dict[str, List[dict]],
    enum_short_index: Dict[str, List[dict]],
    same_scc_packages: Set[str],
    emitted_symbols: Set[str],
) -> str:
    return_info = function.get("return") or None
    return_type = "void"
    if return_info:
        return_type = _format_signature_param(
            return_info,
            current_package=current_package,
            types_by_full=types_by_full,
            enums=enums,
            type_short_index=type_short_index,
            enum_short_index=enum_short_index,
            same_scc_packages=same_scc_packages,
            emitted_symbols=emitted_symbols,
            is_return=True,
        )
    params = [
        _format_signature_param(
            param,
            current_package=current_package,
            types_by_full=types_by_full,
            enums=enums,
            type_short_index=type_short_index,
            enum_short_index=enum_short_index,
            same_scc_packages=same_scc_packages,
            emitted_symbols=emitted_symbols,
            is_return=False,
        )
        for param in function.get("params", []) or []
        if not ((param.get("qualifiers") or {}).get("return"))
    ]
    return f"{return_type} {function.get('name', 'Function')}({', '.join(params)})"


def _emit_function_param_structs(
    type_entry: dict,
    *,
    current_package: str,
    types_by_full: Dict[str, dict],
    enums: Dict[str, dict],
    type_short_index: Dict[str, List[dict]],
    enum_short_index: Dict[str, List[dict]],
    same_scc_packages: Set[str],
    emitted_symbols: Set[str],
) -> str:
    lines: List[str] = []
    type_symbol = type_entry["symbol"]
    for function in type_entry.get("functions", []) or []:
        params = sorted(
            function.get("params", []) or [],
            key=lambda param: (
                int(param.get("storage_offset", param.get("offset", 0))),
                int(((param.get("bool_meta") or {}).get("bit_index", 0))),
                param.get("name", ""),
            ),
        )
        if not params and function.get("return") is None:
            continue
        struct_name = f"{type_symbol}_{_sanitize_identifier(function['name'])}_Params"
        max_alignment = 1
        lines.append(
            f"// Signature: {_format_function_signature(function, current_package=current_package, types_by_full=types_by_full, enums=enums, type_short_index=type_short_index, enum_short_index=enum_short_index, same_scc_packages=same_scc_packages, emitted_symbols=emitted_symbols)}\n"
        )
        lines.append("#pragma pack(push, 0x1)\n")
        lines.append(f"struct {struct_name} {{\n")
        current_offset = 0
        used_field_names: Set[str] = set()
        idx = 0
        while idx < len(params):
            param = params[idx]
            storage_offset = int(param.get("storage_offset", param.get("offset", 0)))
            bool_meta = param.get("bool_meta") or {}
            is_packed_bool = bool_meta and not bool(bool_meta.get("is_native"))
            if storage_offset > current_offset:
                pad = storage_offset - current_offset
                lines.append(_emit_padding(f"pad_{current_offset:04X}", current_offset, pad))
                current_offset = storage_offset
            if is_packed_bool:
                group: List[dict] = []
                group_offset = storage_offset
                while idx < len(params):
                    candidate = params[idx]
                    candidate_meta = candidate.get("bool_meta") or {}
                    if not candidate_meta or bool(candidate_meta.get("is_native")):
                        break
                    candidate_offset = int(candidate.get("storage_offset", candidate.get("offset", 0)))
                    if candidate_offset != group_offset:
                        break
                    group.append(candidate)
                    idx += 1
                lines.append(_emit_bitfield_group(group, group_offset))
                current_offset = group_offset + 1
                max_alignment = max(max_alignment, 1)
                continue

            type_node = param.get("type") or {}
            param_offset = int(param.get("offset", 0))
            param_size = max(1, int(param.get("size", 1)))
            param_property_class = param.get("property_class", "")
            param_array_dim = int(param.get("array_dim", 1) or 1)
            element_size = max(1, param_size // param_array_dim) if param_array_dim > 1 else param_size
            cpp_type, _ = _qualified_type_name(
                type_node,
                current_package=current_package,
                types_by_full=types_by_full,
                enums=enums,
                type_short_index=type_short_index,
                enum_short_index=enum_short_index,
                same_scc_packages=same_scc_packages,
                emitted_symbols=emitted_symbols,
                direct_value_context=True,
                property_class=param_property_class,
                size_hint=element_size,
                align_hint=int((type_node.get("align") if type_node else 0) or 1),
            )
            emitted_align = _emitted_type_alignment(
                type_node,
                param_property_class,
                element_size,
                types_by_full,
                type_short_index,
            )
            if emitted_align > 1 and (param_offset % emitted_align) != 0:
                cpp_type = _opaque_fixup(element_size, 1)
                max_alignment = max(max_alignment, 1)
            else:
                max_alignment = max(max_alignment, emitted_align)
            lines.append(
                _emit_field_declaration(
                    cpp_type,
                    _dedupe_field_name(param.get("name", "Param"), used_field_names),
                    comment=f"0x{param_offset:04X} flags={param.get('flags', '0x0')}",
                )
            )
            current_offset = storage_offset + param_size
            idx += 1
        aligned_offset = _align_up(current_offset, max_alignment)
        if aligned_offset > current_offset:
            lines.append(_emit_padding(f"pad_{current_offset:04X}", current_offset, aligned_offset - current_offset))
            current_offset = aligned_offset

        lines.append("};\n")
        lines.append("#pragma pack(pop)\n")
        lines.append(f"static_assert(sizeof({struct_name}) == 0x{current_offset:X});\n\n")
    return "".join(lines)


def _emit_runtime_headers(out_dir: str) -> None:
    basic_path = os.path.join(out_dir, "Basic.hpp")
    with open(basic_path, "w", encoding="utf-8") as f:
        f.write("#pragma once\n")
        f.write("#include <cstddef>\n")
        f.write("#include <cstdint>\n\n")
        f.write("namespace sdk {\n\n")
        f.write("struct UObject;\nstruct UClass;\nstruct UInterface;\nstruct UFunction;\n\n")
        f.write("template<std::size_t Size, std::size_t Align = 1>\n")
        f.write("struct alignas(Align) TCycleFixup {\n    std::uint8_t Data[Size == 0 ? 1 : Size];\n};\n\n")
        f.write("struct FName {\n    std::int32_t ComparisonIndex;\n    std::int32_t Number;\n};\n")
        f.write("static_assert(sizeof(FName) == 0x8);\n\n")
        f.write("struct FString {\n    wchar_t* Data;\n    std::int32_t Num;\n    std::int32_t Max;\n};\n")
        f.write("static_assert(sizeof(FString) == 0x10);\n\n")
        f.write("struct alignas(8) FText {\n    std::uint8_t Data[0x18];\n};\n")
        f.write("static_assert(sizeof(FText) == 0x18);\n\n")
        f.write("struct alignas(8) FScriptDelegate {\n    std::uint8_t Data[0x10];\n};\n")
        f.write("struct alignas(8) FMulticastScriptDelegate {\n    std::uint8_t Data[0x10];\n};\n\n")
        f.write("template<typename T>\nstruct TEnumAsByte {\n    std::uint8_t Value;\n};\n\n")
        f.write("template<typename T>\nstruct TObjectPtr {\n    T* Object;\n};\n")
        f.write("template<typename T>\nstruct TSubclassOf {\n    UClass* Class;\n};\n\n")
        f.write("} // namespace sdk\n")

    containers_path = os.path.join(out_dir, "UnrealContainers.hpp")
    with open(containers_path, "w", encoding="utf-8") as f:
        f.write("#pragma once\n")
        f.write('#include "Basic.hpp"\n\n')
        f.write("namespace sdk {\n\n")
        f.write("template<typename T>\nstruct TArray {\n    T* Data;\n    std::int32_t Num;\n    std::int32_t Max;\n};\n")
        f.write("static_assert(sizeof(TArray<int>) == 0x10);\n\n")
        f.write("template<typename K, typename V>\nstruct TPair {\n    K Key;\n    V Value;\n};\n\n")
        f.write("template<typename T>\nstruct alignas(4) TWeakObjectPtr {\n    std::int32_t ObjectIndex;\n    std::int32_t ObjectSerialNumber;\n};\n")
        f.write("template<typename T>\nstruct alignas(4) TLazyObjectPtr {\n    std::uint8_t Data[0x1C];\n};\n")
        f.write("template<typename T>\nstruct alignas(8) TSoftObjectPtr {\n    std::uint8_t Data[0x28];\n};\n")
        f.write("template<typename T>\nstruct alignas(8) TSoftClassPtr {\n    TSoftObjectPtr<T> Value;\n};\n")
        f.write("template<typename T>\nstruct TScriptInterface {\n    T* ObjectPointer;\n    void* InterfacePointer;\n};\n")
        f.write("template<typename T>\nstruct alignas(8) TFieldPath {\n    std::uint8_t Data[0x20];\n};\n")
        f.write("template<typename T>\nstruct alignas(8) TSet {\n    std::uint8_t Data[0x50];\n};\n")
        f.write("template<typename K, typename V>\nstruct alignas(8) TMap {\n    std::uint8_t Data[0x50];\n};\n\n")
        f.write("} // namespace sdk\n")


def _entry_effective_alignment(
    entry: dict,
    types_by_full: Dict[str, dict],
    _seen: Optional[Set[str]] = None,
) -> int:
    if _seen is None:
        _seen = set()
    entry_key = entry.get("full_name") or entry.get("symbol") or ""
    if entry_key in _seen:
        return max(1, int((entry.get("layout") or {}).get("min_alignment") or 1))
    _seen = set(_seen)
    _seen.add(entry_key)

    alignment = 1
    layout = entry.get("layout") or {}
    alignment = max(alignment, int(layout.get("min_alignment") or 1))
    super_full_name = _normalize_full_name(entry.get("super_full_name", ""))
    if super_full_name and super_full_name in types_by_full:
        alignment = max(alignment, _entry_effective_alignment(types_by_full[super_full_name], types_by_full, _seen))
    for member in entry.get("members", []) or []:
        type_node = member.get("type") or {}
        if type_node.get("kind") == "named_struct":
            ref_full_name = _normalize_full_name(type_node.get("full_name", ""))
            if ref_full_name and ref_full_name in types_by_full:
                alignment = max(alignment, _entry_effective_alignment(types_by_full[ref_full_name], types_by_full, _seen))
                continue
        alignment = max(
            alignment,
            _effective_field_alignment(
                type_node,
                member.get("property_class", ""),
                int(member.get("size", 0) or 0),
                int((type_node.get("align") if type_node else 0) or 1),
            ),
        )
    return alignment


def _dedupe_enum_member_name(name: str, used: Set[str]) -> str:
    base = _sanitize_identifier(str(name or "").split("::")[-1])
    candidate = base
    suffix = 1
    while candidate in used:
        candidate = f"{base}_{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def _dedupe_field_name(name: str, used: Set[str]) -> str:
    base = _sanitize_identifier(name)
    candidate = base
    suffix = 1
    while candidate in used:
        candidate = f"{base}_{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def _emit_package_header(
    path: str,
    *,
    package_name: str,
    entries: List[dict],
    package_includes: List[str],
    forward_structs: List[str],
    forward_enums: List[Tuple[str, str]],
    types_by_full: Dict[str, dict],
    enums: Dict[str, dict],
    type_short_index: Dict[str, List[dict]],
    enum_short_index: Dict[str, List[dict]],
    same_scc_packages: Set[str],
    type_graph: Dict[str, Set[str]],
) -> None:
    ordered_type_groups, _, _ = _topological_components(type_graph)
    emitted_symbols: Set[str] = set()
    with open(path, "w", encoding="utf-8") as f:
        f.write("#pragma once\n")
        f.write('#include "Basic.hpp"\n')
        f.write('#include "UnrealContainers.hpp"\n')
        for include_name in package_includes:
            f.write(f'#include "{include_name}.hpp"\n')
        f.write("\nnamespace sdk {\n\n")

        local_entry_symbols = {entry["symbol"] for entry in entries}
        local_enums = sorted(
            (enum_info for enum_info in enums.values() if enum_info["package"] == package_name),
            key=lambda item: item["symbol"],
        )

        for symbol, underlying in forward_enums:
            if all(enum_info["symbol"] != symbol for enum_info in local_enums):
                f.write(f"enum class {symbol} : {underlying};\n")
        for symbol in forward_structs:
            f.write(f"struct {symbol};\n")
        if forward_enums or forward_structs:
            f.write("\n")

        for enum_info in local_enums:
            f.write(f"enum class {enum_info['symbol']} : {enum_info['underlying']} {{\n")
            used_enum_members: Set[str] = set()
            for name, value in enum_info["values"]:
                safe_name = _dedupe_enum_member_name(name, used_enum_members)
                f.write(f"    {safe_name} = {value},\n")
            f.write("};\n\n")

        entry_lookup = {entry["full_name"]: entry for entry in entries}
        for component in ordered_type_groups:
            for full_name in component:
                if full_name not in entry_lookup:
                    continue
                entry = entry_lookup[full_name]
                layout = entry.get("layout") or {}
                # Trust the dump's recorded min_alignment. Inflating via member
                # types produced alignas values incompatible with the actual
                # packed size (e.g. alignas(8) on a 0x1C struct). The per-field
                # emission guard below rewrites any member whose offset cannot
                # satisfy its natural alignment.
                align = max(1, int(layout.get("min_alignment") or 1))
                struct_size = int(entry.get("size", 0))
                while align > 1 and struct_size > 0 and (struct_size % align) != 0:
                    align //= 2

                symbol = entry["symbol"]
                super_full_name = entry.get("super_full_name") or ""
                super_entry = types_by_full.get(super_full_name) if super_full_name else None
                reuse_super_tail = bool(layout.get("reuses_super_tail_padding")) and super_entry is not None

                f.write("#pragma pack(push, 0x1)\n")
                inheritance = ""
                if super_entry is not None and not reuse_super_tail:
                    inheritance = f" : public {super_entry['symbol']}"
                f.write(f"struct alignas(0x{align:X}) {symbol}{inheritance} {{\n")
                body, assertions = _emit_struct_body(
                    entry,
                    current_package=package_name,
                    types_by_full=types_by_full,
                    enums=enums,
                    type_short_index=type_short_index,
                    enum_short_index=enum_short_index,
                    same_scc_packages=same_scc_packages,
                    emitted_symbols=emitted_symbols,
                )
                f.write(body)
                f.write("};\n")
                f.write("#pragma pack(pop)\n")
                f.write(f"static_assert(sizeof({symbol}) == 0x{int(entry.get('size', 0)):X});\n")
                f.write(f"static_assert(alignof({symbol}) == 0x{align:X});\n")
                for field_name, offset in assertions:
                    safe_name = _sanitize_identifier(field_name)
                    if safe_name == "Super":
                        continue
                    f.write(f"static_assert(offsetof({symbol}, {safe_name}) == 0x{offset:X});\n")
                f.write("\n")
                emitted_symbols.add(symbol)

            for full_name in component:
                if full_name not in entry_lookup:
                    continue
                entry = entry_lookup[full_name]
                f.write(
                    _emit_function_param_structs(
                        entry,
                        current_package=package_name,
                        types_by_full=types_by_full,
                        enums=enums,
                        type_short_index=type_short_index,
                        enum_short_index=enum_short_index,
                        same_scc_packages=same_scc_packages,
                        emitted_symbols=emitted_symbols,
                    )
                )

        f.write("} // namespace sdk\n")


def generate_v2_package_headers(dump_dir: str, out_dir: str) -> List[str]:
    entries = _load_v2_struct_entries(dump_dir)
    enums = _load_legacy_enums(dump_dir)
    if not entries:
        return []

    (
        types_by_full,
        packages,
        package_graph,
        soft_struct_refs,
        enum_refs,
        type_graph_by_package,
        type_short_index,
        enum_short_index,
    ) = _build_type_index(entries, enums)
    ordered_package_groups, package_component_index, _ = _topological_components(package_graph)
    package_scc_by_name = {
        package_name: set(ordered_package_groups[package_component_index[package_name]])
        for package_name in package_component_index
    }

    package_names: List[str] = []
    for package_group in ordered_package_groups:
        for package_name in package_group:
            package_symbol = _package_symbol(package_name)
            package_names.append(package_symbol)
            same_scc_packages = package_scc_by_name.get(package_name, {package_name})
            include_names = sorted(
                _package_symbol(dep)
                for dep in package_graph.get(package_name, set())
                if dep not in same_scc_packages
            )
            forward_structs = sorted(
                {
                    types_by_full[dep]["symbol"]
                    for dep in soft_struct_refs.get(package_name, set())
                    if dep in types_by_full
                }
            )
            forward_enums = sorted(
                (
                    enums[enum_name]["symbol"],
                    enum_refs.get(package_name, {}).get(enum_name) or enums[enum_name]["underlying"],
                )
                for enum_name in enum_refs.get(package_name, {})
                if enum_name in enums and enums[enum_name]["package"] != package_name
            )
            _emit_package_header(
                os.path.join(out_dir, f"{package_symbol}.hpp"),
                package_name=package_name,
                entries=sorted(packages[package_name], key=lambda item: item["symbol"]),
                package_includes=include_names,
                forward_structs=forward_structs,
                forward_enums=forward_enums,
                types_by_full=types_by_full,
                enums=enums,
                type_short_index=type_short_index,
                enum_short_index=enum_short_index,
                same_scc_packages=same_scc_packages,
                type_graph=type_graph_by_package.get(package_name, {}),
            )

    _emit_runtime_headers(out_dir)
    return package_names


def generate_v2_master_header(packages: List[str], out_dir: str) -> None:
    with open(os.path.join(out_dir, "SDK.hpp"), "w", encoding="utf-8") as f:
        f.write("#pragma once\n\n")
        f.write('#include "Basic.hpp"\n')
        f.write('#include "UnrealContainers.hpp"\n')
        f.write('#include "Offsets.hpp"\n')
        f.write('#include "chains.hpp"\n\n')
        for package in sorted(packages):
            f.write(f'#include "{package}.hpp"\n')
