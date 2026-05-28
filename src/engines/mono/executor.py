
from typing import Dict, List, Optional

from src.engines.mono.assembly_parser import TypeInfo
from src.engines.mono.mono_scanner import (
    build_class_map,
    get_class_fields_from_memory,
)
from src.core.models import SDKDump, StructInfo, MemberInfo, EnumInfo

_TYPE_SIZES: Dict[str, int] = {
    "System.Boolean": 1, "System.Byte": 1, "System.SByte": 1,
    "System.Char": 2, "System.Int16": 2, "System.UInt16": 2,
    "System.Int32": 4, "System.UInt32": 4, "System.Single": 4,
    "System.Int64": 8, "System.UInt64": 8, "System.Double": 8,
    "System.IntPtr": 8, "System.UIntPtr": 8,
    "System.String": 8, "System.Object": 8,
    "bool": 1, "byte": 1, "sbyte": 1, "char": 2,
    "short": 2, "ushort": 2, "int": 4, "uint": 4,
    "long": 8, "ulong": 8, "float": 4, "double": 8,
    "string": 8, "object": 8,
    "Boolean": 1, "Byte": 1, "SByte": 1, "Char": 2,
    "Int16": 2, "UInt16": 2, "Int32": 4, "UInt32": 4,
    "Single": 4, "Int64": 8, "UInt64": 8, "Double": 8,
}

def _type_size(type_name: str) -> int:
    if type_name in _TYPE_SIZES:
        return _TYPE_SIZES[type_name]
    parts = type_name.rsplit(".", 1)
    if len(parts) == 2 and parts[1] in _TYPE_SIZES:
        return _TYPE_SIZES[parts[1]]
    return 8

class MonoExecutor:

    def __init__(
        self,
        types_from_disk: List[TypeInfo],
        handle: int,
        domain_ptr: int,
        mono_base: int = 0,
    ):
        self.types     = types_from_disk
        self.handle    = handle
        self.domain_ptr = domain_ptr
        self.mono_base  = mono_base

        self._class_map: Dict[str, int] = {}
        if domain_ptr and handle:
            print("  Building class map from Mono runtime...")
            self._class_map = build_class_map(handle, domain_ptr)

        real = sum(1 for v in self._class_map.values() if v)
        print(f"  [OK] Class map: {real} classes with real addresses")

    def _find_class_ptr(self, ti: TypeInfo) -> int:
        for key in (ti.full_name, ti.name, f"{ti.namespace}.{ti.name}"):
            if key and key in self._class_map:
                return self._class_map[key]
        return 0

    def walk_types(self, progress_callback=None, log=None) -> SDKDump:
        if log is None: log = print
        dump = SDKDump()
        dump.object_count = len(self.types)
        total = len(self.types)
        structs_found = enums_found = 0

        # Diagnostic: count types with/without fields
        with_fields = sum(1 for t in self.types if t.fields)
        with_enum_vals = sum(1 for t in self.types if t.is_enum and (t.enum_values or t.fields))
        log(f"  Total {total} types, {with_fields} have fields, {with_enum_vals} are enums with values")
        for t in self.types[:5]:
            log(f"  > {t.full_name}: fields={len(t.fields)}, is_enum={t.is_enum}")

        for i, ti in enumerate(self.types):
            if progress_callback and i % 200 == 0:
                progress_callback(i, total)

            if ti.is_enum:
                e = self._process_enum(ti, i)
                if e:
                    dump.enums.append(e)
                    enums_found += 1
            else:
                s = self._process_struct(ti, i)
                if s:
                    dump.structs.append(s)
                    structs_found += 1

        if progress_callback:
            progress_callback(total, total)

        log(
            f"  [OK] walk complete — "
            f"{structs_found} structs/classes, {enums_found} enums"
        )
        return dump

    def _process_struct(self, ti: TypeInfo, idx: int) -> Optional[StructInfo]:
        if not ti.fields:
            return None

        class_ptr = self._find_class_ptr(ti)
        memory_offsets: Dict[str, int] = {}

        if class_ptr:
            memory_offsets = get_class_fields_from_memory(
                self.handle, class_ptr, len(ti.fields)
            )

        members = []
        max_offset = 0
        for fi, field in enumerate(ti.fields):
            if field.name in memory_offsets:
                offset = memory_offsets[field.name]
            else:
                offset = 8 + fi * 8

            size = _type_size(field.type_name)
            members.append(MemberInfo(
                name=field.name,
                offset=offset,
                size=size,
                type_name=field.type_name,
            ))
            if offset + size > max_offset:
                max_offset = offset + size

        if not members:
            return None

        parent = ti.parent_name
        if parent in ("Object", "System.Object", "MonoBehaviour",
                      "ValueType", "System.ValueType"):
            parent = ""

        return StructInfo(
            name=ti.name,
            full_name=ti.full_name,
            address=class_ptr or idx,
            size=max_offset if max_offset > 0 else len(ti.fields) * 8,
            super_name=parent,
            is_class=ti.is_class,
            package=ti.namespace,
            members=members,
        )

    def _process_enum(self, ti: TypeInfo, idx: int) -> Optional[EnumInfo]:
        if not ti.enum_values and not ti.fields:
            return None

        info = EnumInfo(
            name=ti.name,
            full_name=ti.full_name,
            address=idx,
        )

        if ti.enum_values:
            info.values = list(ti.enum_values)
        else:
            counter = 0
            for field in ti.fields:
                if field.name == "value__":
                    continue
                info.values.append((field.name, counter))
                counter += 1

        return info if info.values else None
