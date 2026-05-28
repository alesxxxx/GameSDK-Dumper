import logging
import struct
from typing import Callable, Dict, List, Optional

from src.core.memory import read_uint64, read_uint32, read_string, read_uint16, read_bytes, get_module_info, get_pid_by_name
from src.core.models import EnumInfo, SDKDump, StructInfo, MemberInfo
from src.engines.source2.parser import get_type_scope_classes, get_type_scope_enums

logger = logging.getLogger(__name__)

_MAX_SCHEMA_CLASS_NAME_LEN = 128
_MAX_SCHEMA_TYPE_NAME_LEN = 256
_MAX_SCHEMA_METADATA_NAME_LEN = 128
_MAX_REASONABLE_CLASS_SIZE = 1024 * 1024
_MAX_REASONABLE_CLASS_FIELDS = 512
_MAX_REASONABLE_ENUM_MEMBERS = 4096
_MAX_REASONABLE_METADATA = 128


def _is_reasonable_schema_text(value: str, *, max_len: int) -> bool:
    if not value or len(value) > max_len:
        return False
    return all(0x20 <= ord(ch) <= 0x7E for ch in value)


def _read_u8(handle: int, address: int) -> int:
    data = read_bytes(handle, address, 1)
    if len(data) < 1:
        return 0
    return data[0]


def _read_i64(handle: int, address: int) -> int:
    data = read_bytes(handle, address, 8)
    if len(data) < 8:
        return 0
    return struct.unpack_from("<q", data)[0]


def _compact_type_name(value: str) -> str:
    return (value or "").replace(" ", "")


def _normalize_source2_module_name(value: str, fallback: str) -> str:
    module = value if _is_reasonable_schema_text(value, max_len=_MAX_SCHEMA_CLASS_NAME_LEN) else fallback
    lower = module.lower()
    if module and "." not in lower and not lower.endswith((".dll", ".exe")):
        return f"{module}.dll"
    return module or fallback


def read_schema_metadata_entries(
    handle: int,
    metadata_ptr: int,
    count: int,
) -> List[Dict[str, object]]:
    """Read Source 2 SchemaMetadataEntryData items.

    Known metadata entries are normalized while unknown entries are preserved by
    name so generated outputs can still show that metadata exists.
    """
    if not metadata_ptr or count <= 0 or count > _MAX_REASONABLE_METADATA:
        return []

    entries: List[Dict[str, object]] = []
    for i in range(count):
        entry_addr = metadata_ptr + (i * 0x10)
        name_ptr = read_uint64(handle, entry_addr + 0x0)
        network_value_ptr = read_uint64(handle, entry_addr + 0x8)
        name = read_string(handle, name_ptr, max_len=_MAX_SCHEMA_METADATA_NAME_LEN) if name_ptr else ""
        if not _is_reasonable_schema_text(name, max_len=_MAX_SCHEMA_METADATA_NAME_LEN):
            continue

        item: Dict[str, object] = {"name": name, "kind": "unknown"}
        if network_value_ptr and name == "MNetworkChangeCallback":
            callback_ptr = read_uint64(handle, network_value_ptr + 0x0)
            callback_name = read_string(handle, callback_ptr, max_len=_MAX_SCHEMA_METADATA_NAME_LEN) if callback_ptr else ""
            item["kind"] = "network_change_callback"
            if _is_reasonable_schema_text(callback_name, max_len=_MAX_SCHEMA_METADATA_NAME_LEN):
                item["callback"] = callback_name
        elif network_value_ptr and name == "MNetworkVarNames":
            var_name_ptr = read_uint64(handle, network_value_ptr + 0x0)
            type_name_ptr = read_uint64(handle, network_value_ptr + 0x8)
            var_name = read_string(handle, var_name_ptr, max_len=_MAX_SCHEMA_METADATA_NAME_LEN) if var_name_ptr else ""
            type_name = read_string(handle, type_name_ptr, max_len=_MAX_SCHEMA_TYPE_NAME_LEN) if type_name_ptr else ""
            item["kind"] = "network_var_names"
            if _is_reasonable_schema_text(var_name, max_len=_MAX_SCHEMA_METADATA_NAME_LEN):
                item["var_name"] = var_name
            if _is_reasonable_schema_text(type_name, max_len=_MAX_SCHEMA_TYPE_NAME_LEN):
                item["type_name"] = _compact_type_name(type_name)
        elif network_value_ptr:
            item["network_value"] = f"0x{network_value_ptr:X}"

        entries.append(item)

    return entries


def read_enum_binding(
    handle: int,
    enum_ptr: int,
    scope_name: str,
) -> Optional[EnumInfo]:
    """Read one Source 2 SchemaEnumInfoData binding into the common EnumInfo."""
    name_ptr = read_uint64(handle, enum_ptr + 0x8)
    name = read_string(handle, name_ptr, max_len=_MAX_SCHEMA_CLASS_NAME_LEN) if name_ptr else ""
    if not _is_reasonable_schema_text(name, max_len=_MAX_SCHEMA_CLASS_NAME_LEN):
        return None

    module_name_ptr = read_uint64(handle, enum_ptr + 0x10)
    module_name = read_string(handle, module_name_ptr, max_len=_MAX_SCHEMA_CLASS_NAME_LEN) if module_name_ptr else ""
    module_name = _normalize_source2_module_name(module_name, scope_name)

    enum_size = _read_u8(handle, enum_ptr + 0x18)
    alignment = _read_u8(handle, enum_ptr + 0x19)
    flags = _read_u8(handle, enum_ptr + 0x1A)
    member_count = read_uint16(handle, enum_ptr + 0x1C)
    metadata_count = read_uint16(handle, enum_ptr + 0x1E)
    members_ptr = read_uint64(handle, enum_ptr + 0x20)
    metadata_ptr = read_uint64(handle, enum_ptr + 0x28)

    if member_count > _MAX_REASONABLE_ENUM_MEMBERS:
        return None
    if member_count and not members_ptr:
        return None

    values = []
    for i in range(member_count):
        # SchemaEnumeratorInfoData is 0x20 bytes.
        member_addr = members_ptr + (i * 0x20)
        member_name_ptr = read_uint64(handle, member_addr + 0x0)
        member_name = read_string(handle, member_name_ptr, max_len=_MAX_SCHEMA_CLASS_NAME_LEN) if member_name_ptr else ""
        if not _is_reasonable_schema_text(member_name, max_len=_MAX_SCHEMA_CLASS_NAME_LEN):
            continue
        values.append((member_name, _read_i64(handle, member_addr + 0x8)))

    metadata = {
        "source2_module": module_name,
        "source2_scope": scope_name,
        "source2_size": enum_size,
        "source2_alignment": alignment,
        "source2_flags": flags,
        "source2_metadata": read_schema_metadata_entries(handle, metadata_ptr, metadata_count),
    }

    return EnumInfo(
        name=name,
        full_name=f"Source2.{module_name}.{name}",
        address=enum_ptr,
        values=values,
        metadata=metadata,
    )

def dump_source2(
    handle: int,
    process_name: str,
    progress_callback: Optional[Callable[[str], None]] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> SDKDump:

    def _log(msg: str) -> None:
        logger.info(msg)
        if log_fn:
            log_fn(msg)

    pid = get_pid_by_name(process_name)
    if not pid:
        raise RuntimeError(f"Process {process_name!r} not found")

    _log(f"[Source2] Dumping schemas for {process_name}...")

    # For Source 2, the schema system is in schemasystem.dll
    schema_base, schema_size = get_module_info(pid, "schemasystem.dll")
    if not schema_base:
        raise RuntimeError(f"Could not find schemasystem.dll in {process_name}")

    if progress_callback:
        progress_callback("Scanning schemasystem.dll for CSchemaSystem...")

    # Pattern scan for CSchemaSystem
    from src.engines.source2.signatures import find_schema_system_ptr
    schema_sys = find_schema_system_ptr(handle, schema_base, schema_size)
    
    if not schema_sys:
        raise RuntimeError("Could not find CSchemaSystem pattern in schemasystem.dll.")

    # Sanity check: the primary pattern (lea) resolves directly to the struct.
    # If the address looks like a valid pointer (very high value), it might be the
    # struct itself. If the first qword at the address looks like another pointer,
    # we may need to dereference. We try reading the type_scopes count at +0x1A0
    # to validate which interpretation is correct.
    test_count = read_uint32(handle, schema_sys + 0x190 + 0x10)
    if test_count == 0 or test_count > 256:
        # Maybe we got a pointer TO the struct, not the struct itself — dereference
        deref = read_uint64(handle, schema_sys)
        if deref:
            test2 = read_uint32(handle, deref + 0x190 + 0x10)
            if 0 < test2 <= 256:
                schema_sys = deref
                _log(f"[Source2] CSchemaSystem (dereferenced): 0x{schema_sys:X}")
            else:
                _log(f"[Source2] CSchemaSystem: 0x{schema_sys:X} (direct)")
        else:
            _log(f"[Source2] CSchemaSystem: 0x{schema_sys:X} (direct, unvalidated)")
    else:
        _log(f"[Source2] CSchemaSystem: 0x{schema_sys:X}")

    if progress_callback:
        progress_callback("Reading Schema System Scopes...")

    # SchemaSystemTypeScopes are at +0x190 in CSchemaSystem 
    # UtlVector layout (from a2x/cs2-dumper utl_vector.rs):
    #   0x0000: count  (i32)
    #   0x0004: pad    (4 bytes)
    #   0x0008: data   (Pointer64<[T]>)
    scopes_size = read_uint32(handle, schema_sys + 0x190 + 0x0)  # count
    scopes_data = read_uint64(handle, schema_sys + 0x190 + 0x8)  # data ptr
    
    if scopes_size == 0 or not scopes_data:
        raise RuntimeError("No type scopes found in schema system.")

    _log(f"[Source2] Found {scopes_size} type scopes (data @ 0x{scopes_data:X})")

    structs = []
    enums = []
    total_props = 0
    skipped_invalid_classes = 0
    skipped_invalid_fields = 0
    skipped_invalid_enums = 0

    for i in range(scopes_size):
        # Array of pointers to CSchemaSystemTypeScope
        scope_ptr = read_uint64(handle, scopes_data + (i * 8))
        if not scope_ptr:
            _log(f"  [Scope {i}] null pointer — skipped")
            continue
            
        scope_name_ptr = scope_ptr + 0x8 
        scope_name = read_string(handle, scope_name_ptr, max_len=256)
        
        if not scope_name:
            _log(f"  [Scope {i}] empty name at 0x{scope_ptr:X} — skipped")
            continue
            
        _log(f"  -> Scope: {scope_name}")
        
        classes_ptrs = get_type_scope_classes(handle, scope_ptr)
        enum_ptrs = get_type_scope_enums(handle, scope_ptr)
        _log(f"     => {len(classes_ptrs)} classes, {len(enum_ptrs)} enums")

        for enum_ptr in enum_ptrs:
            enum_info = read_enum_binding(handle, enum_ptr, scope_name)
            if enum_info is None:
                skipped_invalid_enums += 1
                continue
            enums.append(enum_info)
        
        for class_ptr in classes_ptrs:
            # Parse SchemaClassInfoData
            class_name_ptr = read_uint64(handle, class_ptr + 0x8)
            class_name = read_string(handle, class_name_ptr, max_len=_MAX_SCHEMA_CLASS_NAME_LEN)
            module_name_ptr = read_uint64(handle, class_ptr + 0x18)
            module_name = read_string(handle, module_name_ptr, max_len=_MAX_SCHEMA_CLASS_NAME_LEN) if module_name_ptr else ""
            module_name = _normalize_source2_module_name(module_name, scope_name)
            size = read_uint32(handle, class_ptr + 0x20)
            fields_count = read_uint16(handle, class_ptr + 0x24)
            class_metadata_count = read_uint16(handle, class_ptr + 0x26)
            alignment = _read_u8(handle, class_ptr + 0x2A)
            fields_ptr = read_uint64(handle, class_ptr + 0x30)
            class_metadata_ptr = read_uint64(handle, class_ptr + 0x48)

            if not _is_reasonable_schema_text(class_name, max_len=_MAX_SCHEMA_CLASS_NAME_LEN):
                skipped_invalid_classes += 1
                continue
            if size > _MAX_REASONABLE_CLASS_SIZE:
                skipped_invalid_classes += 1
                continue
            if fields_count > _MAX_REASONABLE_CLASS_FIELDS:
                skipped_invalid_classes += 1
                continue
            if fields_count and not fields_ptr:
                skipped_invalid_classes += 1
                continue
            
            # base class
            base_classes_ptr = read_uint64(handle, class_ptr + 0x40)
            base_class_name = ""
            if base_classes_ptr:
                base_class_ptr = read_uint64(handle, base_classes_ptr + 0x18)
                if base_class_ptr:
                    b_name_ptr = read_uint64(handle, base_class_ptr + 0x10)
                    candidate = read_string(handle, b_name_ptr, max_len=_MAX_SCHEMA_CLASS_NAME_LEN) if b_name_ptr else ""
                    if _is_reasonable_schema_text(candidate, max_len=_MAX_SCHEMA_CLASS_NAME_LEN):
                        base_class_name = candidate
            
            members = []
            for f in range(fields_count):
                # SchemaClassFieldData_t size is 0x20
                f_addr = fields_ptr + (f * 0x20)
                
                f_name_ptr = read_uint64(handle, f_addr + 0x0)
                f_name = read_string(handle, f_name_ptr, max_len=_MAX_SCHEMA_CLASS_NAME_LEN)
                if not _is_reasonable_schema_text(f_name, max_len=_MAX_SCHEMA_CLASS_NAME_LEN):
                    skipped_invalid_fields += 1
                    continue
                
                schema_type_ptr = read_uint64(handle, f_addr + 0x8)
                type_name = "Unknown"
                if schema_type_ptr:
                    # SchemaType_t : name is at +0x8
                    t_name_ptr = read_uint64(handle, schema_type_ptr + 0x8)
                    candidate = read_string(handle, t_name_ptr, max_len=_MAX_SCHEMA_TYPE_NAME_LEN)
                    if _is_reasonable_schema_text(candidate, max_len=_MAX_SCHEMA_TYPE_NAME_LEN):
                        type_name = candidate
                    
                offset = read_uint32(handle, f_addr + 0x10)
                if size and offset > size + 0x1000:
                    skipped_invalid_fields += 1
                    continue

                field_metadata_count = read_uint32(handle, f_addr + 0x14)
                field_metadata_ptr = read_uint64(handle, f_addr + 0x18)
                
                members.append(
                    MemberInfo(
                        name=f_name,
                        offset=offset,
                        size=0, # not provided easily in schema type, it's complex
                        type_name=type_name,
                        array_dim=1,
                        flags=0,
                        metadata={
                            "source2_metadata": read_schema_metadata_entries(
                                handle,
                                field_metadata_ptr,
                                field_metadata_count,
                            )
                        }
                    )
                )
                total_props += 1

            class_metadata = read_schema_metadata_entries(
                handle,
                class_metadata_ptr,
                class_metadata_count,
            )
                
            structs.append(
                StructInfo(
                    name=class_name,
                    full_name=f"Source2.{module_name}.{class_name}",
                    address=class_ptr,
                    size=size,
                    super_name=base_class_name,
                    is_class=True,
                    package=module_name,
                    members=members,
                    metadata={
                        "source2_scope": scope_name,
                        "source2_module": module_name,
                        "source2_alignment": alignment,
                        "source2_metadata": class_metadata,
                    }
                )
            )

    if skipped_invalid_classes:
        _log(f"[Source2] Skipped {skipped_invalid_classes} invalid class bindings.")
    if skipped_invalid_fields:
        _log(f"[Source2] Skipped {skipped_invalid_fields} invalid fields.")
    if skipped_invalid_enums:
        _log(f"[Source2] Skipped {skipped_invalid_enums} invalid enum bindings.")
    _log(f"[Source2] Walk complete. {len(structs)} structs, {len(enums)} enums, {total_props} properties.")
    
    if progress_callback:
        progress_callback(f"Walk complete. {len(structs)} structs, {len(enums)} enums, {total_props} properties.")

    return SDKDump(
        structs=structs,
        enums=enums,
        metadata={
            "source2_scopes": scopes_size,
            "source2_invalid_classes": skipped_invalid_classes,
            "source2_invalid_fields": skipped_invalid_fields,
            "source2_invalid_enums": skipped_invalid_enums,
        }
    )
