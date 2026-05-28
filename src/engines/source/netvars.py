
import logging
import struct
from typing import Callable, Dict, List, Optional, Set, Tuple

from src.core.memory import (
    read_bytes,
    read_int32,
    read_string,
    read_uint32,
)
from src.core.scanner import scan_pattern
from src.engines.source.game_data import (
    CLIENTCLASS_NETWORK_NAME_32,
    CLIENTCLASS_NETWORK_NAME_64,
    CLIENTCLASS_NEXT_32,
    CLIENTCLASS_NEXT_64,
    CLIENTCLASS_RECV_TABLE_32,
    CLIENTCLASS_RECV_TABLE_64,
    RECVPROP_ARRAYPROP_32,
    RECVPROP_ARRAYPROP_64,
    RECVPROP_DATATABLE_32,
    RECVPROP_DATATABLE_64,
    RECVPROP_ELEMENTS_32,
    RECVPROP_ELEMENTS_64,
    RECVPROP_ELEMENTSTRIDE_32,
    RECVPROP_ELEMENTSTRIDE_64,
    RECVPROP_FLAGS_32,
    RECVPROP_FLAGS_64,
    RECVPROP_INSIDE_ARRAY_32,
    RECVPROP_INSIDE_ARRAY_64,
    RECVPROP_OFFSET_32,
    RECVPROP_OFFSET_64,
    RECVPROP_PARENT_ARRAY_NAME_32,
    RECVPROP_PARENT_ARRAY_NAME_64,
    RECVPROP_RECVTYPE_32,
    RECVPROP_RECVTYPE_64,
    RECVPROP_SIZE_32,
    RECVPROP_SIZE_64,
    RECVPROP_STRING_BUFFER_SIZE_32,
    RECVPROP_STRING_BUFFER_SIZE_64,
    RECVPROP_VARNAME_32,
    RECVPROP_VARNAME_64,
    RECVTABLE_NPROPS_32,
    RECVTABLE_NPROPS_64,
    RECVTABLE_PROPS_32,
    RECVTABLE_PROPS_64,
    RECVTABLE_TABLENAME_32,
    RECVTABLE_TABLENAME_64,
    SourceGameProfile,
    prop_type_name,
)
from src.engines.source.signatures import (
    GETALLCLASSES_SIGS_32,
    GETALLCLASSES_SIGS_64,
)

logger = logging.getLogger(__name__)

class RecvPropInfo:

    __slots__ = (
        "raw_name",
        "name",
        "offset",
        "type_id",
        "type_name",
        "flags",
        "string_buffer_size",
        "inside_array",
        "datatable_ptr",
        "array_prop_ptr",
        "element_stride",
        "elements",
        "parent_array_name",
    )

    def __init__(
        self,
        raw_name: str,
        offset: int,
        type_id: int,
        *,
        flags: int = 0,
        string_buffer_size: int = 0,
        inside_array: bool = False,
        datatable_ptr: int = 0,
        array_prop_ptr: int = 0,
        element_stride: int = 0,
        elements: int = 0,
        parent_array_name: str = "",
    ):
        self.raw_name = raw_name
        self.name = _resolve_prop_name(raw_name, parent_array_name)
        self.offset = offset
        self.type_id = type_id
        self.type_name = prop_type_name(type_id)
        self.flags = flags
        self.string_buffer_size = string_buffer_size
        self.inside_array = inside_array
        self.datatable_ptr = datatable_ptr
        self.array_prop_ptr = array_prop_ptr
        self.element_stride = element_stride
        self.elements = elements
        self.parent_array_name = parent_array_name

    def __repr__(self) -> str:
        return (
            f"RecvPropInfo({self.name!r}, offset=0x{self.offset:X}, "
            f"type={self.type_name}, flags=0x{self.flags:X})"
        )

class RecvTableInfo:

    __slots__ = ("name", "address", "props")

    def __init__(self, name: str, address: int, props: List[RecvPropInfo]):
        self.name = name
        self.address = address
        self.props = props

    def __repr__(self) -> str:
        return f"RecvTableInfo({self.name!r}, {len(self.props)} props)"

class FlatPropInfo:

    __slots__ = (
        "name",
        "raw_name",
        "offset",
        "size",
        "type_id",
        "type_name",
        "flags",
        "kind",
        "datatable_name",
        "elements",
        "element_stride",
        "element_type_name",
        "parent_array_name",
    )

    def __init__(
        self,
        *,
        name: str,
        raw_name: str,
        offset: int,
        size: int,
        type_id: int,
        type_name: str,
        flags: int,
        kind: str = "prop",
        datatable_name: str = "",
        elements: int = 0,
        element_stride: int = 0,
        element_type_name: str = "",
        parent_array_name: str = "",
    ):
        self.name = name
        self.raw_name = raw_name
        self.offset = offset
        self.size = size
        self.type_id = type_id
        self.type_name = type_name
        self.flags = flags
        self.kind = kind
        self.datatable_name = datatable_name
        self.elements = elements
        self.element_stride = element_stride
        self.element_type_name = element_type_name
        self.parent_array_name = parent_array_name

class NetvarTableDump:

    __slots__ = ("name", "client_classes", "props", "base_table_name")

    def __init__(self, name: str):
        self.name = name
        self.client_classes: Set[str] = set()
        self.props: List[FlatPropInfo] = []
        self.base_table_name = ""

def _resolve_prop_name(raw_name: str, parent_array_name: str = "") -> str:

    name = (raw_name or "").strip()
    parent_name = (parent_array_name or "").strip().strip("\"'")

    if name.startswith(("\"", "'")) and name.endswith(("\"", "'")) and len(name) >= 2:
        name = name[1:-1]

    if name.isdigit():
        if parent_name:
            return f"{parent_name}[{int(name)}]"
        return f"unnamed_{name}"

    if not name:
        if parent_name:
            return parent_name
        return "unnamed"

    return name

def _infer_prop_size(prop: RecvPropInfo, element_prop: Optional[RecvPropInfo] = None) -> int:

    if prop.type_id == 0:
        return 4
    if prop.type_id == 1:
        return 4
    if prop.type_id == 2:
        return 12
    if prop.type_id == 3:
        return 8
    if prop.type_id == 4:
        return max(0, prop.string_buffer_size)
    if prop.type_id == 5:
        if prop.element_stride > 0 and prop.elements > 0:
            return prop.element_stride * prop.elements
        if element_prop is not None and prop.elements > 0:
            return _infer_prop_size(element_prop) * prop.elements
        return 0
    if prop.type_id == 6:
        return 0
    if prop.type_id == 7:
        return 8
    return 0

def _prop_sort_key(prop: FlatPropInfo) -> Tuple[int, int, str]:

    kind_rank = {
        "array": 0,
        "datatable": 1,
        "prop": 2,
    }.get(prop.kind, 3)
    return (prop.offset, kind_rank, prop.name)

def _infer_uniform_stride(offsets: List[int]) -> int:

    ordered = sorted(set(offsets))
    if len(ordered) < 2:
        return 0

    deltas = [current - previous for previous, current in zip(ordered, ordered[1:])]
    if not deltas:
        return 0

    stride = deltas[0]
    if stride <= 0:
        return 0

    return stride if all(delta == stride for delta in deltas) else 0

def _detect_datatable_array(
    prop: RecvPropInfo,
    nested_table: Optional[RecvTableInfo],
) -> Optional[dict]:

    if not nested_table or len(nested_table.props) < 2:
        return None

    children = [child for child in nested_table.props if child.raw_name != "baseclass"]
    if len(children) < 2:
        return None
    if any(child.type_id in (5, 6) for child in children):
        return None

    numeric_children = sum(1 for child in children if child.raw_name.isdigit())
    parent_candidates = {name for name in (prop.name, prop.raw_name, nested_table.name) if name}
    parent_matches = sum(
        1
        for child in children
        if (child.parent_array_name or nested_table.name) in parent_candidates
    )

    majority = len(children) // 2 + 1
    if numeric_children < majority or parent_matches < majority:
        return None

    element_types = {child.type_name for child in children}
    return {
        "elements": len(children),
        "element_stride": _infer_uniform_stride([child.offset for child in children]),
        "element_type_name": children[0].type_name if len(element_types) == 1 else "",
    }

def _get_layout(is_64bit: bool) -> dict:

    if is_64bit:
        return {
            "cc_name": CLIENTCLASS_NETWORK_NAME_64,
            "cc_table": CLIENTCLASS_RECV_TABLE_64,
            "cc_next": CLIENTCLASS_NEXT_64,
            "rt_props": RECVTABLE_PROPS_64,
            "rt_nprops": RECVTABLE_NPROPS_64,
            "rt_name": RECVTABLE_TABLENAME_64,
            "rp_size": RECVPROP_SIZE_64,
            "rp_varname": RECVPROP_VARNAME_64,
            "rp_type": RECVPROP_RECVTYPE_64,
            "rp_flags": RECVPROP_FLAGS_64,
            "rp_string_buffer_size": RECVPROP_STRING_BUFFER_SIZE_64,
            "rp_inside_array": RECVPROP_INSIDE_ARRAY_64,
            "rp_arrayprop": RECVPROP_ARRAYPROP_64,
            "rp_datatable": RECVPROP_DATATABLE_64,
            "rp_offset": RECVPROP_OFFSET_64,
            "rp_element_stride": RECVPROP_ELEMENTSTRIDE_64,
            "rp_elements": RECVPROP_ELEMENTS_64,
            "rp_parent_array_name": RECVPROP_PARENT_ARRAY_NAME_64,
        }

    return {
        "cc_name": CLIENTCLASS_NETWORK_NAME_32,
        "cc_table": CLIENTCLASS_RECV_TABLE_32,
        "cc_next": CLIENTCLASS_NEXT_32,
        "rt_props": RECVTABLE_PROPS_32,
        "rt_nprops": RECVTABLE_NPROPS_32,
        "rt_name": RECVTABLE_TABLENAME_32,
        "rp_size": RECVPROP_SIZE_32,
        "rp_varname": RECVPROP_VARNAME_32,
        "rp_type": RECVPROP_RECVTYPE_32,
        "rp_flags": RECVPROP_FLAGS_32,
        "rp_string_buffer_size": RECVPROP_STRING_BUFFER_SIZE_32,
        "rp_inside_array": RECVPROP_INSIDE_ARRAY_32,
        "rp_arrayprop": RECVPROP_ARRAYPROP_32,
        "rp_datatable": RECVPROP_DATATABLE_32,
        "rp_offset": RECVPROP_OFFSET_32,
        "rp_element_stride": RECVPROP_ELEMENTSTRIDE_32,
        "rp_elements": RECVPROP_ELEMENTS_32,
        "rp_parent_array_name": RECVPROP_PARENT_ARRAY_NAME_32,
    }

def _read_ptr(handle: int, address: int, is_64bit: bool) -> int:

    if is_64bit:
        data = read_bytes(handle, address, 8)
        if len(data) < 8:
            return 0
        return struct.unpack_from("<Q", data)[0]
    return read_uint32(handle, address)

def _read_bool(handle: int, address: int) -> bool:

    data = read_bytes(handle, address, 1)
    return bool(data and data[0])

def _parse_recv_prop(
    handle: int,
    prop_addr: int,
    layout: dict,
    is_64bit: bool,
) -> Optional[RecvPropInfo]:

    if not prop_addr:
        return None

    varname_ptr = _read_ptr(handle, prop_addr + layout["rp_varname"], is_64bit)
    if not varname_ptr:
        return None
    raw_name = read_string(handle, varname_ptr, 128)
    if not raw_name:
        return None

    parent_array_name = ""
    parent_array_name_ptr = _read_ptr(
        handle, prop_addr + layout["rp_parent_array_name"], is_64bit
    )
    if parent_array_name_ptr:
        parent_array_name = read_string(handle, parent_array_name_ptr, 128) or ""

    return RecvPropInfo(
        raw_name=raw_name,
        offset=read_int32(handle, prop_addr + layout["rp_offset"]),
        type_id=read_int32(handle, prop_addr + layout["rp_type"]),
        flags=read_int32(handle, prop_addr + layout["rp_flags"]),
        string_buffer_size=read_int32(handle, prop_addr + layout["rp_string_buffer_size"]),
        inside_array=_read_bool(handle, prop_addr + layout["rp_inside_array"]),
        datatable_ptr=_read_ptr(handle, prop_addr + layout["rp_datatable"], is_64bit),
        array_prop_ptr=_read_ptr(handle, prop_addr + layout["rp_arrayprop"], is_64bit),
        element_stride=read_int32(handle, prop_addr + layout["rp_element_stride"]),
        elements=read_int32(handle, prop_addr + layout["rp_elements"]),
        parent_array_name=parent_array_name,
    )

def _parse_recv_table(
    handle: int,
    table_ptr: int,
    layout: dict,
    is_64bit: bool,
    max_props: int = 512,
) -> Optional[RecvTableInfo]:

    if not table_ptr:
        return None

    name_ptr = _read_ptr(handle, table_ptr + layout["rt_name"], is_64bit)
    if not name_ptr:
        return None
    table_name = read_string(handle, name_ptr, 128)
    if not table_name:
        return None

    props_ptr = _read_ptr(handle, table_ptr + layout["rt_props"], is_64bit)
    n_props = read_int32(handle, table_ptr + layout["rt_nprops"])

    if not props_ptr or n_props <= 0 or n_props > max_props:
        return RecvTableInfo(name=table_name, address=table_ptr, props=[])

    props: List[RecvPropInfo] = []
    rp_size = layout["rp_size"]

    for i in range(n_props):
        prop = _parse_recv_prop(handle, props_ptr + i * rp_size, layout, is_64bit)
        if prop:
            props.append(prop)

    return RecvTableInfo(name=table_name, address=table_ptr, props=props)

def _flatten_netvars(
    handle: int,
    table_ptr: int,
    layout: dict,
    is_64bit: bool,
    *,
    base_offset: int = 0,
    depth: int = 0,
    max_depth: int = 32,
    visited: Optional[Set[int]] = None,
) -> List[FlatPropInfo]:

    if depth > max_depth:
        return []

    path = set(visited or ())
    if table_ptr in path:
        return []
    path.add(table_ptr)

    table = _parse_recv_table(handle, table_ptr, layout, is_64bit)
    if not table:
        return []

    result: List[FlatPropInfo] = []

    for prop in table.props:
        total_offset = base_offset + prop.offset

        if prop.raw_name == "baseclass":
            if prop.datatable_ptr:
                result.extend(
                    _flatten_netvars(
                        handle,
                        prop.datatable_ptr,
                        layout,
                        is_64bit,
                        base_offset=base_offset,
                        depth=depth + 1,
                        max_depth=max_depth,
                        visited=path,
                    )
                )
            continue

        if prop.type_id == 5:
            element_prop = _parse_recv_prop(handle, prop.array_prop_ptr, layout, is_64bit)
            result.append(
                FlatPropInfo(
                    name=prop.name,
                    raw_name=prop.raw_name,
                    offset=total_offset,
                    size=_infer_prop_size(prop, element_prop),
                    type_id=prop.type_id,
                    type_name=prop.type_name,
                    flags=prop.flags,
                    kind="array",
                    elements=max(prop.elements, 0),
                    element_stride=max(prop.element_stride, 0),
                    element_type_name=element_prop.type_name if element_prop else "",
                    parent_array_name=prop.parent_array_name,
                )
            )
            continue

        if prop.type_id == 6 and prop.datatable_ptr:
            nested_table = _parse_recv_table(handle, prop.datatable_ptr, layout, is_64bit)
            array_meta = _detect_datatable_array(prop, nested_table)
            result.append(
                FlatPropInfo(
                    name=prop.name,
                    raw_name=prop.raw_name,
                    offset=total_offset,
                    size=(
                        array_meta["element_stride"] * array_meta["elements"]
                        if array_meta and array_meta["element_stride"] > 0
                        else 0
                    ),
                    type_id=prop.type_id,
                    type_name=prop.type_name,
                    flags=prop.flags,
                    kind="array" if array_meta else "datatable",
                    datatable_name=nested_table.name if nested_table else "",
                    elements=array_meta["elements"] if array_meta else 0,
                    element_stride=array_meta["element_stride"] if array_meta else 0,
                    element_type_name=array_meta["element_type_name"] if array_meta else "",
                    parent_array_name=prop.parent_array_name or (prop.name if array_meta else ""),
                )
            )
            result.extend(
                _flatten_netvars(
                    handle,
                    prop.datatable_ptr,
                    layout,
                    is_64bit,
                    base_offset=total_offset,
                    depth=depth + 1,
                    max_depth=max_depth,
                    visited=path,
                )
            )
            continue

        result.append(
            FlatPropInfo(
                name=prop.name,
                raw_name=prop.raw_name,
                offset=total_offset,
                size=_infer_prop_size(prop),
                type_id=prop.type_id,
                type_name=prop.type_name,
                flags=prop.flags,
                kind="prop",
                parent_array_name=prop.parent_array_name,
            )
        )

    return result

def walk_netvars(
    handle: int,
    head_ptr: int,
    is_64bit: bool = True,
    progress_callback: Optional[Callable[[str], None]] = None,
) -> Tuple[Dict[str, NetvarTableDump], Dict[str, str]]:

    layout = _get_layout(is_64bit)
    tables: Dict[str, NetvarTableDump] = {}
    aliases: Dict[str, str] = {}

    current = head_ptr
    count = 0
    max_classes = 2048

    while current and count < max_classes:
        count += 1

        class_name = ""
        class_name_ptr = _read_ptr(handle, current + layout["cc_name"], is_64bit)
        if class_name_ptr:
            class_name = read_string(handle, class_name_ptr, 128) or ""

        table_ptr = _read_ptr(handle, current + layout["cc_table"], is_64bit)
        if table_ptr:
            table = _parse_recv_table(handle, table_ptr, layout, is_64bit)
            if table and table.name:
                base_table_name = ""
                for prop in table.props:
                    if prop.raw_name == "baseclass" and prop.datatable_ptr:
                        base_table = _parse_recv_table(handle, prop.datatable_ptr, layout, is_64bit)
                        if base_table and base_table.name:
                            base_table_name = base_table.name
                            break

                resolved = _flatten_netvars(handle, table_ptr, layout, is_64bit)
                if resolved:
                    bucket = tables.setdefault(table.name, NetvarTableDump(table.name))
                    if class_name:
                        bucket.client_classes.add(class_name)
                        aliases[class_name] = table.name
                    if base_table_name and not bucket.base_table_name:
                        bucket.base_table_name = base_table_name

                    seen = {
                        (
                            item.kind,
                            item.name,
                            item.raw_name,
                            item.offset,
                            item.datatable_name,
                            item.elements,
                            item.element_stride,
                        )
                        for item in bucket.props
                    }
                    for item in resolved:
                        key = (
                            item.kind,
                            item.name,
                            item.raw_name,
                            item.offset,
                            item.datatable_name,
                            item.elements,
                            item.element_stride,
                        )
                        if key not in seen:
                            bucket.props.append(item)
                            seen.add(key)

                    bucket.props.sort(key=_prop_sort_key)
                    if progress_callback and count % 20 == 0:
                        progress_callback(f"Parsed {count} classes... ({table.name})")

        current = _read_ptr(handle, current + layout["cc_next"], is_64bit)

    logger.info("Walked %d ClientClasses, found %d tables", count, len(tables))
    return tables, aliases

def _find_create_interface_export(
    handle: int,
    module_base: int,
    module_size: int,
) -> int:

    dos = read_bytes(handle, module_base, 0x40)
    if len(dos) < 0x40 or dos[:2] != b"MZ":
        return 0

    e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
    if not e_lfanew or e_lfanew > 0x1000:
        return 0

    pe = read_bytes(handle, module_base + e_lfanew, 0x120)
    if len(pe) < 0x120 or pe[:4] != b"PE\x00\x00":
        return 0

    magic = struct.unpack_from("<H", pe, 0x18)[0]
    if magic == 0x20B:
        export_rva = struct.unpack_from("<I", pe, 0x88)[0]
        export_size = struct.unpack_from("<I", pe, 0x8C)[0]
    elif magic == 0x10B:
        export_rva = struct.unpack_from("<I", pe, 0x78)[0]
        export_size = struct.unpack_from("<I", pe, 0x7C)[0]
    else:
        return 0

    if not export_rva or not export_size:
        return 0

    export_dir = read_bytes(handle, module_base + export_rva, min(export_size, 0x1000))
    if len(export_dir) < 40:
        return 0

    num_funcs = struct.unpack_from("<I", export_dir, 0x14)[0]
    num_names = struct.unpack_from("<I", export_dir, 0x18)[0]
    addr_table_rva = struct.unpack_from("<I", export_dir, 0x1C)[0]
    name_table_rva = struct.unpack_from("<I", export_dir, 0x20)[0]
    ordinal_table_rva = struct.unpack_from("<I", export_dir, 0x24)[0]

    if not num_names or num_names > 10000:
        return 0

    name_ptrs = read_bytes(handle, module_base + name_table_rva, num_names * 4)
    if len(name_ptrs) < num_names * 4:
        return 0

    for i in range(num_names):
        name_rva = struct.unpack_from("<I", name_ptrs, i * 4)[0]
        name = read_string(handle, module_base + name_rva, 32)
        if name == "CreateInterface":
            ordinals = read_bytes(handle, module_base + ordinal_table_rva, num_names * 2)
            if len(ordinals) < (i + 1) * 2:
                return 0
            ordinal = struct.unpack_from("<H", ordinals, i * 2)[0]

            func_rvas = read_bytes(handle, module_base + addr_table_rva, num_funcs * 4)
            if len(func_rvas) < (ordinal + 1) * 4:
                return 0
            func_rva = struct.unpack_from("<I", func_rvas, ordinal * 4)[0]
            return module_base + func_rva

    return 0

def find_client_class_head(
    handle: int,
    client_base: int,
    client_size: int,
    game: SourceGameProfile,
) -> int:

    is_64bit = game.is_64bit

    create_iface = _find_create_interface_export(handle, client_base, client_size)
    if create_iface:
        logger.info("Found CreateInterface at 0x%X", create_iface)

    sigs = GETALLCLASSES_SIGS_64 if is_64bit else GETALLCLASSES_SIGS_32

    for sig in sorted(sigs, key=lambda s: s.priority):
        matches = scan_pattern(handle, client_base, client_size, sig.pattern, max_results=10)

        for match_va in matches:
            if is_64bit:
                disp = read_int32(handle, match_va + sig.disp_offset)
                target = match_va + sig.instruction_size + disp
            else:
                target = read_uint32(handle, match_va + sig.disp_offset)

            if not target:
                continue

            head = _read_ptr(handle, target, is_64bit)
            if not head:
                head = target

            if _validate_client_class(handle, head, is_64bit):
                logger.info("Found ClientClass head via %s at 0x%X", sig.name, head)
                return head

            if head != target and _validate_client_class(handle, target, is_64bit):
                logger.info(
                    "Found ClientClass head via %s (direct) at 0x%X",
                    sig.name,
                    target,
                )
                return target

    logger.warning("Could not find ClientClass head - all strategies exhausted")
    return 0

def _validate_client_class(handle: int, addr: int, is_64bit: bool) -> bool:

    layout = _get_layout(is_64bit)

    table_ptr = _read_ptr(handle, addr + layout["cc_table"], is_64bit)
    if not table_ptr:
        return False

    name_ptr = _read_ptr(handle, table_ptr + layout["rt_name"], is_64bit)
    if not name_ptr:
        return False

    name = read_string(handle, name_ptr, 64)
    if not name or len(name) < 2:
        return False

    if name.startswith("DT_") or name.startswith("m_"):
        return True

    return all(32 <= ord(c) < 127 for c in name[:16])
