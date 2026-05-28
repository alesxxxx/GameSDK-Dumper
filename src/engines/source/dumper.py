
import logging
from typing import Callable, Optional

from src.core.memory import get_module_info, get_pid_by_name
from src.core.models import SDKDump, MemberInfo, StructInfo
from src.engines.source.game_data import SourceGameProfile, identify_game
from src.engines.source.netvars import find_client_class_head, walk_netvars

logger = logging.getLogger(__name__)

def _source_table_to_class_name(table_name: str) -> str:

    if table_name.startswith("DT_") and len(table_name) > 3:
        return f"C{table_name[3:]}"
    return table_name

def _source_cpp_type_hint(prop_name: str, type_name: str, kind: str) -> str:

    if kind == "array":
        return "array"
    if kind == "datatable":
        return "datatable"
    if type_name == "Float":
        return "float"
    if type_name == "Vector":
        return "Vector"
    if type_name == "VectorXY":
        return "Vector2D"
    if type_name == "String":
        return "const char*"
    if type_name == "Int64":
        return "std::int64_t"
    if type_name == "Int":
        if prop_name.startswith(("m_b", "b")):
            return "bool"
        if prop_name.startswith(("m_h", "h")):
            return "EHANDLE"
        return "std::int32_t"
    return type_name

def dump_source(
    handle: int,
    process_name: str,
    game: Optional[SourceGameProfile] = None,
    progress_callback: Optional[Callable[[str], None]] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> SDKDump:

    def _log(msg: str) -> None:
        logger.info(msg)
        if log_fn:
            log_fn(msg)

    if game is None:
        game = identify_game(process_name)
    _log(f"[Source] Game: {game.name}  (64-bit: {game.is_64bit})")

    pid = get_pid_by_name(process_name)
    if not pid:
        raise RuntimeError(f"Process {process_name!r} not found")

    client_base, client_size = get_module_info(pid, game.client_module)
    if not client_base:
        raise RuntimeError(
            f"Could not find {game.client_module} in {process_name} (PID {pid}). "
            f"Is the game fully loaded?"
        )
    _log(
        f"[Source] {game.client_module}: base=0x{client_base:X}  "
        f"size={client_size // (1024 * 1024)} MB"
    )

    if progress_callback:
        progress_callback(f"Found {game.client_module} - scanning for netvars...")

    head_ptr = find_client_class_head(handle, client_base, client_size, game)
    if not head_ptr:
        raise RuntimeError(
            f"Could not locate ClientClass linked list head in {game.client_module}. "
            f"The game may need to be fully loaded (in a map, not just the menu)."
        )
    _log(f"[Source] ClientClass head: 0x{head_ptr:X}")

    if progress_callback:
        progress_callback("Walking ClientClass linked list...")

    netvar_tables, aliases = walk_netvars(
        handle, head_ptr, game.is_64bit, progress_callback,
    )

    _log(f"[Source] Extracted {len(netvar_tables)} RecvTables")

    structs = []
    total_props = 0

    for table_name, table in sorted(netvar_tables.items()):
        members = []
        for prop in table.props:
            members.append(
                MemberInfo(
                    name=prop.name,
                    offset=prop.offset,
                    size=prop.size,
                    type_name=prop.type_name,
                    array_dim=max(1, prop.elements or 1),
                    flags=prop.flags,
                    metadata={
                        "raw_name": prop.raw_name,
                        "kind": prop.kind,
                        "recv_type": prop.type_name,
                        "type_id": prop.type_id,
                        "flags_hex": f"0x{prop.flags:X}",
                        "cpp_type_hint": _source_cpp_type_hint(prop.name, prop.type_name, prop.kind),
                        "datatable_name": prop.datatable_name,
                        "elements": prop.elements,
                        "element_stride": prop.element_stride,
                        "element_type_name": prop.element_type_name,
                        "parent_array_name": prop.parent_array_name,
                    },
                )
            )
            total_props += 1

        structs.append(
            StructInfo(
                name=table_name,
                full_name=f"Source.{table_name}",
                address=0,
                size=0,
                super_name=_source_table_to_class_name(table.base_table_name) if table.base_table_name else "",
                is_class=True,
                package="Source",
                members=members,
                metadata={
                    "client_classes": sorted(table.client_classes),
                    "source_table_name": table_name,
                    "source_primary_class_name": (
                        sorted(table.client_classes)[0]
                        if table.client_classes else _source_table_to_class_name(table_name)
                    ),
                    "source_base_table_name": table.base_table_name,
                },
            )
        )

    _log(f"[Source] SDKDump: {len(structs)} structs, {total_props} properties")

    if game.validation_netvars:
        struct_lookup = {struct.name: struct for struct in structs}
        validated = 0
        missing = 0

        for table_name, expected_props in game.validation_netvars.items():
            struct = struct_lookup.get(table_name)
            if not struct:
                missing += len(expected_props)
                _log(f"[Source] WARNING Missing expected table: {table_name}")
                continue

            prop_names = {member.name for member in struct.members}
            raw_prop_names = {
                member.metadata.get("raw_name", member.name)
                for member in struct.members
            }
            for prop_name in expected_props:
                if prop_name in prop_names or prop_name in raw_prop_names:
                    validated += 1
                else:
                    missing += 1
                    _log(f"[Source] WARNING Missing expected netvar: {table_name}.{prop_name}")

        if validated > 0:
            _log(f"[Source] Validated {validated} known netvars")
        if missing > 0:
            _log(f"[Source] WARNING {missing} expected netvars not found")

    if progress_callback:
        progress_callback(f"Done - {len(structs)} tables, {total_props} netvars")

    return SDKDump(
        structs=structs,
        metadata={
            "source_aliases": aliases,
        },
    )
