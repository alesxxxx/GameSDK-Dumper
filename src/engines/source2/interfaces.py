import logging
import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from src.core.memory import enumerate_modules, get_pid_by_name, read_bytes, read_string, read_uint64
from src.core.scanner import resolve_rip

logger = logging.getLogger(__name__)

_INTERFACE_CREATE_FN_OFFSET = 0x00
_INTERFACE_NAME_OFFSET = 0x08
_INTERFACE_NEXT_OFFSET = 0x10
_MAX_INTERFACES_PER_MODULE = 512


@dataclass
class CS2InterfaceResult:
    name: str
    module: str
    rva: int
    absolute: int
    create_fn: int = 0
    found: bool = True
    error: str = ""


@dataclass
class CS2InterfaceModuleResult:
    module: str
    base: int
    size: int
    path: str = ""
    interfaces: List[CS2InterfaceResult] = field(default_factory=list)
    found: bool = True
    error: str = ""


def _read_c_string(handle: int, address: int, max_len: int = 256) -> str:
    if not address:
        return ""
    return read_string(handle, address, max_len=max_len)


def _read_pe_headers(handle: int, module_base: int):
    dos = read_bytes(handle, module_base, 0x40)
    if len(dos) < 0x40 or dos[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
    headers = read_bytes(handle, module_base + e_lfanew, 0x400)
    if len(headers) < 0x108 or headers[:4] != b"PE\x00\x00":
        return None

    coff_off = 4
    num_sections = struct.unpack_from("<H", headers, coff_off + 2)[0]
    opt_size = struct.unpack_from("<H", headers, coff_off + 16)[0]
    opt_off = coff_off + 20
    opt_magic = struct.unpack_from("<H", headers, opt_off)[0]
    if opt_magic == 0x20B:
        data_dir_off = opt_off + 112
    elif opt_magic == 0x10B:
        data_dir_off = opt_off + 96
    else:
        return None

    sec_table_rva = e_lfanew + opt_off + opt_size
    return e_lfanew, data_dir_off, sec_table_rva, num_sections


def get_export_rva(handle: int, module_base: int, export_name: str) -> int:
    headers_info = _read_pe_headers(handle, module_base)
    if not headers_info:
        return 0

    e_lfanew, data_dir_off, _, _ = headers_info
    headers = read_bytes(handle, module_base + e_lfanew, 0x400)
    if len(headers) <= data_dir_off + 8:
        return 0

    export_rva, export_size = struct.unpack_from("<II", headers, data_dir_off)
    if not export_rva or not export_size:
        return 0

    directory = read_bytes(handle, module_base + export_rva, 40)
    if len(directory) < 40:
        return 0

    number_of_functions = struct.unpack_from("<I", directory, 20)[0]
    number_of_names = struct.unpack_from("<I", directory, 24)[0]
    functions_rva = struct.unpack_from("<I", directory, 28)[0]
    names_rva = struct.unpack_from("<I", directory, 32)[0]
    ordinals_rva = struct.unpack_from("<I", directory, 36)[0]

    if number_of_names > 100000 or number_of_functions > 100000:
        return 0

    names_blob = read_bytes(handle, module_base + names_rva, number_of_names * 4)
    ordinals_blob = read_bytes(handle, module_base + ordinals_rva, number_of_names * 2)
    functions_blob = read_bytes(handle, module_base + functions_rva, number_of_functions * 4)
    if len(names_blob) < number_of_names * 4 or len(ordinals_blob) < number_of_names * 2:
        return 0

    for i in range(number_of_names):
        name_rva = struct.unpack_from("<I", names_blob, i * 4)[0]
        name = _read_c_string(handle, module_base + name_rva, max_len=128)
        if name != export_name:
            continue

        ordinal = struct.unpack_from("<H", ordinals_blob, i * 2)[0]
        if ordinal >= number_of_functions or len(functions_blob) < (ordinal + 1) * 4:
            return 0
        return struct.unpack_from("<I", functions_blob, ordinal * 4)[0]

    return 0


def read_interfaces_from_list(
    handle: int,
    module_name: str,
    module_base: int,
    list_head: int,
    *,
    max_interfaces: int = _MAX_INTERFACES_PER_MODULE,
) -> List[CS2InterfaceResult]:
    results: List[CS2InterfaceResult] = []
    seen: set[int] = set()
    reg_ptr = list_head

    while reg_ptr and reg_ptr not in seen and len(results) < max_interfaces:
        seen.add(reg_ptr)

        create_fn = read_uint64(handle, reg_ptr + _INTERFACE_CREATE_FN_OFFSET)
        name_ptr = read_uint64(handle, reg_ptr + _INTERFACE_NAME_OFFSET)
        name = _read_c_string(handle, name_ptr, max_len=128)
        instance_addr = resolve_rip(handle, create_fn) if create_fn else 0

        if name and instance_addr:
            rva = instance_addr - module_base
            if 0 <= rva < 0x10000000:
                results.append(
                    CS2InterfaceResult(
                        name=name,
                        module=module_name,
                        rva=rva,
                        absolute=instance_addr,
                        create_fn=create_fn,
                    )
                )

        reg_ptr = read_uint64(handle, reg_ptr + _INTERFACE_NEXT_OFFSET)

    results.sort(key=lambda item: item.name)
    return results


def find_module_interfaces(
    handle: int,
    module_name: str,
    module_base: int,
    module_size: int,
    path: str = "",
) -> CS2InterfaceModuleResult:
    export_rva = get_export_rva(handle, module_base, "CreateInterface")
    if not export_rva:
        return CS2InterfaceModuleResult(
            module=module_name,
            base=module_base,
            size=module_size,
            path=path,
            interfaces=[],
            found=False,
            error="CreateInterface export missing",
        )

    list_storage = resolve_rip(handle, module_base + export_rva)
    list_head = read_uint64(handle, list_storage) if list_storage else 0
    if not list_head:
        return CS2InterfaceModuleResult(
            module=module_name,
            base=module_base,
            size=module_size,
            path=path,
            interfaces=[],
            found=False,
            error="interface list head null",
        )

    interfaces = read_interfaces_from_list(handle, module_name, module_base, list_head)
    return CS2InterfaceModuleResult(
        module=module_name,
        base=module_base,
        size=module_size,
        path=path,
        interfaces=interfaces,
        found=bool(interfaces),
        error="" if interfaces else "interface list empty",
    )


def find_cs2_interfaces(
    handle: int,
    process_name: str = "cs2.exe",
    *,
    progress_callback: Optional[Callable[[str], None]] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> List[CS2InterfaceModuleResult]:
    def _log(msg: str) -> None:
        logger.info(msg)
        if log_fn:
            log_fn(msg)

    pid = get_pid_by_name(process_name)
    if not pid:
        raise RuntimeError(f"Process {process_name!r} not found")

    modules = enumerate_modules(pid)
    results: List[CS2InterfaceModuleResult] = []
    for module_name, base, size, path in modules:
        if not module_name.lower().endswith(".dll") or not base:
            continue
        result = find_module_interfaces(handle, module_name, base, size, path)
        if result.interfaces:
            if progress_callback:
                progress_callback(f"Resolved {module_name} interfaces...")
            _log(f"[Source2] Interfaces {module_name}: {len(result.interfaces)}")
            results.append(result)

    results.sort(key=lambda item: item.module.lower())
    return results


def interface_map(results: List[CS2InterfaceModuleResult]) -> Dict[str, Dict[str, int]]:
    out: Dict[str, Dict[str, int]] = {}
    for module in results:
        if not module.interfaces:
            continue
        out[module.module] = {item.name: item.rva for item in module.interfaces if item.found}
    return out
