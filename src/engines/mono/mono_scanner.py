
import struct
from typing import Dict, List, Optional, Tuple

from src.core.memory import (
    read_bytes, read_uint64, read_uint32, read_int32,
    read_string, get_module_info,
)

_MONO_MODULE_NAMES = [
    "mono-2.0-bdwgc.dll",
    "mono.dll",
    "MonoBleedingEdge.dll",
]

def find_mono_module(pid: int) -> Tuple[int, int, str]:
    for name in _MONO_MODULE_NAMES:
        base, size = get_module_info(pid, name)
        if base:
            print(f"[DEBUG] Mono: Found {name} at 0x{base:X} ({size // 1024} KB)")
            return base, size, name
    print("[DEBUG] Mono: No Mono runtime module found")
    return 0, 0, ""

def _parse_pe_exports(handle: int, module_base: int) -> Dict[str, int]:
    exports: Dict[str, int] = {}

    dos = read_bytes(handle, module_base, 0x40)
    if len(dos) < 0x40 or dos[:2] != b"MZ":
        return exports

    e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
    pe_hdr = read_bytes(handle, module_base + e_lfanew, 24)
    if len(pe_hdr) < 24 or pe_hdr[:4] != b"PE\x00\x00":
        return exports

    opt_header_size = struct.unpack_from("<H", pe_hdr, 20)[0]
    opt = read_bytes(handle, module_base + e_lfanew + 24, min(opt_header_size, 256))
    if len(opt) < 4:
        return exports

    opt_magic = struct.unpack_from("<H", opt, 0)[0]
    export_dd_off = 112 if opt_magic == 0x20B else 96

    if export_dd_off + 8 > len(opt):
        return exports

    export_rva = struct.unpack_from("<I", opt, export_dd_off)[0]
    if export_rva == 0:
        return exports

    export_dir = read_bytes(handle, module_base + export_rva, 40)
    if len(export_dir) < 40:
        return exports

    num_functions = struct.unpack_from("<I", export_dir, 20)[0]
    num_names    = struct.unpack_from("<I", export_dir, 24)[0]
    addr_rva     = struct.unpack_from("<I", export_dir, 28)[0]
    name_ptr_rva = struct.unpack_from("<I", export_dir, 32)[0]
    ord_rva      = struct.unpack_from("<I", export_dir, 36)[0]

    name_ptrs = read_bytes(handle, module_base + name_ptr_rva, num_names * 4)
    ordinals  = read_bytes(handle, module_base + ord_rva,      num_names * 2)
    addrs     = read_bytes(handle, module_base + addr_rva,     num_functions * 4)

    if len(name_ptrs) < num_names * 4:
        return exports

    for i in range(num_names):
        name_rva = struct.unpack_from("<I", name_ptrs, i * 4)[0]
        ordinal  = struct.unpack_from("<H", ordinals,  i * 2)[0]
        if ordinal >= num_functions:
            continue
        func_rva = struct.unpack_from("<I", addrs, ordinal * 4)[0]
        name = read_string(handle, module_base + name_rva, max_len=128)
        if name:
            exports[name] = module_base + func_rva

    return exports

def find_root_domain(handle: int, mono_base: int, mono_size: int) -> int:
    exports = _parse_pe_exports(handle, mono_base)
    print(f"[DEBUG] Mono: {len(exports)} exports found in mono module")

    for sym in ("mono_root_domain",):
        if sym in exports:
            domain_ptr = read_uint64(handle, exports[sym])
            if domain_ptr and domain_ptr > 0x10000:
                print(f"[DEBUG] Mono: root domain via {sym} = 0x{domain_ptr:X}")
                return domain_ptr

    for sym in ("mono_get_root_domain", "mono_domain_get"):
        if sym not in exports:
            continue
        func_addr = exports[sym]
        code = read_bytes(handle, func_addr, 48)
        if not code:
            continue
        for off in range(min(len(code) - 7, 32)):
            if code[off:off+3] == b"\x48\x8B\x05":
                disp = struct.unpack_from("<i", code, off + 3)[0]
                global_addr = func_addr + off + 7 + disp
                domain_ptr = read_uint64(handle, global_addr)
                if domain_ptr and 0x10000 < domain_ptr < 0x7FFFFFFFFFFF:
                    print(f"[DEBUG] Mono: root domain via {sym} MOV = 0x{domain_ptr:X}")
                    return domain_ptr
            if code[off:off+3] == b"\x48\x8D\x05":
                disp = struct.unpack_from("<i", code, off + 3)[0]
                global_addr = func_addr + off + 7 + disp
                domain_ptr = read_uint64(handle, global_addr)
                if domain_ptr and 0x10000 < domain_ptr < 0x7FFFFFFFFFFF:
                    print(f"[DEBUG] Mono: root domain via {sym} LEA = 0x{domain_ptr:X}")
                    return domain_ptr

    print("[DEBUG] Mono: root domain not found via exports")
    return 0

def _is_heap(v: int) -> bool:
    return 0x10000 < v < 0x7FFFFFFFFFFF

def _read_cstring(handle: int, ptr: int) -> str:
    if not _is_heap(ptr):
        return ""
    return read_string(handle, ptr, max_len=256)

def walk_domain_assemblies(handle: int, domain_ptr: int) -> List[int]:
    assemblies: List[int] = []

    for probe_off in range(0x80, 0x200, 8):
        list_ptr = read_uint64(handle, domain_ptr + probe_off)
        if not _is_heap(list_ptr):
            continue

        asm0 = read_uint64(handle, list_ptr)
        if not _is_heap(asm0):
            continue

        valid = False
        for img_off in (0x58, 0x60, 0x68, 0x50, 0x44, 0x48, 0x70):
            img_ptr = read_uint64(handle, asm0 + img_off)
            if not _is_heap(img_ptr):
                continue
            for name_off in (0x10, 0x18, 0x08, 0x20):
                name_ptr = read_uint64(handle, img_ptr + name_off)
                if not name_ptr:
                    continue
                name = _read_cstring(handle, name_ptr)
                if name and (".dll" in name.lower() or "mscorlib" in name.lower()):
                    valid = True
                    break
            if valid:
                break

        if not valid:
            continue

        node = list_ptr
        seen: set = set()
        while node and node not in seen and len(assemblies) < 1000:
            seen.add(node)
            data = read_uint64(handle, node)
            if _is_heap(data):
                assemblies.append(data)
            node = read_uint64(handle, node + 8)

        print(f"[DEBUG] Mono: {len(assemblies)} assemblies at domain+0x{probe_off:X}")
        return assemblies

    print("[DEBUG] Mono: could not locate assembly list in domain")
    return assemblies

def _walk_image_classes(handle: int, image_ptr: int) -> Dict[str, int]:
    result: Dict[str, int] = {}

    for cache_off in range(0x280, 0x500, 8):
        ht_ptr = read_uint64(handle, image_ptr + cache_off)
        if not _is_heap(ht_ptr):
            continue

        hdr = read_bytes(handle, ht_ptr, 48)
        if len(hdr) < 48:
            continue

        num_buckets = struct.unpack_from("<I", hdr, 0)[0]
        nnodes      = struct.unpack_from("<I", hdr, 12)[0]

        if num_buckets < 8 or num_buckets > 0x100000:
            continue
        if nnodes < 1 or nnodes > 100000:
            continue

        keys_ptr   = struct.unpack_from("<Q", hdr, 24)[0]
        hashes_ptr = struct.unpack_from("<Q", hdr, 32)[0]
        values_ptr = struct.unpack_from("<Q", hdr, 40)[0]

        if not (_is_heap(keys_ptr) and _is_heap(values_ptr)):
            continue

        keys_raw   = read_bytes(handle, keys_ptr,   num_buckets * 8)
        values_raw = read_bytes(handle, values_ptr, num_buckets * 8)
        hashes_raw = read_bytes(handle, hashes_ptr, num_buckets * 4) if _is_heap(hashes_ptr) else b""

        if len(keys_raw) < num_buckets * 8:
            continue

        found_count = 0
        for i in range(num_buckets):
            key_ptr   = struct.unpack_from("<Q", keys_raw,   i * 8)[0]
            value_ptr = struct.unpack_from("<Q", values_raw, i * 8)[0] if len(values_raw) >= (i+1)*8 else 0

            if not _is_heap(key_ptr) or not _is_heap(value_ptr):
                continue

            ns_ptr   = read_uint64(handle, key_ptr)
            name_ptr = read_uint64(handle, key_ptr + 8)

            class_name = ""
            if _is_heap(name_ptr):
                n = _read_cstring(handle, name_ptr)
                if n and n.isascii() and len(n) < 128:
                    ns = _read_cstring(handle, ns_ptr) if _is_heap(ns_ptr) else ""
                    class_name = f"{ns}.{n}" if ns else n

            if not class_name:
                n = _read_cstring(handle, key_ptr)
                if n and n.isascii() and len(n) < 128:
                    class_name = n

            if class_name and value_ptr:
                result[class_name] = value_ptr
                found_count += 1

        if found_count >= max(1, nnodes // 2):
            return result

    return result

def build_class_map(handle: int, domain_ptr: int) -> Dict[str, int]:
    class_map: Dict[str, int] = {}

    assemblies = walk_domain_assemblies(handle, domain_ptr)
    if not assemblies:
        return class_map

    for asm_ptr in assemblies:
        for img_off in (0x58, 0x60, 0x68, 0x50, 0x44, 0x48, 0x70):
            img_ptr = read_uint64(handle, asm_ptr + img_off)
            if not _is_heap(img_ptr):
                continue

            img_name = ""
            for name_off in (0x10, 0x18, 0x08):
                np = read_uint64(handle, img_ptr + name_off)
                if not np:
                    continue
                n = _read_cstring(handle, np)
                if n and ".dll" in n.lower():
                    img_name = n
                    break

            if not img_name:
                continue

            classes = _walk_image_classes(handle, img_ptr)
            if classes:
                class_map.update(classes)
                print(f"  [OK] {img_name.split('/')[-1].split(chr(92))[-1]}: {len(classes)} classes")
            break

    print(f"[DEBUG] Mono: {len(class_map)} total classes mapped")
    return class_map

_MONO_FIELD_STRUCT_SIZE = 0x20

def get_class_fields_from_memory(
    handle: int,
    class_ptr: int,
    expected_field_count: int,
) -> Dict[str, int]:
    result: Dict[str, int] = {}
    if not _is_heap(class_ptr):
        return result

    for fields_off in range(0x80, 0xD0, 8):
        fields_ptr = read_uint64(handle, class_ptr + fields_off)
        if not _is_heap(fields_ptr):
            continue

        name_ptr = read_uint64(handle, fields_ptr + 0x08)
        if not _is_heap(name_ptr):
            continue
        first_name = _read_cstring(handle, name_ptr)
        if not first_name or not first_name.replace("_", "").replace("<", "").replace(">", "").isalnum():
            continue

        count = min(expected_field_count, 512)
        for fi in range(count):
            faddr = fields_ptr + fi * _MONO_FIELD_STRUCT_SIZE
            fn_ptr = read_uint64(handle, faddr + 0x08)
            if not _is_heap(fn_ptr):
                break
            fname = _read_cstring(handle, fn_ptr)
            if not fname:
                break
            foffset = read_int32(handle, faddr + 0x18)
            if foffset < 0 or foffset > 0x10000:
                continue
            result[fname] = foffset

        if result:
            return result

    return result
