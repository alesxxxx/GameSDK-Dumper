
import struct
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from src.core.memory import (
    read_bytes,
    read_uint64,
    read_uint32,
    read_int32,
    read_string,
    get_module_info,
)

MONO_MODULE_NAMES = [
    "mono-2.0-bdwgc.dll",
    "mono-2.0.dll",
    "mono.dll",
    "MonoBleedingEdge.dll",
]

_MONO_FIELD_STRUCT_SIZE = 0x20

@dataclass
class MonoFieldInfo:
    name: str
    offset: int
    type_ptr: int = 0

@dataclass
class MonoClassInfo:
    name: str
    namespace: str
    full_name: str
    class_ptr: int
    image_name: str = ""
    fields: List[MonoFieldInfo] = field(default_factory=list)
    parent_ptr: int = 0
    parent_name: str = ""
    field_count: int = 0
    is_valuetype: bool = False
    is_enum: bool = False

@dataclass
class MonoImageInfo:
    name: str
    image_ptr: int
    class_count: int = 0

@dataclass
class MonoWalkResult:
    domain_ptr: int = 0
    mono_module_name: str = ""
    mono_module_base: int = 0
    mono_module_size: int = 0
    assemblies: int = 0
    images: List[MonoImageInfo] = field(default_factory=list)
    classes: List[MonoClassInfo] = field(default_factory=list)
    class_map: Dict[str, int] = field(default_factory=dict)

def _is_heap(v: int) -> bool:
    return 0x10000 < v < 0x7FFFFFFFFFFF

def _read_cstring(handle: int, ptr: int, max_len: int = 256) -> str:
    if not _is_heap(ptr):
        return ""
    return read_string(handle, ptr, max_len=max_len)

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
    num_names     = struct.unpack_from("<I", export_dir, 24)[0]
    addr_rva      = struct.unpack_from("<I", export_dir, 28)[0]
    name_ptr_rva  = struct.unpack_from("<I", export_dir, 32)[0]
    ord_rva       = struct.unpack_from("<I", export_dir, 36)[0]

    name_ptrs = read_bytes(handle, module_base + name_ptr_rva, num_names * 4)
    ordinals  = read_bytes(handle, module_base + ord_rva, num_names * 2)
    addrs     = read_bytes(handle, module_base + addr_rva, num_functions * 4)

    if len(name_ptrs) < num_names * 4:
        return exports

    for i in range(num_names):
        name_rva = struct.unpack_from("<I", name_ptrs, i * 4)[0]
        ordinal  = struct.unpack_from("<H", ordinals, i * 2)[0]
        if ordinal >= num_functions:
            continue
        func_rva = struct.unpack_from("<I", addrs, ordinal * 4)[0]
        name = read_string(handle, module_base + name_rva, max_len=128)
        if name:
            exports[name] = module_base + func_rva

    return exports

class MonoWalker:

    def __init__(self, handle: int, pid: int):
        self.handle = handle
        self.pid = pid

        self.mono_base: int = 0
        self.mono_size: int = 0
        self.mono_name: str = ""
        self.domain_ptr: int = 0
        self._exports: Dict[str, int] = {}

    def attach(self) -> bool:
        for name in MONO_MODULE_NAMES:
            base, size = get_module_info(self.pid, name)
            if base:
                self.mono_base = base
                self.mono_size = size
                self.mono_name = name
                print(f"[OK] MonoWalker: {name} at 0x{base:X} ({size // 1024} KB)")
                break

        if not self.mono_base:
            print("[!!] MonoWalker: No Mono runtime module found")
            return False

        self._exports = _parse_pe_exports(self.handle, self.mono_base)
        print(f"[DEBUG] MonoWalker: {len(self._exports)} PE exports parsed")

        self.domain_ptr = self._find_root_domain()
        if self.domain_ptr:
            print(f"[OK] MonoWalker: Root domain at 0x{self.domain_ptr:X}")
        else:
            print("[--] MonoWalker: Root domain not resolved (game may still be loading)")

        return True

    def _find_root_domain(self) -> int:
        for sym in ("mono_root_domain",):
            if sym in self._exports:
                ptr = read_uint64(self.handle, self._exports[sym])
                if ptr and _is_heap(ptr):
                    return ptr

        for sym in ("mono_get_root_domain", "mono_domain_get"):
            if sym not in self._exports:
                continue
            func_addr = self._exports[sym]
            code = read_bytes(self.handle, func_addr, 48)
            if not code:
                continue
            for off in range(min(len(code) - 7, 32)):
                if code[off] == 0x48 and code[off + 1] in (0x8B, 0x8D) and code[off + 2] == 0x05:
                    disp = struct.unpack_from("<i", code, off + 3)[0]
                    global_addr = func_addr + off + 7 + disp
                    domain_ptr = read_uint64(self.handle, global_addr)
                    if domain_ptr and _is_heap(domain_ptr):
                        return domain_ptr

        return 0

    def walk_assemblies(self) -> List[int]:
        if not self.domain_ptr:
            return []

        assemblies: List[int] = []

        for probe_off in range(0x80, 0x200, 8):
            list_ptr = read_uint64(self.handle, self.domain_ptr + probe_off)
            if not _is_heap(list_ptr):
                continue

            asm0 = read_uint64(self.handle, list_ptr)
            if not _is_heap(asm0):
                continue

            if not self._validate_assembly(asm0):
                continue

            node = list_ptr
            seen: set = set()
            while node and node not in seen and len(assemblies) < 1000:
                seen.add(node)
                data = read_uint64(self.handle, node)
                if _is_heap(data):
                    assemblies.append(data)
                node = read_uint64(self.handle, node + 8)

            if assemblies:
                print(f"[OK] MonoWalker: {len(assemblies)} assemblies at domain+0x{probe_off:X}")
                return assemblies

        print("[--] MonoWalker: Could not locate assembly list in domain")
        return assemblies

    def _validate_assembly(self, asm_ptr: int) -> bool:
        for img_off in (0x58, 0x60, 0x68, 0x50, 0x44, 0x48, 0x70):
            img_ptr = read_uint64(self.handle, asm_ptr + img_off)
            if not _is_heap(img_ptr):
                continue
            for name_off in (0x10, 0x18, 0x08, 0x20):
                name_ptr = read_uint64(self.handle, img_ptr + name_off)
                if not name_ptr:
                    continue
                name = _read_cstring(self.handle, name_ptr)
                if name and (".dll" in name.lower() or "mscorlib" in name.lower()):
                    return True
        return False

    def get_image_from_assembly(self, asm_ptr: int) -> Tuple[int, str]:
        for img_off in (0x58, 0x60, 0x68, 0x50, 0x44, 0x48, 0x70):
            img_ptr = read_uint64(self.handle, asm_ptr + img_off)
            if not _is_heap(img_ptr):
                continue
            for name_off in (0x10, 0x18, 0x08):
                np = read_uint64(self.handle, img_ptr + name_off)
                if not np:
                    continue
                n = _read_cstring(self.handle, np)
                if n and ".dll" in n.lower():
                    return img_ptr, n
        return 0, ""

    def walk_image_classes(self, image_ptr: int) -> Dict[str, int]:
        result: Dict[str, int] = {}

        for cache_off in range(0x280, 0x500, 8):
            ht_ptr = read_uint64(self.handle, image_ptr + cache_off)
            if not _is_heap(ht_ptr):
                continue

            hdr = read_bytes(self.handle, ht_ptr, 48)
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

            keys_raw   = read_bytes(self.handle, keys_ptr, num_buckets * 8)
            values_raw = read_bytes(self.handle, values_ptr, num_buckets * 8)

            if len(keys_raw) < num_buckets * 8:
                continue

            found_count = 0
            for i in range(num_buckets):
                key_ptr   = struct.unpack_from("<Q", keys_raw, i * 8)[0]
                value_ptr = (
                    struct.unpack_from("<Q", values_raw, i * 8)[0]
                    if len(values_raw) >= (i + 1) * 8
                    else 0
                )
                if not _is_heap(key_ptr) or not _is_heap(value_ptr):
                    continue

                class_name = self._resolve_class_name_from_key(key_ptr)
                if class_name and value_ptr:
                    result[class_name] = value_ptr
                    found_count += 1

            if found_count >= max(1, nnodes // 2):
                return result

        return result

    def _resolve_class_name_from_key(self, key_ptr: int) -> str:
        ns_ptr   = read_uint64(self.handle, key_ptr)
        name_ptr = read_uint64(self.handle, key_ptr + 8)
        if _is_heap(name_ptr):
            n = _read_cstring(self.handle, name_ptr)
            if n and n.isascii() and len(n) < 128:
                ns = _read_cstring(self.handle, ns_ptr) if _is_heap(ns_ptr) else ""
                return f"{ns}.{n}" if ns else n

        n = _read_cstring(self.handle, key_ptr)
        if n and n.isascii() and len(n) < 128:
            return n

        return ""

    def walk_class_fields(
        self,
        class_ptr: int,
        max_fields: int = 512,
    ) -> List[MonoFieldInfo]:
        fields: List[MonoFieldInfo] = []
        if not _is_heap(class_ptr):
            return fields

        for fields_off in range(0x80, 0xD0, 8):
            fields_ptr = read_uint64(self.handle, class_ptr + fields_off)
            if not _is_heap(fields_ptr):
                continue

            first_name_ptr = read_uint64(self.handle, fields_ptr + 0x08)
            if not _is_heap(first_name_ptr):
                continue
            first_name = _read_cstring(self.handle, first_name_ptr)
            if not first_name or not self._is_valid_field_name(first_name):
                continue

            for fi in range(max_fields):
                faddr = fields_ptr + fi * _MONO_FIELD_STRUCT_SIZE
                fn_ptr = read_uint64(self.handle, faddr + 0x08)
                if not _is_heap(fn_ptr):
                    break
                fname = _read_cstring(self.handle, fn_ptr)
                if not fname:
                    break

                foffset = read_int32(self.handle, faddr + 0x18)
                if foffset < 0 or foffset > 0x10000:
                    continue

                type_ptr = read_uint64(self.handle, faddr + 0x00)
                fields.append(MonoFieldInfo(
                    name=fname,
                    offset=foffset,
                    type_ptr=type_ptr,
                ))

            if fields:
                return fields

        return fields

    @staticmethod
    def _is_valid_field_name(name: str) -> bool:
        return name.replace("_", "").replace("<", "").replace(">", "").isalnum()

    def read_class_metadata(self, class_ptr: int) -> Tuple[str, str, int, bool, bool]:
        name = ""
        namespace = ""
        parent_ptr = 0

        for base_off in (0x40, 0x48, 0x38, 0x50):
            np = read_uint64(self.handle, class_ptr + base_off)
            if not _is_heap(np):
                continue
            candidate = _read_cstring(self.handle, np)
            if candidate and candidate.isascii() and len(candidate) < 128:
                name = candidate
                nsp = read_uint64(self.handle, class_ptr + base_off + 8)
                if _is_heap(nsp):
                    ns_candidate = _read_cstring(self.handle, nsp)
                    if ns_candidate and ns_candidate.isascii():
                        namespace = ns_candidate
                break

        for p_off in (0x28, 0x30, 0x20):
            pp = read_uint64(self.handle, class_ptr + p_off)
            if _is_heap(pp):
                parent_ptr = pp
                break

        is_valuetype = False
        is_enum = False
        if parent_ptr:
            parent_name, _, _, _, _ = self.read_class_metadata(parent_ptr) if parent_ptr != class_ptr else ("", "", 0, False, False)
            if parent_name in ("ValueType", "Enum"):
                is_valuetype = True
            if parent_name == "Enum":
                is_enum = True

        return name, namespace, parent_ptr, is_valuetype, is_enum

    def walk_all(
        self,
        read_fields: bool = True,
        progress_callback=None,
    ) -> MonoWalkResult:
        result = MonoWalkResult(
            domain_ptr=self.domain_ptr,
            mono_module_name=self.mono_name,
            mono_module_base=self.mono_base,
            mono_module_size=self.mono_size,
        )

        if not self.domain_ptr:
            print("[!!] MonoWalker: Cannot walk without a root domain")
            return result

        asm_ptrs = self.walk_assemblies()
        result.assemblies = len(asm_ptrs)
        if not asm_ptrs:
            return result

        all_classes: Dict[str, int] = {}
        for asm_ptr in asm_ptrs:
            img_ptr, img_name = self.get_image_from_assembly(asm_ptr)
            if not img_ptr:
                continue

            classes = self.walk_image_classes(img_ptr)
            if classes:
                short_name = img_name.split("/")[-1].split("\\")[-1]
                print(f"  [OK] {short_name}: {len(classes)} classes")
                result.images.append(MonoImageInfo(
                    name=img_name,
                    image_ptr=img_ptr,
                    class_count=len(classes),
                ))
                all_classes.update(classes)

        result.class_map = all_classes
        print(f"[OK] MonoWalker: {len(all_classes)} total classes mapped")

        if read_fields:
            total = len(all_classes)
            for idx, (full_name, class_ptr) in enumerate(all_classes.items()):
                if progress_callback and idx % 200 == 0:
                    progress_callback(idx, total)

                fields = self.walk_class_fields(class_ptr)

                parent_name = ""
                parent_ptr = 0
                for p_off in (0x28, 0x30, 0x20):
                    pp = read_uint64(self.handle, class_ptr + p_off)
                    if _is_heap(pp) and pp in all_classes.values():
                        parent_ptr = pp
                        for pn, pv in all_classes.items():
                            if pv == pp:
                                parent_name = pn
                                break
                        break

                if "." in full_name:
                    ns, _, short_name = full_name.rpartition(".")
                else:
                    ns, short_name = "", full_name

                result.classes.append(MonoClassInfo(
                    name=short_name,
                    namespace=ns,
                    full_name=full_name,
                    class_ptr=class_ptr,
                    fields=fields,
                    parent_ptr=parent_ptr,
                    parent_name=parent_name,
                    field_count=len(fields),
                ))

            if progress_callback:
                progress_callback(total, total)

        print(
            f"[OK] MonoWalker: walk complete — "
            f"{len(result.classes)} classes, "
            f"{sum(c.field_count for c in result.classes)} fields"
        )
        return result

    def get_field_offsets(self, full_name: str, class_map: Dict[str, int]) -> Dict[str, int]:
        class_ptr = class_map.get(full_name, 0)
        if not class_ptr:
            return {}
        fields = self.walk_class_fields(class_ptr)
        return {f.name: f.offset for f in fields}
