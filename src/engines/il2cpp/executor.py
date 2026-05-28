
import struct
from typing import Dict, List, Optional, Tuple
from functools import lru_cache

from src.core.memory import read_bytes, read_uint64, read_uint32, read_int32
from src.engines.il2cpp.metadata import Metadata, TypeDef, FieldDef
from src.core.models import SDKDump, StructInfo, MemberInfo, EnumInfo, FunctionInfo

PRIMITIVE_TYPES = {
    0x00: "END",
    0x01: "void",
    0x02: "bool",
    0x03: "char",
    0x04: "int8",
    0x05: "uint8",
    0x06: "int16",
    0x07: "uint16",
    0x08: "int32",
    0x09: "uint32",
    0x0A: "int64",
    0x0B: "uint64",
    0x0C: "float",
    0x0D: "double",
    0x0E: "string",
    0x0F: "Ptr",
    0x10: "ByRef",
    0x11: "ValueType",
    0x12: "Class",
    0x13: "Var",
    0x14: "Array",
    0x15: "GenericInst",
    0x16: "TypedByRef",
    0x18: "IntPtr",
    0x19: "UIntPtr",
    0x1D: "SZArray",
    0x1E: "MVar",
    0x41: "Modifier",
    0x45: "Sentinel",
    0x55: "Enum",
}

_PRIMITIVE_SIZES = {
    "void": 0, "bool": 1, "char": 2, "int8": 1, "uint8": 1,
    "int16": 2, "uint16": 2, "int32": 4, "uint32": 4,
    "int64": 8, "uint64": 8, "float": 4, "double": 8,
    "string": 0, "IntPtr": 0, "UIntPtr": 0, "object": 0,
    "Ptr": 0, "Class": 0, "SZArray": 0, "Array": 0,
}

_TYPE_LAYOUTS = [
    ("std_IHBB",  "<IHBB", 2, 0, 1, 8),
    ("BBHi",      "<BBHi", 0, 3, 2, 8),
    ("iBB",       "<iBB",  1, 0, -1, 6),
    ("HBBi",      "<HBBi", 1, 3, 0, 8),
]

class Il2CppExecutor:

    def __init__(
        self,
        metadata: Metadata,
        handle: int,
        base: int,
        meta_reg_addr: int,
        code_reg_addr: int = 0,
        module_size: int = 0,
        reg_data: dict = None,
    ):
        self.metadata = metadata
        self.handle = handle
        self.base = base
        self.meta_reg_addr = meta_reg_addr
        self.code_reg_addr = code_reg_addr
        self.module_size = module_size or (200 * 1024 * 1024)
        self.reg_data = reg_data or {}
        
        from src.core.memory import IS_32BIT, POINTER_SIZE
        self.is_32bit = IS_32BIT
        self.ptr_size = POINTER_SIZE

        self._field_offsets_ptr = self.reg_data.get("field_offsets", 0)
        if not self._field_offsets_ptr:
            self._probe_field_offsets()

        self._types_ptr = self.reg_data.get("types_array", 0)

        self._method_pointers: Dict[int, List[int]] = {}
        
        self.codegen_modules_ptr = self.reg_data.get("codegen_modules", 0)
        if self.codegen_modules_ptr or self.code_reg_addr:
            self._probe_code_registration()

        self._type_name_cache: Dict[int, str] = {}

        self._type_layout = _TYPE_LAYOUTS[0]
        if 29 <= metadata.version < 39:
            self._probe_type_layout()
        elif metadata.version >= 39:
            self._ensure_types_ptr()

        self._klass_map_v39: Optional[Dict[int, int]] = None

        self._field_default_map: Dict[int, Tuple[int, int]] = {}
        for fdv in metadata.field_default_values:
            self._field_default_map[fdv.field_index] = (fdv.type_index, fdv.data_index)

    def _probe_code_registration(self):
        from src.core.memory import read_pointer

        real_image_count = len(self.metadata.images)
        if real_image_count == 0:
            return

        try:
            ptr_array = self.codegen_modules_ptr
            count = real_image_count

            if not ptr_array and self.code_reg_addr:
                count_off = 0x40 if self.ptr_size == 8 else 0x3C
                ptr_off   = 0x48 if self.ptr_size == 8 else 0x40

                raw_count = read_int32(self.handle, self.code_reg_addr + count_off)
                ptr_array = read_pointer(self.handle, self.code_reg_addr + ptr_off)

                if raw_count > 0 and abs(raw_count - real_image_count) <= real_image_count:
                    count = raw_count

            if count <= 0 or not ptr_array:
                return

            count = min(count, real_image_count * 2, 500)

            for i in range(count):
                module_ptr = read_pointer(self.handle, ptr_array + i * self.ptr_size)
                if not module_ptr:
                    continue

                if getattr(self, "reg_data", {}).get("is_relative_pointers", False):
                    m_count = read_int32(self.handle, module_ptr + 4)
                    m_ptrs_rel = read_int32(self.handle, module_ptr + 8)
                    m_ptrs = module_ptr + 8 + m_ptrs_rel
                else:
                    m_count = read_int32(self.handle, module_ptr + (0x08 if self.ptr_size == 8 else 0x04))
                    m_ptrs = read_pointer(self.handle, module_ptr + (0x10 if self.ptr_size == 8 else 0x08))

                if m_count <= 0 or m_count > 50000:
                    continue
                module_end = self.base + self.module_size
                if not (self.base < m_ptrs < module_end):
                    continue

                capped = min(m_count, 50000)
                raw = read_bytes(self.handle, m_ptrs, capped * self.ptr_size)
                if raw and len(raw) >= self.ptr_size:
                    n = len(raw) // self.ptr_size
                    fmt = f"<{n}{'I' if self.ptr_size == 4 else 'Q'}"
                    self._method_pointers[i] = list(struct.unpack_from(fmt, raw))
        except Exception as e:
            print(f"[!!] IL2CPP: Failed to probe CodeRegistration/CodeGenModules: {e}")

    def _probe_field_offsets(self):
        if not self.meta_reg_addr: return
        from src.core.memory import read_pointer
        expected_types = len(self.metadata.type_definitions)
        def is_valid_ptr(v):
            return 0x10000 < v < getattr(self, "base", 0) + self.module_size

        def _score(arr_ptr: int) -> int:
            score = 0
            sample_n = min(20, expected_types)
            for idx in range(sample_n):
                entry = read_pointer(self.handle, arr_ptr + idx * self.ptr_size)
                if is_valid_ptr(entry) or entry == 0:
                    if entry != 0:
                        first_off = read_int32(self.handle, entry)
                        if 0x08 <= first_off <= 0x2000: score += 1
                    else:
                        score += 1
            return score

        best_ptr, best_score = 0, 0
        
        offsets_to_test = [0x58, 0x38, 0x78, 0x48, 0x68]
        if self.ptr_size == 4:
            offsets_to_test = [0x2C, 0x1C, 0x3C, 0x24, 0x34]
            
        for off in offsets_to_test:
            cand = read_pointer(self.handle, self.meta_reg_addr + off)
            if not is_valid_ptr(cand): continue
            s = _score(cand)
            if s > best_score:
                best_score, best_ptr = s, cand
        
        if best_ptr:
            self._field_offsets_ptr = best_ptr
            print(f"[OK] IL2CPP: fieldOffsets found (confidence={best_score})")

    def _probe_type_layout(self):
        raw = self.metadata.raw_data
        raw_len = len(raw)
        td_count = len(self.metadata.type_definitions)

        sample_indices = []
        for fd in self.metadata.field_definitions[:200]:
            ti = fd.type_index
            if 0 < ti < raw_len - 8:
                sample_indices.append(ti)
        if not sample_indices:
            return

        valid_enums = set(PRIMITIVE_TYPES.keys())

        best_layout = _TYPE_LAYOUTS[0]
        best_score = -1

        for layout in _TYPE_LAYOUTS:
            name, fmt, type_idx, data_idx, _attrs_idx, nbytes = layout
            score = 0
            for ti in sample_indices:
                if ti + nbytes > raw_len:
                    continue
                vals = struct.unpack_from(fmt, raw, ti)
                te = vals[type_idx]
                dv = vals[data_idx] & 0xFFFFFFFF

                if te not in valid_enums:
                    continue
                if te == 0x00:
                    continue
                score += 1
                if te in (0x11, 0x12, 0x55) and 0 <= dv < td_count:
                    score += 2

            if score > best_score:
                best_score = score
                best_layout = layout

        self._type_layout = best_layout
        print(f"[OK] IL2CPP: Type layout detected: {best_layout[0]} "
              f"(score={best_score}/{len(sample_indices)})")

    def _precache_field_offsets_ptrs(self):
        self._field_offsets_cache = {}
        if not getattr(self, "_field_offsets_ptr", 0):
            return

        total = len(self.metadata.type_definitions)
        raw = read_bytes(self.handle, self._field_offsets_ptr, total * self.ptr_size)
        if not raw:
            return

        count = len(raw) // self.ptr_size
        fmt = f'<{count}{"I" if self.ptr_size == 4 else "Q"}'
        ptrs = struct.unpack_from(fmt, raw)
        for i, p in enumerate(ptrs):
            if p and p > 0x10000:
                self._field_offsets_cache[i] = p

    def _precache_runtime_type_data(self):
        self._type_data_cache = {}
        if self.metadata.version < 31:
            return
        self._ensure_types_ptr()
        if not getattr(self, "_types_ptr", 0):
            return

        from src.core.memory import scatter_read_multiple

        unique_indices = set()
        for fd in self.metadata.field_definitions:
            if fd.type_index >= 0:
                unique_indices.add(fd.type_index)

        if not unique_indices:
            return

        idx_list = sorted(unique_indices)

        ptr_requests = [(self._types_ptr + ti * self.ptr_size, self.ptr_size) for ti in idx_list]
        BATCH = 256
        ptr_results = []
        for bs in range(0, len(ptr_requests), BATCH):
            batch = ptr_requests[bs:bs + BATCH]
            ptr_results.extend(scatter_read_multiple(self.handle, batch))

        ptr_fmt = '<I' if self.ptr_size == 4 else '<Q'
        type_struct_size = self.ptr_size + 4

        type_ptrs = []
        valid_indices = []
        for i, ti in enumerate(idx_list):
            raw = ptr_results[i] if i < len(ptr_results) else b""
            if raw and len(raw) >= self.ptr_size:
                tp = struct.unpack_from(ptr_fmt, raw)[0]
                if tp and tp > 0x10000:
                    type_ptrs.append((tp, type_struct_size))
                    valid_indices.append(ti)

        struct_results = []
        for bs in range(0, len(type_ptrs), BATCH):
            batch = type_ptrs[bs:bs + BATCH]
            struct_results.extend(scatter_read_multiple(self.handle, batch))

        for i, ti in enumerate(valid_indices):
            raw = struct_results[i] if i < len(struct_results) else b""
            if raw and len(raw) >= type_struct_size:
                data_val = struct.unpack_from(ptr_fmt, raw, 0)[0]
                packed = struct.unpack_from('<I', raw, self.ptr_size)[0]
                type_enum = (packed >> 16) & 0xFF
                attrs = packed & 0xFFFF
                self._type_data_cache[ti] = (type_enum, data_val, attrs)

    def get_field_offset(self, type_idx: int, field_local_idx: int) -> int:
        if not getattr(self, "_field_offsets_ptr", 0): return -1
        cache = getattr(self, "_field_offsets_cache", {})
        type_offsets_ptr = cache.get(type_idx)
        if type_offsets_ptr is None:
            from src.core.memory import read_pointer
            type_offsets_ptr = read_pointer(self.handle, self._field_offsets_ptr + type_idx * self.ptr_size)
        if not type_offsets_ptr or type_offsets_ptr < 0x10000: return -1
        return read_int32(self.handle, type_offsets_ptr + field_local_idx * 4)

    def _ensure_types_ptr(self):
        if getattr(self, "_types_ptr", 0):
            return
        if not self.meta_reg_addr:
            return
        from src.core.memory import read_pointer
        for off in ([0x1C, 0x0C, 0x04, 0x24, 0x14] if self.ptr_size == 4
                    else [0x38, 0x18, 0x08, 0x48, 0x28]):
            cand = read_pointer(self.handle, self.meta_reg_addr + off)
            if cand and cand > 0x10000:
                first_type_ptr = read_pointer(self.handle, cand)
                if first_type_ptr and first_type_ptr > 0x10000:
                    self._types_ptr = cand
                    return

    def _read_type_from_memory(self, type_idx: int):
        cache = getattr(self, "_type_data_cache", {})
        if type_idx in cache:
            te, dv, _attrs = cache[type_idx]
            return te, dv

        from src.core.memory import read_pointer
        self._ensure_types_ptr()
        if not getattr(self, "_types_ptr", 0):
            return None, None
        type_ptr = read_pointer(self.handle, self._types_ptr + type_idx * self.ptr_size)
        if not type_ptr or type_ptr < 0x10000:
            return None, None
        data_val = read_pointer(self.handle, type_ptr)
        packed = read_uint32(self.handle, type_ptr + self.ptr_size)
        type_enum = (packed >> 16) & 0xFF
        return type_enum, data_val

    @lru_cache(maxsize=4096)
    def _get_type_name(self, type_idx: int) -> str:
        if type_idx < 0: return "Unknown"
        from src.core.memory import read_pointer

        if self.metadata.version >= 39:
            type_enum, data_val = self._read_type_from_memory(type_idx)
            if type_enum is None:
                return f"type_{type_idx}"
        elif self.metadata.version >= 31:
            type_enum, data_val = self._read_type_from_memory(type_idx)
            if type_enum is None:
                return f"type_{type_idx}"
        elif self.metadata.version >= 29:
            layout = self._type_layout
            _, fmt, te_idx, dv_idx, _attrs_idx, nbytes = layout
            if type_idx + nbytes > len(self.metadata.raw_data) or type_idx < 0:
                return f"type_{type_idx}"
            vals = struct.unpack_from(fmt, self.metadata.raw_data, type_idx)
            type_enum = vals[te_idx]
            data_val = vals[dv_idx]
        else:
            type_enum, data_val = self._read_type_from_memory(type_idx)
            if type_enum is None:
                return f"type_{type_idx}"

        if type_enum in PRIMITIVE_TYPES:
            res = PRIMITIVE_TYPES[type_enum]
            if type_enum not in (0x11, 0x12, 0x55): return res

        if type_enum in (0x11, 0x12, 0x55):
            td_idx = data_val & 0xFFFFFFFF
            if 0 <= td_idx < len(self.metadata.type_definitions):
                td = self.metadata.type_definitions[td_idx]
                name = self.metadata.get_string(td.name_index)
                ns = self.metadata.get_string(td.namespace_index)
                return f"{ns}.{name}" if ns else name
            if data_val > 0x10000:
                resolved = self._resolve_class_name(data_val)
                if resolved:
                    return resolved

        if type_enum == 0x1D:
            if self.metadata.version >= 39:
                if data_val < len(self.metadata.type_definitions):
                    elem = self._get_type_name(data_val)
                else:
                    elem = "object"
            elif self.metadata.version >= 29:
                elem = self._get_type_name(data_val)
            else:
                elem = "Array"
            return f"{elem}[]"

        return f"type_{type_idx}"

    @lru_cache(maxsize=4096)
    def _resolve_class_name(self, class_ptr: int) -> Optional[str]:
        cache = getattr(self, '_class_name_cache', {})
        if class_ptr in cache:
            return cache[class_ptr]

        from src.core.memory import read_pointer
        if self.ptr_size == 4:
            name_ptr = read_pointer(self.handle, class_ptr + 0x08)
            ns_ptr = read_pointer(self.handle, class_ptr + 0x0C)
        else:
            name_ptr = read_pointer(self.handle, class_ptr + 0x10)
            ns_ptr = read_pointer(self.handle, class_ptr + 0x18)

        if not name_ptr or name_ptr < 0x10000:
            return None

        name_bytes = read_bytes(self.handle, name_ptr, 128)
        if not name_bytes:
            return None
        null_pos = name_bytes.find(b'\x00')
        if null_pos <= 0:
            return None
        name = name_bytes[:null_pos].decode('utf-8', errors='replace')

        if not all(c.isalnum() or c in '._<>[]`+' for c in name):
            return None

        ns = ""
        if ns_ptr and ns_ptr > 0x10000:
            ns_bytes = read_bytes(self.handle, ns_ptr, 128)
            if ns_bytes:
                ns_null = ns_bytes.find(b'\x00')
                if ns_null > 0:
                    ns = ns_bytes[:ns_null].decode('utf-8', errors='replace')

        result = f"{ns}.{name}" if ns else name
        if hasattr(self, '_class_name_cache'):
            self._class_name_cache[class_ptr] = result
        return result

    def _get_field_attrs(self, type_idx: int) -> int:
        if type_idx < 0: return 0
        if self.metadata.version >= 31:
            cache = getattr(self, "_type_data_cache", {})
            if type_idx in cache:
                _te, _dv, attrs = cache[type_idx]
                return attrs
            from src.core.memory import read_pointer
            self._ensure_types_ptr()
            if not getattr(self, "_types_ptr", 0): return 0
            type_ptr = read_pointer(self.handle, self._types_ptr + type_idx * self.ptr_size)
            if not type_ptr or type_ptr < 0x10000: return 0
            packed = read_uint32(self.handle, type_ptr + self.ptr_size)
            return packed & 0xFFFF
        if self.metadata.version >= 29:
            layout = self._type_layout
            _, fmt, _te, _dv, attrs_idx, nbytes = layout
            if attrs_idx < 0:
                return 0
            if type_idx + nbytes > len(self.metadata.raw_data):
                return 0
            vals = struct.unpack_from(fmt, self.metadata.raw_data, type_idx)
            return vals[attrs_idx]
        if getattr(self, "_types_ptr", 0):
            from src.core.memory import read_pointer
            type_ptr = read_pointer(self.handle, self._types_ptr + type_idx * self.ptr_size)
            if type_ptr: return read_uint32(self.handle, type_ptr + self.ptr_size) & 0xFFFF
        return 0

    def _is_enum_type(self, td: TypeDef) -> bool:
        if td.field_count >= 1 and td.field_start >= 0 and td.field_start < len(self.metadata.field_definitions):
            fd = self.metadata.field_definitions[td.field_start]
            if self.metadata.get_string(fd.name_index) == "value__": return True
        return False

    def _build_runtime_klass_map(self, log_fn=None):
        from src.core.memory import read_pointer, scatter_read_multiple

        self._ensure_types_ptr()
        if not getattr(self, "_types_ptr", 0):
            return

        types_count = 0
        if self.ptr_size == 4:
            types_count = read_int32(self.handle, self.meta_reg_addr + 0x18)
        else:
            types_count = read_int32(self.handle, self.meta_reg_addr + 0x30)

        if types_count <= 0 or types_count > 200000:
            for off in ([0x14, 0x18, 0x1C, 0x20] if self.ptr_size == 4
                        else [0x28, 0x30, 0x38]):
                val = read_int32(self.handle, self.meta_reg_addr + off)
                if 1000 < val < 200000:
                    types_count = val
                    break

        if types_count <= 0 or types_count > 200000:
            if log_fn:
                log_fn("[WARN] Could not read typesCount from MetadataRegistration")
            return

        if log_fn:
            log_fn(f"  Scanning {types_count} runtime types for Il2CppClass pointers...")
            log_fn(f"  _types_ptr=0x{self._types_ptr:X}, meta_reg=0x{self.meta_reg_addr:X}")

        token_to_tdidx: Dict[int, int] = {}
        for i, td in enumerate(self.metadata.type_definitions):
            if td.token:
                token_to_tdidx[td.token] = i

        name_to_tdidx: Dict[Tuple[str, str], int] = {}
        for i, td in enumerate(self.metadata.type_definitions):
            nm = self.metadata.get_string(td.name_index)
            ns = self.metadata.get_string(td.namespace_index)
            if nm:
                name_to_tdidx[(nm, ns or "")] = i

        self._klass_map_v39 = {}
        matched = 0
        ptr_fmt = '<I' if self.ptr_size == 4 else '<Q'

        types_array_size = types_count * self.ptr_size
        types_array_raw = read_bytes(self.handle, self._types_ptr, types_array_size)
        if not types_array_raw or len(types_array_raw) < self.ptr_size:
            if log_fn:
                log_fn("[WARN] Could not bulk-read types pointer array")
            return

        actual_count = len(types_array_raw) // self.ptr_size
        all_type_ptrs = struct.unpack_from(f'<{actual_count}{("I" if self.ptr_size == 4 else "Q")}', types_array_raw)
        del types_array_raw

        type_struct_size = self.ptr_size + 4
        valid_type_indices = []
        scatter_requests = []
        for ti in range(actual_count):
            tp = all_type_ptrs[ti]
            if tp and tp > 0x10000:
                valid_type_indices.append(ti)
                scatter_requests.append((tp, type_struct_size))

        if log_fn:
            log_fn(f"  Batch-reading {len(scatter_requests)} type structs (of {actual_count} total)...")
            if scatter_requests:
                sample = scatter_requests[:5]
                sample_addrs = ', '.join(f'0x{a:X}' for a, _ in sample)
                log_fn(f"  Sample type ptrs: {sample_addrs}")

        BATCH_SIZE = 256
        type_struct_data = []
        for batch_start in range(0, len(scatter_requests), BATCH_SIZE):
            batch = scatter_requests[batch_start:batch_start + BATCH_SIZE]
            results = scatter_read_multiple(self.handle, batch)
            type_struct_data.extend(results)

        klass_candidates = []
        _dbg_empty = 0
        _dbg_short = 0
        _dbg_type_enum_dist = {}
        for idx, ti in enumerate(valid_type_indices):
            raw = type_struct_data[idx]
            if not raw:
                _dbg_empty += 1
                continue
            if len(raw) < type_struct_size:
                _dbg_short += 1
                continue
            data_val = struct.unpack_from(ptr_fmt, raw, 0)[0]
            packed = struct.unpack_from('<I', raw, self.ptr_size)[0]
            type_enum = (packed >> 16) & 0xFF
            _dbg_type_enum_dist[type_enum] = _dbg_type_enum_dist.get(type_enum, 0) + 1

            if type_enum not in (0x11, 0x12, 0x55):
                continue
            if not data_val or data_val < 0x10000:
                continue

            klass_candidates.append((data_val, ti))

        del type_struct_data

        if log_fn:
            log_fn(f"  Found {len(klass_candidates)} CLASS/ValueType/Enum types, reading tokens...")
            if _dbg_empty or _dbg_short:
                log_fn(f"  [DIAG] {_dbg_empty} empty reads, {_dbg_short} short reads")
            top_enums = sorted(_dbg_type_enum_dist.items(), key=lambda x: -x[1])[:8]
            enum_str = ', '.join(f'0x{e:02X}:{c}' for e, c in top_enums)
            log_fn(f"  [DIAG] type_enum distribution: {enum_str}")

        if self.ptr_size == 4:
            klass_read_offset = 0x04
            klass_read_size = 0x58
            tok_offsets = [0x44, 0x48, 0x4C, 0x50, 0x54]
            name_off, ns_off = 0x08, 0x0C
        else:
            klass_read_offset = 0x08
            klass_read_size = 0xA8
            tok_offsets = [0x80, 0x88, 0x90, 0x98, 0xA0]
            name_off, ns_off = 0x10, 0x18

        klass_requests = [(kp, klass_read_size) for kp, _ in klass_candidates]
        klass_data = []
        for batch_start in range(0, len(klass_requests), BATCH_SIZE):
            batch = klass_requests[batch_start:batch_start + BATCH_SIZE]
            results = scatter_read_multiple(self.handle, batch)
            klass_data.extend(results)

        unmatched_klasses = []
        for idx, (klass_ptr, ti) in enumerate(klass_candidates):
            raw = klass_data[idx]
            if not raw or len(raw) < max(tok_offsets) + 4:
                unmatched_klasses.append(idx)
                continue

            td_idx = -1
            for tok_off in tok_offsets:
                if tok_off + 4 > len(raw):
                    continue
                tok = struct.unpack_from('<I', raw, tok_off)[0]
                if (tok >> 24) == 0x02 and (tok & 0x00FFFFFF) > 0:
                    if tok in token_to_tdidx:
                        td_idx = token_to_tdidx[tok]
                        break

            if td_idx >= 0 and td_idx not in self._klass_map_v39:
                self._klass_map_v39[td_idx] = klass_ptr
                matched += 1
            else:
                unmatched_klasses.append(idx)

        name_resolve_requests = []
        for idx in unmatched_klasses:
            klass_ptr, ti = klass_candidates[idx]
            raw = klass_data[idx]
            if not raw or len(raw) < ns_off + self.ptr_size:
                continue
            nm_ptr = struct.unpack_from(ptr_fmt, raw, name_off)[0]
            nsp = struct.unpack_from(ptr_fmt, raw, ns_off)[0]
            if nm_ptr and nm_ptr > 0x10000:
                name_resolve_requests.append((nm_ptr, nsp, klass_ptr, idx))

        del klass_data

        if name_resolve_requests:
            name_scatter = [(nm_ptr, 128) for nm_ptr, _, _, _ in name_resolve_requests]
            ns_scatter = [(nsp, 128) if nsp and nsp > 0x10000 else (0, 0)
                          for _, nsp, _, _ in name_resolve_requests]

            name_results = []
            for batch_start in range(0, len(name_scatter), BATCH_SIZE):
                batch = name_scatter[batch_start:batch_start + BATCH_SIZE]
                results = scatter_read_multiple(self.handle, batch)
                name_results.extend(results)

            ns_results = []
            for batch_start in range(0, len(ns_scatter), BATCH_SIZE):
                batch = ns_scatter[batch_start:batch_start + BATCH_SIZE]
                real_batch = [(a, s) if a > 0 else (1, 0) for a, s in batch]
                results = scatter_read_multiple(self.handle, real_batch)
                ns_results.extend(results)

            if not hasattr(self, '_class_name_cache'):
                self._class_name_cache = {}

            for i, (nm_ptr, nsp, klass_ptr, idx) in enumerate(name_resolve_requests):
                name_bytes = name_results[i] if i < len(name_results) else b""
                if not name_bytes:
                    continue
                null_pos = name_bytes.find(b'\x00')
                if null_pos <= 0:
                    continue
                nm = name_bytes[:null_pos].decode('utf-8', errors='replace')
                if not all(c.isalnum() or c in '._<>[]`+' for c in nm):
                    continue
                ns = ""
                if nsp and nsp > 0x10000 and i < len(ns_results):
                    ns_bytes = ns_results[i]
                    if ns_bytes:
                        ns_null = ns_bytes.find(b'\x00')
                        if ns_null > 0:
                            ns = ns_bytes[:ns_null].decode('utf-8', errors='replace')

                full_name = f"{ns}.{nm}" if ns else nm
                self._class_name_cache[klass_ptr] = full_name

                key = (nm, ns)
                if key in name_to_tdidx:
                    td_idx = name_to_tdidx[key]
                    if td_idx not in self._klass_map_v39:
                        self._klass_map_v39[td_idx] = klass_ptr
                        matched += 1

        if log_fn:
            log_fn(f"  [OK] Mapped {matched}/{len(self.metadata.type_definitions)} types to Il2CppClass pointers")

    @lru_cache(maxsize=8192)
    def _get_klass_ptr(self, type_idx: int) -> int:
        if type_idx < 0 or type_idx >= len(self.metadata.type_definitions):
            return 0

        if self.metadata.version >= 31:
            if self._klass_map_v39 is not None:
                mapped = self._klass_map_v39.get(type_idx, 0)
                if mapped:
                    return mapped
            td = self.metadata.type_definitions[type_idx]
            bti = td.byval_type_index
            if bti >= 0:
                type_enum, data_val = self._read_type_from_memory(bti)
                if type_enum in (0x11, 0x12, 0x55) and data_val and data_val > 0x10000:
                    return data_val
            return 0

        if self.metadata.version < 29:
            td = self.metadata.type_definitions[type_idx]
            bti = td.byval_type_index
            if bti < 0:
                return 0
            type_enum, data_val = self._read_type_from_memory(bti)
            if type_enum is None:
                return 0
            if type_enum in (0x11, 0x12, 0x55) and data_val > 0x10000:
                return data_val
            return 0

        return 0

    def _probe_static_fields_offset(self) -> int:
        from src.core.memory import scatter_read_multiple

        sample_klasses = []
        for type_idx, td in enumerate(self.metadata.type_definitions):
            if td.field_count <= 0:
                continue
            has_static = False
            for i in range(min(td.field_count, 20)):
                gi = td.field_start + i
                if gi >= len(self.metadata.field_definitions):
                    break
                fd = self.metadata.field_definitions[gi]
                attrs = self._get_field_attrs(fd.type_index)
                if attrs & 0x10:
                    has_static = True
                    break
            if not has_static:
                continue
            klass = self._get_klass_ptr(type_idx)
            if klass > 0x10000:
                sample_klasses.append(klass)
            if len(sample_klasses) >= 30:
                break

        if len(sample_klasses) < 3:
            return 0

        sample_klasses = sample_klasses[:20]

        if self.ptr_size == 4:
            test_offsets = list(range(0x40, 0xA0, 4))
            max_off = 0xA0
        else:
            test_offsets = list(range(0x80, 0x120, 8))
            max_off = 0x120

        read_size = max_off
        requests = [(klass, read_size) for klass in sample_klasses]
        klass_data = scatter_read_multiple(self.handle, requests)

        ptr_fmt = '<I' if self.ptr_size == 4 else '<Q'
        candidates_per_offset: Dict[int, int] = {}

        for off in test_offsets:
            hits = 0
            for i, klass in enumerate(sample_klasses):
                raw = klass_data[i] if i < len(klass_data) else b""
                if not raw or off + self.ptr_size > len(raw):
                    continue
                val = struct.unpack_from(ptr_fmt, raw, off)[0]
                if val and val > 0x10000:
                    if not (self.base <= val < self.base + self.module_size):
                        hits += 1
            candidates_per_offset[off] = hits

        if not candidates_per_offset:
            return 0

        best_off = max(candidates_per_offset, key=candidates_per_offset.get)
        best_hits = candidates_per_offset[best_off]
        if best_hits >= len(sample_klasses) * 0.4:
            return best_off
        return 0

    def _search_static_typeinfo(self, method_ptr: int) -> Optional[int]:
        if not method_ptr or method_ptr < self.base: return None
        target_addr = method_ptr
        if target_addr < self.base: target_addr += self.base

        code = read_bytes(self.handle, target_addr, 128)
        if not code: return None

        if getattr(self, "is_32bit", False):
            for i in range(len(code) - 5):
                if code[i] == 0xA1:
                    addr = struct.unpack_from("<I", code, i + 1)[0]
                    if self.base < addr < self.base + self.module_size:
                        return addr
                if code[i] == 0x8B and code[i + 1] in (0x0D, 0x15, 0x05, 0x35, 0x3D):
                    addr = struct.unpack_from("<I", code, i + 2)[0]
                    if self.base < addr < self.base + self.module_size:
                        return addr
            return None

        for i in range(len(code) - 7):
            if code[i:i+2] == b"\x48\x8B" and code[i+2] in (0x05, 0x0D, 0x15):
                rel = struct.unpack_from("<i", code, i+3)[0]
                target = target_addr + i + 7 + rel
                if self.base < target < self.base + self.module_size:
                    return target
        return None

    def walk_types(self, progress_callback=None, log_fn=None) -> SDKDump:
        dump = SDKDump()
        total = len(self.metadata.type_definitions)
        type_to_module: Dict[int, int] = {}
        module_to_method_start: Dict[int, int] = {}

        def _wlog(msg):
            if log_fn:
                log_fn(msg)
            else:
                print(msg)

        _wlog("  Pre-caching field offsets...")
        self._precache_field_offsets_ptrs()

        if self.metadata.version >= 31:
            _wlog("  Pre-caching runtime type data...")
            self._precache_runtime_type_data()
            self._build_runtime_klass_map(log_fn=_wlog)

        self._static_fields_off = self._probe_static_fields_offset()
        if self._static_fields_off:
            _wlog(f"  [OK] Il2CppClass.static_fields at +0x{self._static_fields_off:X}")
        else:
            _wlog("  [WARN] Could not determine Il2CppClass.static_fields offset")

        _bad_images = 0
        for i, img in enumerate(self.metadata.images):
            if img.type_count <= 0:
                module_to_method_start[i] = 0
                continue
            if (img.type_start < 0 or img.type_start >= total
                    or img.type_start + img.type_count > total):
                _bad_images += 1
                module_to_method_start[i] = 0
                continue

            first_type = self.metadata.type_definitions[img.type_start]
            module_to_method_start[i] = first_type.method_start

            for ti in range(img.type_start, img.type_start + img.type_count):
                type_to_module[ti] = i

        if _bad_images:
            _wlog(f"[WARN] {_bad_images}/{len(self.metadata.images)} images had invalid type ranges")

        from src.core.memory import read_pointer, scatter_read_multiple
        _klass_resolved = 0
        _static_resolved = 0

        _sf_cache = {}
        if self._static_fields_off and getattr(self, '_klass_map_v39', None):
            klass_items = [(tidx, kp) for tidx, kp in self._klass_map_v39.items() if kp > 0x10000]
            if klass_items:
                sf_requests = [(kp + self._static_fields_off, self.ptr_size) for _, kp in klass_items]
                sf_results = []
                BATCH = 256
                for bs in range(0, len(sf_requests), BATCH):
                    batch = sf_requests[bs:bs + BATCH]
                    sf_results.extend(scatter_read_multiple(self.handle, batch))
                ptr_fmt = '<I' if self.ptr_size == 4 else '<Q'
                for i, (tidx, kp) in enumerate(klass_items):
                    raw = sf_results[i] if i < len(sf_results) else b""
                    if raw and len(raw) >= self.ptr_size:
                        sf_ptr = struct.unpack_from(ptr_fmt, raw)[0]
                        if sf_ptr and sf_ptr > 0x10000:
                            _sf_cache[tidx] = sf_ptr

        for type_idx, td in enumerate(self.metadata.type_definitions):
            if progress_callback and type_idx % 1000 == 0: progress_callback(type_idx, total)

            name = self.metadata.get_string(td.name_index)
            if not name or name.startswith("<") or name == "<Module>": continue
            ns = self.metadata.get_string(td.namespace_index)
            full_name = f"{ns}.{name}" if ns else name
            if self._is_enum_type(td):
                info = self._walk_enum(type_idx, td, name, full_name)
                if info:
                    dump.enums.append(info)
                continue

            module_idx = type_to_module.get(type_idx, -1)
            module_ptrs = self._method_pointers.get(module_idx, [])
            module_m_start = module_to_method_start.get(module_idx, 0)

            s_info = self._walk_struct(type_idx, td, name, full_name, module_ptrs, module_m_start)
            if s_info:
                klass_ptr = self._get_klass_ptr(type_idx)
                if klass_ptr:
                    setattr(s_info, "klass_ptr", klass_ptr)
                    _klass_resolved += 1

                    sf_ptr = _sf_cache.get(type_idx)
                    if sf_ptr:
                        setattr(s_info, "static_fields_ptr", sf_ptr)
                        _static_resolved += 1
                    elif self._static_fields_off:
                        sf_ptr = read_pointer(self.handle, klass_ptr + self._static_fields_off)
                        if sf_ptr and sf_ptr > 0x10000:
                            setattr(s_info, "static_fields_ptr", sf_ptr)
                            _static_resolved += 1

                for j in range(min(2, td.method_count)):
                    global_mi = td.method_start + j
                    local_mi = global_mi - module_m_start
                    if 0 <= local_mi < len(module_ptrs):
                        m_ptr = module_ptrs[local_mi]
                        ti_ptr = self._search_static_typeinfo(m_ptr)
                        if ti_ptr:
                            setattr(s_info, "static_typeinfo_ptr", ti_ptr)
                            break
                dump.structs.append(s_info)

        _wlog(f"[OK] Resolved {_klass_resolved} Il2CppClass ptrs, {_static_resolved} static_fields ptrs")
        return dump

    _MAX_FIELDS_PER_TYPE = 5000
    _MAX_METHODS_PER_TYPE = 5000

    def _batch_read_field_offsets(self, type_idx: int, field_count: int) -> List[int]:
        cache = getattr(self, "_field_offsets_cache", {})
        type_offsets_ptr = cache.get(type_idx)
        if not type_offsets_ptr:
            if not getattr(self, "_field_offsets_ptr", 0):
                return [-1] * field_count
            from src.core.memory import read_pointer
            type_offsets_ptr = read_pointer(self.handle, self._field_offsets_ptr + type_idx * self.ptr_size)
        if not type_offsets_ptr or type_offsets_ptr < 0x10000:
            return [-1] * field_count
        raw = read_bytes(self.handle, type_offsets_ptr, field_count * 4)
        if not raw or len(raw) < 4:
            return [-1] * field_count
        n = len(raw) // 4
        offsets = list(struct.unpack_from(f'<{n}i', raw))
        while len(offsets) < field_count:
            offsets.append(-1)
        return offsets

    def _walk_struct(self, type_idx: int, td: TypeDef, name: str, full_name: str, module_ptrs: List[int], module_m_start: int) -> Optional[StructInfo]:
        members: List[MemberInfo] = []
        max_offset = 0
        field_count = min(td.field_count, self._MAX_FIELDS_PER_TYPE)

        all_offsets = self._batch_read_field_offsets(type_idx, field_count)

        for i in range(field_count):
            global_fi = td.field_start + i
            if global_fi >= len(self.metadata.field_definitions): continue
            fd = self.metadata.field_definitions[global_fi]
            f_name = self.metadata.get_string(fd.name_index)
            t_name = self._get_type_name(fd.type_index)
            attrs = self._get_field_attrs(fd.type_index)
            is_static = bool(attrs & 0x10)
            offset = all_offsets[i] if i < len(all_offsets) else -1
            raw_size = _PRIMITIVE_SIZES.get(t_name, -1)
            if raw_size <= 0:
                size = self.ptr_size
            else:
                size = raw_size
            mi = MemberInfo(name=f_name, offset=offset, size=size, type_name=t_name)
            setattr(mi, "is_static", is_static)
            members.append(mi)
            if not is_static and offset + size > max_offset: max_offset = offset + size

        functions: List[FunctionInfo] = []

        method_infos = []
        method_count = min(td.method_count, self._MAX_METHODS_PER_TYPE)
        for i in range(method_count):
            global_mi = td.method_start + i
            if global_mi >= len(self.metadata.method_definitions): continue
            md = self.metadata.method_definitions[global_mi]
            m_name = self.metadata.get_string(md.name_index)

            local_mi = global_mi - module_m_start
            m_ptr = module_ptrs[local_mi] if 0 <= local_mi < len(module_ptrs) else 0

            target_addr = m_ptr
            if 0 < target_addr < self.base: target_addr += self.base
            rv = m_ptr
            if rv > self.base: rv -= self.base
            abs_addr = m_ptr if m_ptr > self.base else (m_ptr + self.base if m_ptr else 0)
            method_infos.append((m_name, target_addr, abs_addr, rv))

        MAX_PATTERN_READS = 20
        pattern_map = {}
        for idx, (m_name, target_addr, abs_addr, rv) in enumerate(method_infos):
            if idx < MAX_PATTERN_READS and target_addr > 0x10000:
                pattern_bytes = read_bytes(self.handle, target_addr, 16)
                if pattern_bytes:
                    pattern_map[idx] = " ".join(f"{b:02X}" for b in pattern_bytes)

        for idx, (m_name, target_addr, abs_addr, rv) in enumerate(method_infos):
            f_info = FunctionInfo(
                name=m_name, address=abs_addr,
                rva=rv, flags=0, exec_func=abs_addr,
            )
            setattr(f_info, "pattern", pattern_map.get(idx, ""))
            functions.append(f_info)

        return StructInfo(
            name=name, full_name=full_name, address=type_idx,
            size=max_offset, is_class=True, members=members, functions=functions
        )

    def _walk_enum(self, type_idx: int, td: TypeDef, name: str, full_name: str) -> Optional[EnumInfo]:
        info = EnumInfo(name=name, full_name=full_name, address=type_idx)
        blob = self.metadata.field_default_value_data
        for i in range(td.field_count):
            global_fi = td.field_start + i
            if global_fi >= len(self.metadata.field_definitions): continue
            fd = self.metadata.field_definitions[global_fi]
            f_name = self.metadata.get_string(fd.name_index)
            if f_name == "value__": continue
            val = None
            if global_fi in self._field_default_map:
                _, data_index = self._field_default_map[global_fi]
                if 0 <= data_index < len(blob) - 3:
                    val = struct.unpack_from("<i", blob, data_index)[0]
            info.values.append((f_name, val if val is not None else i))
        return info
