
import struct
from dataclasses import dataclass, field
from typing import List, Optional

METADATA_SANITY = 0xFAB11BAF
MIN_VERSION = 16
MAX_VERSION = 40

@dataclass
class TypeDef:
    name_index: int
    namespace_index: int
    parent_index: int
    element_type_index: int
    flags: int
    field_start: int
    field_count: int
    method_start: int
    method_count: int
    byval_type_index: int = 0
    declaring_type_index: int = -1
    nested_types_start: int = 0
    nested_type_count: int = 0
    token: int = 0

@dataclass
class FieldDef:
    name_index: int
    type_index: int
    token: int

@dataclass
class MethodDef:
    name_index: int
    declaring_type: int
    return_type: int
    param_start: int
    param_count: int
    token: int

@dataclass
class FieldDefaultValue:
    field_index: int
    type_index: int
    data_index: int

@dataclass
class ImageDef:
    name_index: int
    assembly_index: int
    type_start: int
    type_count: int
    token: int = 0

@dataclass
class Metadata:
    version: int
    string_data: bytes
    type_definitions: List[TypeDef]
    field_definitions: List[FieldDef]
    method_definitions: List[MethodDef]
    field_default_values: List[FieldDefaultValue]
    field_default_value_data: bytes
    images: List[ImageDef]
    raw_data: bytes

    def get_string(self, index: int) -> str:
        if index < 0 or index >= len(self.string_data):
            return ""
        end = self.string_data.find(b"\x00", index)
        if end < 0:
            end = len(self.string_data)
        try:
            return self.string_data[index:end].decode("utf-8", errors="replace")
        except Exception:
            return ""

_HEADER_READ_SIZE = 512
_MAX_HEADER_PAIRS = 60

def _parse_header_pairs(data, version=0):
    pairs = []
    file_size = len(data)
    stride = 12 if version >= 39 else 8
    for i in range(_MAX_HEADER_PAIRS):
        pos = 8 + i * stride
        if pos + 8 > file_size:
            break
        if version >= 39:
            if pos + 12 > file_size:
                break
            off, cnt, explicit_count = struct.unpack_from("<3i", data, pos)
        else:
            off, cnt = struct.unpack_from("<2i", data, pos)
            explicit_count = -1
        pairs.append((off, cnt, explicit_count))
    return pairs

def _find_section_by_entry_count(
    pairs, file_data, entry_size, min_count, max_count, description,
    used_indices=None,
):
    file_size = len(file_data)
    if used_indices is None:
        used_indices = set()

    for i, (off, byte_count, explicit_count) in enumerate(pairs):
        if i in used_indices:
            continue
        if off < 0x40 or off >= file_size:
            continue
        if byte_count <= 0:
            continue
        if off + byte_count > file_size:
            continue
        if byte_count % entry_size != 0:
            continue
        entry_count = byte_count // entry_size
        
        if entry_count < min_count or entry_count > max_count:
            continue
        print(
            f"[DEBUG] {description}: found at pair index {i}, "
            f"offset=0x{off:X}, bytes={byte_count}, entries={entry_count}"
        )
        used_indices.add(i)
        return off, byte_count, i

    return 0, 0, -1

def _find_section_by_byte_range(
    pairs, file_data, min_bytes, max_bytes, description,
    used_indices=None,
):
    file_size = len(file_data)
    if used_indices is None:
        used_indices = set()

    for i, (off, byte_count, _) in enumerate(pairs):
        if i in used_indices:
            continue
        if off < 0x40 or off >= file_size:
            continue
        if byte_count < min_bytes or byte_count > max_bytes:
            continue
        if off + byte_count > file_size:
            continue
        print(
            f"[DEBUG] {description}: found at pair index {i}, "
            f"offset=0x{off:X}, bytes={byte_count}"
        )
        used_indices.add(i)
        return off, byte_count, i

    return 0, 0, -1

def _get_typedef_size(version: int) -> int:
    if version >= 39:
        return 76
    if version >= 31:
        return 88
    if version >= 29:
        return 92
    if version >= 27:
        return 88
    if version >= 24:
        return 80
    if version >= 21:
        return 76
    return 76

def _get_typedef_indices_size(version: int) -> int:
    return 32 if version >= 27 else 28

def _parse_typedef_v24plus(data: bytes, offset: int, version: int) -> TypeDef:
    if version >= 39:
        layout = _V39_TYPEDEF_LAYOUT
        raw = struct.unpack_from("<5i", data, offset)
        name_idx       = raw[0]
        namespace_idx  = raw[1]
        byval_type_idx = raw[2]
        declaring_type = raw[3]
        parent_idx     = raw[4]

        starts = struct.unpack_from("<9i", data, offset + layout["starts_offset"])
        field_start        = starts[0]
        method_start       = starts[1]
        nested_types_start = starts[4]

        counts = struct.unpack_from("<8H", data, offset + layout["counts_offset"])
        field_count       = counts[layout["field_idx"]]
        method_count      = counts[layout["method_idx"]]
        nested_type_count = counts[layout["nested_idx"]]

        token = struct.unpack_from("<i", data, offset + layout["token_offset"])[0]

        return TypeDef(
            name_index=name_idx, namespace_index=namespace_idx,
            parent_index=parent_idx, element_type_index=byval_type_idx,
            flags=0, field_start=field_start, field_count=field_count,
            method_start=method_start, method_count=method_count,
            byval_type_index=byval_type_idx, declaring_type_index=declaring_type,
            nested_types_start=nested_types_start, nested_type_count=nested_type_count,
            token=token,
        )

    if version >= 31:
        raw = struct.unpack_from("<7i", data, offset)
        name_idx       = raw[0]
        namespace_idx  = raw[1]
        byval_type_idx = raw[2]
        declaring_type = raw[3]
        parent_idx     = raw[4]
        element_type   = raw[5]
        flags = struct.unpack_from("<I", data, offset + 28)[0]
        starts_off = offset + 32
        counts_off = offset + 64
    elif version >= 27:
        raw = struct.unpack_from("<8i", data, offset)
        name_idx       = raw[0]
        namespace_idx  = raw[1]
        byval_type_idx = raw[2]
        declaring_type = raw[4]
        parent_idx     = raw[5]
        element_type   = raw[6]
        flags = struct.unpack_from("<I", data, offset + 32)[0]
        starts_off = offset + 36
        counts_off = offset + 68
    else:
        raw = struct.unpack_from("<7i", data, offset)
        name_idx       = raw[0]
        namespace_idx  = raw[1]
        byval_type_idx = raw[2]
        declaring_type = raw[3]
        parent_idx     = raw[4]
        element_type   = raw[5]
        flags = struct.unpack_from("<I", data, offset + 28)[0]
        starts_off = offset + 32
        counts_off = offset + 64

    starts = struct.unpack_from("<8i", data, starts_off)
    field_start        = starts[0]
    method_start       = starts[1]
    nested_types_start = starts[4]

    counts = struct.unpack_from("<8H", data, counts_off)
    method_count      = counts[0]
    field_count       = counts[2]
    nested_type_count = counts[4]

    token_off = offset + _get_typedef_size(version) - 4
    token = struct.unpack_from("<I", data, token_off)[0] if version >= 24 else 0

    return TypeDef(
        name_index=name_idx, namespace_index=namespace_idx,
        parent_index=parent_idx, element_type_index=element_type,
        flags=flags, field_start=field_start, field_count=field_count,
        method_start=method_start, method_count=method_count,
        byval_type_index=byval_type_idx, declaring_type_index=declaring_type,
        nested_types_start=nested_types_start, nested_type_count=nested_type_count,
        token=token,
    )

def _parse_typedef_pre24(data: bytes, offset: int, version: int) -> TypeDef:
    vals = struct.unpack_from("<6iI", data, offset)
    name_idx       = vals[0]
    namespace_idx  = vals[1]
    byval_type_idx = vals[2]
    declaring_type = vals[3]
    parent_idx     = vals[4]
    element_type   = vals[5]
    flags          = vals[6]

    starts = struct.unpack_from("<8i", data, offset + 28)
    field_start        = starts[0]
    method_start       = starts[1]
    nested_types_start = starts[4]

    counts = struct.unpack_from("<8H", data, offset + 60)
    method_count      = counts[0]
    field_count       = counts[2]
    nested_type_count = counts[4]

    return TypeDef(
        name_index=name_idx,
        namespace_index=namespace_idx,
        parent_index=parent_idx,
        element_type_index=element_type,
        flags=flags,
        field_start=field_start,
        field_count=field_count,
        method_start=method_start,
        method_count=method_count,
        byval_type_index=byval_type_idx,
        declaring_type_index=declaring_type,
        nested_types_start=nested_types_start,
        nested_type_count=nested_type_count,
    )

_FIELD_DEFAULT_VALUE_SIZE = 12
_METHOD_DEF_SIZE_V24 = 28
_METHOD_DEF_SIZE_V31 = 36

def _get_field_def_size(version: int) -> int:
    if version >= 39:
        return 10
    if 24 <= version <= 28:
        return 16
    return 12

def _parse_field_def(data: bytes, offset: int, version: int = 29) -> FieldDef:
    if version >= 39:
        name_idx = struct.unpack_from("<i", data, offset)[0]
        type_idx = struct.unpack_from("<H", data, offset + 4)[0]
        token = struct.unpack_from("<I", data, offset + 6)[0]
        return FieldDef(name_index=name_idx, type_index=type_idx, token=token)
    if 24 <= version <= 28:
        name_idx, type_idx, _custom_attr, token = struct.unpack_from("<iiIi", data, offset)
    else:
        name_idx, type_idx, token = struct.unpack_from("<iiI", data, offset)
    return FieldDef(name_index=name_idx, type_index=type_idx, token=token)

def _parse_method_def(data: bytes, offset: int, version: int) -> MethodDef:
    if version >= 31:
        vals = struct.unpack_from("<9i", data, offset)
        return MethodDef(
            name_index=vals[0],
            declaring_type=vals[1],
            return_type=vals[2],
            param_start=0,
            param_count=0,
            token=vals[6],
        )
    vals = struct.unpack_from("<iiiihh", data, offset)
    return MethodDef(
        name_index=vals[0],
        declaring_type=vals[1],
        return_type=vals[2],
        param_start=vals[3],
        param_count=vals[4],
        token=0,
    )

def _get_method_def_size(version: int) -> int:
    if version >= 31:
        return _METHOD_DEF_SIZE_V31
    if version >= 24:
        return 28
    return 24

def _parse_field_default_value(data: bytes, offset: int) -> FieldDefaultValue:
    field_idx, type_idx, data_idx = struct.unpack_from("<iii", data, offset)
    return FieldDefaultValue(
        field_index=field_idx,
        type_index=type_idx,
        data_index=data_idx,
    )

_V39_IMAGE_LAYOUT = {"name": 0, "assembly": 4, "type_start": 8, "type_count": 12}
_V39_TYPEDEF_LAYOUT = {
    "starts_offset": 20,
    "counts_offset": 56,
    "token_offset": 72,
    "field_idx": 0,
    "method_idx": 2,
    "nested_idx": 4,
}

def _detect_v39_typedef_layout(
    data: bytes,
    td_off: int,
    td_size: int,
    td_num: int,
    field_def_num: int,
    approx_method_num: int,
) -> dict:
    candidates = [
        {"starts_offset": 20, "counts_offset": 56, "token_offset": 72, "field_idx": 0, "method_idx": 2, "nested_idx": 4},
        {"starts_offset": 20, "counts_offset": 56, "token_offset": 72, "field_idx": 1, "method_idx": 0, "nested_idx": 4},
        {"starts_offset": 20, "counts_offset": 56, "token_offset": 72, "field_idx": 0, "method_idx": 1, "nested_idx": 4},
        {"starts_offset": 20, "counts_offset": 56, "token_offset": 72, "field_idx": 1, "method_idx": 2, "nested_idx": 4},
        {"starts_offset": 20, "counts_offset": 56, "token_offset": 72, "field_idx": 2, "method_idx": 0, "nested_idx": 4},
    ]

    best = candidates[0]
    best_score = None
    best_summary = None

    for cand in candidates:
        total_fields = 0
        total_methods = 0
        sane_rows = 0
        max_field_count = 0
        max_method_count = 0

        try:
            for i in range(td_num):
                row_off = td_off + i * td_size
                starts = struct.unpack_from("<9i", data, row_off + cand["starts_offset"])
                counts = struct.unpack_from("<8H", data, row_off + cand["counts_offset"])
                field_start = starts[0]
                method_start = starts[1]
                field_count = counts[cand["field_idx"]]
                method_count = counts[cand["method_idx"]]
                nested_count = counts[cand["nested_idx"]]

                total_fields += field_count
                total_methods += method_count
                max_field_count = max(max_field_count, field_count)
                max_method_count = max(max_method_count, method_count)

                if (
                    field_start >= -1 and method_start >= -1 and
                    field_count < 10000 and method_count < 10000 and nested_count < 10000
                ):
                    sane_rows += 1
        except struct.error:
            continue

        field_delta = abs(total_fields - field_def_num)
        method_delta = abs(total_methods - approx_method_num)
        score = (
            field_delta,
            method_delta,
            -sane_rows,
            max_field_count + max_method_count,
        )
        if best_score is None or score < best_score:
            best = cand
            best_score = score
            best_summary = (total_fields, total_methods, sane_rows)

    if best_summary:
        print(
            "[DEBUG] v39 typedef layout:"
            f" field_idx={best['field_idx']} method_idx={best['method_idx']}"
            f" totals(fields={best_summary[0]}, methods={best_summary[1]}, sane={best_summary[2]}/{td_num})"
        )
    return best

def _detect_v39_image_layout(data: bytes, img_off: int, img_size: int, img_num: int,
                              td_num: int, string_data: bytes) -> dict:
    best_layout = None
    best_score = -1

    max_field = img_size - 4
    for ts_off in range(0, max_field + 1, 4):
        for tc_off in range(0, max_field + 1, 4):
            if ts_off == tc_off:
                continue
            ts0 = struct.unpack_from("<i", data, img_off + ts_off)[0]
            tc0 = struct.unpack_from("<i", data, img_off + tc_off)[0]
            if ts0 < 0 or tc0 <= 0 or tc0 > td_num or ts0 + tc0 > td_num:
                continue

            total_tc = 0
            max_end = 0
            valid = True
            for i in range(img_num):
                off = img_off + i * img_size
                ts = struct.unpack_from("<i", data, off + ts_off)[0]
                tc = struct.unpack_from("<i", data, off + tc_off)[0]
                if ts < 0 or tc < 0 or ts + tc > td_num:
                    valid = False
                    break
                total_tc += tc
                if ts + tc > max_end:
                    max_end = ts + tc
            if not valid:
                continue

            score = 0
            if total_tc == td_num:
                score += 100
            elif abs(total_tc - td_num) < td_num * 0.01:
                score += 50
            else:
                continue

            if max_end <= td_num:
                score += 20

            if score > best_score:
                best_score = score
                best_layout = (ts_off, tc_off)

    if not best_layout:
        print(f"[WARN] v39 image layout auto-detect failed, using fallback")
        return {"name": 0, "assembly": 4, "type_start": 8, "type_count": 12}

    ts_off, tc_off = best_layout

    name_off = 0
    best_name_score = 0
    for n_off in range(0, max_field + 1, 4):
        if n_off in (ts_off, tc_off):
            continue
        ns = 0
        for i in range(min(10, img_num)):
            off = img_off + i * img_size
            ni = struct.unpack_from("<i", data, off + n_off)[0]
            if 0 <= ni < len(string_data):
                end = string_data.find(b"\x00", ni)
                if end > ni:
                    s = string_data[ni:end]
                    if b"." in s and len(s) < 200:
                        ns += 1
        if ns > best_name_score:
            best_name_score = ns
            name_off = n_off

    asm_off = 0
    for a_off in range(0, max_field + 1, 4):
        if a_off in (ts_off, tc_off, name_off):
            continue
        v0 = struct.unpack_from("<i", data, img_off + a_off)[0]
        if 0 <= v0 < img_num:
            asm_off = a_off
            break

    layout = {"name": name_off, "assembly": asm_off,
              "type_start": ts_off, "type_count": tc_off}
    print(f"[OK] v39 image layout detected: type_start=+{ts_off}, type_count=+{tc_off}, "
          f"name=+{name_off}, assembly=+{asm_off} (score={best_score})")
    return layout

def _parse_image_def(data: bytes, offset: int, version: int) -> ImageDef:
    if version >= 39:
        layout = _V39_IMAGE_LAYOUT
        name_idx     = struct.unpack_from("<i", data, offset + layout["name"])[0]
        assembly_idx = struct.unpack_from("<i", data, offset + layout["assembly"])[0]
        type_start   = struct.unpack_from("<i", data, offset + layout["type_start"])[0]
        type_count   = struct.unpack_from("<i", data, offset + layout["type_count"])[0]
        return ImageDef(
            name_index=name_idx,
            assembly_index=assembly_idx,
            type_start=type_start,
            type_count=type_count,
        )
    if version >= 24:
        vals = struct.unpack_from("<iiiiiiiiii", data, offset)
        if version >= 31:
            return ImageDef(
                name_index=vals[0],
                assembly_index=vals[1],
                type_start=vals[2],
                type_count=vals[3],
                token=vals[7],
            )
        return ImageDef(
            name_index=vals[0],
            assembly_index=vals[1],
            type_start=vals[2],
            type_count=vals[5],
            token=vals[7],
        )
    else:
        vals = struct.unpack_from("<iiii", data, offset)
        return ImageDef(
            name_index=vals[0],
            assembly_index=vals[1],
            type_start=vals[2],
            type_count=vals[3],
        )

def _get_image_def_size(version: int) -> int:
    if version >= 39:
        return 68
    if version >= 24:
        return 40
    return 28

def load_metadata(path: str) -> Metadata:
    with open(path, "rb") as f:
        data = f.read()

    if len(data) < _HEADER_READ_SIZE:
        raise ValueError(
            f"global-metadata.dat too small ({len(data)} bytes, need >={_HEADER_READ_SIZE})"
        )

    sanity, version = struct.unpack_from("<Ii", data, 0)
    if sanity != METADATA_SANITY:
        raise ValueError(
            f"Invalid metadata sanity: 0x{sanity:08X} (expected 0x{METADATA_SANITY:08X}). "
            f"File may be encrypted or not a global-metadata.dat."
        )
    if version < MIN_VERSION or version > MAX_VERSION:
        raise ValueError(
            f"Unsupported metadata version {version} (supported: {MIN_VERSION}–{MAX_VERSION})"
        )

    print(f"[DEBUG] IL2CPP metadata: version={version}, file_size={len(data)}")

    try:
        pairs = _parse_header_pairs(data, version)
        print(f"[DEBUG] header: parsed {len(pairs)} section pairs")
        used = set()

        str_off, str_count = 0, 0
        if len(pairs) > 2:
            _s_off, _s_cnt, _ = pairs[2]
            if 0x40 <= _s_off < len(data) and _s_cnt > 0 and _s_off + _s_cnt <= len(data):
                str_off, str_count = _s_off, _s_cnt
                used.update({0, 1, 2})
                print(
                    f"[DEBUG] strings: direct read pair 2, "
                    f"offset=0x{str_off:X}, bytes={str_count}"
                )
        if str_count == 0:
            str_off, str_count, _ = _find_section_by_byte_range(
                pairs, data, 1000, len(data), "strings (fallback probe)", used,
            )

        td_size = _get_typedef_size(version)
        td_off, td_count, td_idx = 0, 0, -1
        for try_size in [td_size, 92, 88, 80, 76, 84, 96]:
            td_off, td_count, td_idx = _find_section_by_entry_count(
                pairs, data, try_size, 500, 500_000,
                f"typeDefinitions (size={try_size})", used,
            )
            if td_idx >= 0:
                td_size = try_size
                break

        fd_size = _get_field_def_size(version)
        fd_off, fd_count, fd_idx = 0, 0, -1
        if version >= 39 and len(pairs) > 11:
            fd_off, fd_count, _ = pairs[11]
            fd_idx = 11
            used.add(11)
        elif version >= 31 and len(pairs) > 11:
            fd_off, fd_count, _ = pairs[11]
            fd_idx = 11
            used.add(11)
        else:
            fd_off, fd_count, fd_idx = _find_section_by_entry_count(
                pairs, data, fd_size, 5_000, 2_000_000, f"fields (size={fd_size})", used,
            )

        md_off, md_bytes = 0, 0
        if version >= 39:
            md_idx = 6
        elif version >= 31:
            md_idx = 5
        else:
            md_idx = 7
        if md_idx < len(pairs):
            md_off, md_bytes, _ = pairs[md_idx]
            used.add(md_idx)

        fdv_off, fdv_count, _ = _find_section_by_entry_count(
            pairs, data, _FIELD_DEFAULT_VALUE_SIZE, 100, 500_000,
            "fieldDefaultValues", used,
        )

        img_entry = _get_image_def_size(version)
        img_off, img_count, _ = _find_section_by_entry_count(
            pairs, data, img_entry, 1, 2_000, "images", used,
        )

        _min_fdd_bytes = 4
        if fdv_count > 0:
            try:
                _max_data_idx = 0
                for _fi in range(fdv_count // _FIELD_DEFAULT_VALUE_SIZE):
                    _didx = struct.unpack_from("<i", data,
                             fdv_off + _fi * _FIELD_DEFAULT_VALUE_SIZE + 8)[0]
                    if _didx > _max_data_idx:
                        _max_data_idx = _didx
                _min_fdd_bytes = max(4, _max_data_idx + 4)
            except Exception:
                pass
        fdd_off, fdd_count, _ = _find_section_by_byte_range(
            pairs, data, _min_fdd_bytes, len(data) // 2, "fieldDefaultData", used,
        )

        string_data = data[str_off:str_off + str_count] if str_count > 0 else b""

        td_num = td_count // td_size if td_size > 0 else 0
        if version >= 39 and td_num > 0:
            global _V39_TYPEDEF_LAYOUT
            _V39_TYPEDEF_LAYOUT = _detect_v39_typedef_layout(
                data,
                td_off,
                td_size,
                td_num,
                field_def_num=(fd_count // fd_size if fd_size > 0 else 0),
                approx_method_num=(md_bytes // _get_method_def_size(version) if md_bytes > 0 else 0),
            )
        print(
            f"[DEBUG] TypeDef struct size for version {version}: {td_size} bytes, "
            f"section bytes={td_count}, entries={td_num}"
        )
        parser = _parse_typedef_v24plus if version >= 24 else _parse_typedef_pre24
        type_defs: List[TypeDef] = []
        for i in range(td_num):
            td = parser(data, td_off + i * td_size, version)
            type_defs.append(td)

        if type_defs:
            total_fc = sum(t.field_count for t in type_defs)
            total_mc = sum(t.method_count for t in type_defs)
            max_fc = max(t.field_count for t in type_defs)
            max_mc = max(t.method_count for t in type_defs)
            print(f"[DEBUG] TypeDef counts: total_fields={total_fc}, total_methods={total_mc}, "
                  f"max_field_count={max_fc}, max_method_count={max_mc}")
            if max_fc > 10000 or max_mc > 10000:
                print(f"[WARN] Suspiciously large counts detected — possible struct layout mismatch!")

        fd_num = fd_count // fd_size
        field_defs: List[FieldDef] = []
        for i in range(fd_num):
            field_defs.append(_parse_field_def(data, fd_off + i * fd_size, version))

        total_methods = max([t.method_start + t.method_count for t in type_defs] + [0])
        if total_methods > 0 and md_bytes > 0:
            md_entry = md_bytes // total_methods
        else:
            md_entry = _get_method_def_size(version)
        md_num = total_methods if total_methods > 0 else (md_bytes // md_entry if md_entry > 0 else 0)
        print(f"[DEBUG] methods: offset=0x{md_off:X}, bytes={md_bytes}, "
              f"entries={md_num}, struct_size={md_entry}")
        method_defs: List[MethodDef] = []
        for i in range(md_num):
            method_defs.append(_parse_method_def(data, md_off + i * md_entry, version))

        fdv_num = fdv_count // _FIELD_DEFAULT_VALUE_SIZE
        field_default_values: List[FieldDefaultValue] = []
        for i in range(fdv_num):
            field_default_values.append(
                _parse_field_default_value(data, fdv_off + i * _FIELD_DEFAULT_VALUE_SIZE)
            )

        fdv_data = data[fdd_off:fdd_off + fdd_count] if fdd_count > 0 else b""

        img_size = _get_image_def_size(version)
        img_num = img_count // img_size

        global _V39_IMAGE_LAYOUT
        if version >= 39 and img_num > 0 and td_num > 0:
            _V39_IMAGE_LAYOUT = _detect_v39_image_layout(
                data, img_off, img_size, img_num, td_num, string_data)

        images: List[ImageDef] = []
        for i in range(img_num):
            images.append(_parse_image_def(data, img_off + i * img_size, version))

    except struct.error as e:
        raise ValueError(
            f"Metadata version {version} parse error (struct layout may differ): {e}"
        )

    print(
        f"[DEBUG] IL2CPP metadata parsed: {td_num} types, {fd_num} fields, "
        f"{md_num} methods, {img_num} images, {fdv_num} field defaults"
    )

    for i in range(min(3, len(type_defs))):
        td = type_defs[i]
        try:
            name_bytes = string_data[td.name_index:].split(b'\0', 1)[0]
            name = name_bytes.decode('utf-8', errors='replace')
            print(f"[DEBUG] Type {i}: name='{name}', parentIndex={td.parent_index}, "
                  f"fieldStart={td.field_start}, fieldCount={td.field_count}")
        except Exception:
            pass

    total_img_types = sum(img.type_count for img in images)
    max_img_tc = max((img.type_count for img in images), default=0)
    print(f"[DEBUG] Images: total_type_count={total_img_types}, max_type_count={max_img_tc}, "
          f"expected={td_num}")
    for i in range(min(5, len(images))):
        img = images[i]
        iname = ""
        try:
            iname = string_data[img.name_index:].split(b'\0', 1)[0].decode('utf-8', errors='replace')
        except Exception:
            pass
        print(f"[DEBUG] Image[{i}]: name='{iname}', type_start={img.type_start}, "
              f"type_count={img.type_count}, assembly_idx={img.assembly_index}")
    if max_img_tc > td_num:
        print(f"[WARN] Image type_count ({max_img_tc}) exceeds total types ({td_num}) — "
              f"v39 image layout may be wrong!")

    return Metadata(
        version=version,
        string_data=string_data,
        type_definitions=type_defs,
        field_definitions=field_defs,
        method_definitions=method_defs,
        field_default_values=field_default_values,
        field_default_value_data=fdv_data,
        images=images,
        raw_data=data,
    )
