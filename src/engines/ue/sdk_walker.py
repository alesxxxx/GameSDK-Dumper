
import logging
import struct
from typing import Dict, List, Optional, Tuple

from src.core.memory import (
    read_bytes,
    read_uint64,
    read_uint32,
    read_int32,
    read_uint16,
    scatter_read_multiple,
)

logger = logging.getLogger(__name__)
from src.core.models import (
    BoolMeta,
    MemberInfo,
    EnumInfo,
    FunctionInfo,
    FunctionParamInfo,
    SDKDump,
    StructInfo,
    StructLayoutMeta,
    TypeDesc,
)
from src.engines.ue.gnames import read_fname
from src.engines.ue.version_matrix import (
    is_pre_425,
    is_pre_423,
    get_ffield_layout,
    get_version_config,
)
from src.engines.ue.gobjects import (
    read_uobject,
    get_object_count,
    get_gobjects_objects_ptr,
    get_object_class_name,
    UOBJECT_CLASS,
    UOBJECT_NAME,
    UOBJECT_OUTER,
    FUOBJECTITEM_SIZE_NORMAL,
    OBJECTS_PER_CHUNK,
)

USTRUCT_SUPER = 0x40
USTRUCT_CHILDREN = 0x48
USTRUCT_CHILD_PROPS = 0x50
USTRUCT_PROPERTIES_SIZE = 0x58
USTRUCT_MIN_ALIGNMENT = 0x5C

USTRUCT_SUPER_LEGACY = 0x30
USTRUCT_CHILDREN_LEGACY = 0x38
USTRUCT_PROPERTIES_SIZE_LEGACY = 0x40
USTRUCT_MIN_ALIGNMENT_LEGACY = 0x44

UPROPERTY_NEXT = 0x28
UPROPERTY_ARRAY_DIM = 0x30
UPROPERTY_ELEMENT_SIZE = 0x34
UPROPERTY_PROPERTY_FLAGS = 0x38
UPROPERTY_REP_INDEX = 0x40
UPROPERTY_OFFSET_INTERNAL = 0x44

FFIELD_CLASS_PRIVATE = 0x08
FFIELD_NEXT = 0x20
FFIELD_NAME = 0x28

FPROPERTY_ARRAY_DIM = 0x38
FPROPERTY_ELEMENT_SIZE = 0x3C
FPROPERTY_FLAGS = 0x40
FPROPERTY_OFFSET = 0x4C

FFIELDCLASS_NAME = 0x00

_ffield_class_name_cache: dict = {}

_uobject_name_cache: dict = {}

_super_chain_cache: dict = {}

UENUM_NAMES_OFFSET = 0x40
_UENUM_NAMES_PROBE_OFFSETS = (0x40, 0x48, 0x50)

_UFUNCTION_FLAGS_PROBE_OFFSETS = (0x88, 0x80, 0x78, 0x70, 0x68, 0x90, 0xA0, 0xB0)

_ufunction_flags_offset_cache: Dict[str, int] = {}

CPF_CONST_PARM = 0x0000000000000002
CPF_PARM = 0x0000000000000080
CPF_OUT_PARM = 0x0000000000000100
CPF_RETURN_PARM = 0x0000000000000400
CPF_REFERENCE_PARM = 0x0000000000000800
CPF_UOBJECT_WRAPPER = 0x0004000000000000

_PROPERTY_CLASS_SIZE_BY_LAYOUT = {
    "pre425": 0x70,
    "ue427": 0x78,
    "ue52plus": 0x70,
}

_UE_PRIMITIVE_TYPES = {
    "BoolProperty": ("bool", 1, 1),
    "ByteProperty": ("uint8_t", 1, 1),
    "Int8Property": ("int8_t", 1, 1),
    "Int16Property": ("int16_t", 2, 2),
    "IntProperty": ("int32_t", 4, 4),
    "Int64Property": ("int64_t", 8, 8),
    "UInt16Property": ("uint16_t", 2, 2),
    "UInt32Property": ("uint32_t", 4, 4),
    "UInt64Property": ("uint64_t", 8, 8),
    "FloatProperty": ("float", 4, 4),
    "DoubleProperty": ("double", 8, 8),
    "NameProperty": ("FName", 0x8, 0x4),
    "StrProperty": ("FString", 0x10, 0x8),
    "TextProperty": ("FText", 0x18, 0x8),
}

_OBJECT_PROPERTY_NAMES = {
    "ObjectProperty",
    "ObjectPtrProperty",
    "WeakObjectProperty",
    "LazyObjectProperty",
    "SoftObjectProperty",
    "AssetObjectProperty",
}

_CLASS_PROPERTY_NAMES = {
    "ClassProperty",
    "ClassPtrProperty",
    "SoftClassProperty",
    "AssetClassProperty",
}

_DELEGATE_PROPERTY_NAMES = {
    "DelegateProperty",
    "MulticastDelegateProperty",
    "MulticastInlineDelegateProperty",
    "MulticastSparseDelegateProperty",
}

_CONTAINER_PROPERTY_NAMES = {
    "ArrayProperty",
    "MapProperty",
    "SetProperty",
}

_POINTER_LIKE_TYPE_KINDS = {
    "object",
    "class",
    "soft_object",
    "soft_class",
    "weak_object",
    "lazy_object",
    "object_ptr",
    "class_ptr",
    "interface",
    "field_path",
    "delegate",
    "multicast_delegate",
}

_type_desc_cache: Dict[int, TypeDesc] = {}
_layout_cache: Dict[int, StructLayoutMeta] = {}

def _align_up(value: int, alignment: int) -> int:
    alignment = max(1, int(alignment or 1))
    return (value + alignment - 1) & ~(alignment - 1)

def _sanitize_signature_type(text: str) -> str:
    return (text or "void").replace("class ", "").replace("struct ", "").strip()

def _normalize_ue_full_name(text: str) -> str:
    value = str(text or "").replace("\\", "/").strip()
    value = value.replace("/Script/", "")
    while value.startswith("."):
        value = value[1:]
    return value

def _ctz8(value: int) -> int:
    value &= 0xFF
    if value == 0:
        return -1
    idx = 0
    while value and (value & 1) == 0:
        value >>= 1
        idx += 1
    return idx

def _ue_property_base_size(ue_version: str) -> int:
    layout = get_ffield_layout(ue_version)
    return _PROPERTY_CLASS_SIZE_BY_LAYOUT.get(layout, 0x78)

def _cached_uobject_name(
    handle: int,
    obj_ptr: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    legacy_names: bool = False,
) -> str:
    if not obj_ptr or not _plausible_runtime_ptr(obj_ptr):
        return ""
    cached = _uobject_name_cache.get(obj_ptr)
    if cached is not None:
        return cached
    name_idx = read_uint32(handle, obj_ptr + UOBJECT_NAME)
    name = read_fname(
        handle,
        gnames_ptr,
        name_idx,
        ue_version,
        case_preserving,
        legacy=legacy_names,
    )
    _uobject_name_cache[obj_ptr] = name or ""
    return name or ""

def _cached_full_object_name(
    handle: int,
    obj_ptr: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    legacy_names: bool = False,
) -> str:
    if not obj_ptr or not _plausible_runtime_ptr(obj_ptr):
        return ""
    name = _cached_uobject_name(
        handle, obj_ptr, gnames_ptr, ue_version, case_preserving, legacy_names
    )
    if not name:
        return ""
    outer_ptr = read_uint64(handle, obj_ptr + UOBJECT_OUTER)
    outer_name = _cached_uobject_name(
        handle, outer_ptr, gnames_ptr, ue_version, case_preserving, legacy_names
    ) if outer_ptr else ""
    return _normalize_ue_full_name(f"{outer_name}.{name}" if outer_name else name)

def _plausible_uobject_class_ptr(value: int) -> bool:
    return 0x1000000 < value < 0x7FFFFFFFFFFF

def _plausible_runtime_ptr(value: int, floor: int = 0x10000) -> bool:
    return floor <= value < 0x7FFFFFFFFFFF

def _pointer_floor_from_chunks(chunk_ptrs: List[int]) -> int:
    vals = [p for p in chunk_ptrs if p and p >= 0x10000]
    if not vals:
        return 0x10000
    return max(0x10000, min(vals) - 0x4000000000)

def _is_pre_425_ue(ue_version: str) -> bool:
    return is_pre_425(ue_version)

def _is_pre_423_ue(ue_version: str) -> bool:
    return is_pre_423(ue_version)

def get_ffield_offsets_for_layout(layout: str) -> dict:
    if layout == "ue52plus":
        return {
            "FFIELD_CLASS_PRIVATE": 0x08,
            "FFIELD_NEXT": 0x18,
            "FFIELD_NAME": 0x20,
            "FPROPERTY_ARRAY_DIM": 0x30,
            "FPROPERTY_ELEMENT_SIZE": 0x34,
            "FPROPERTY_FLAGS": 0x38,
            "FPROPERTY_OFFSET": 0x44,
            "FFIELDCLASS_NAME": 0x00,
            "UENUM_NAMES_OFFSET": UENUM_NAMES_OFFSET,
        }
    return {
        "FFIELD_CLASS_PRIVATE": FFIELD_CLASS_PRIVATE,
        "FFIELD_NEXT": FFIELD_NEXT,
        "FFIELD_NAME": FFIELD_NAME,
        "FPROPERTY_ARRAY_DIM": FPROPERTY_ARRAY_DIM,
        "FPROPERTY_ELEMENT_SIZE": FPROPERTY_ELEMENT_SIZE,
        "FPROPERTY_FLAGS": FPROPERTY_FLAGS,
        "FPROPERTY_OFFSET": FPROPERTY_OFFSET,
        "FFIELDCLASS_NAME": FFIELDCLASS_NAME,
        "UENUM_NAMES_OFFSET": UENUM_NAMES_OFFSET,
    }

def ue_version_for_ffield_layout(layout: str, fallback: str = "4.27") -> str:
    if layout == "ue52plus":
        return "5.2"
    if layout == "ue427":
        return "4.27"
    return fallback or "4.27"

def get_ffield_offsets(ue_version: str = "4.27") -> dict:
    layout = get_ffield_layout(ue_version)
    logger.debug(
        "get_ffield_offsets: ue_version=%r layout=%r (from version_matrix)",
        ue_version,
        layout,
    )
    return get_ffield_offsets_for_layout(layout)

def _looks_like_ffield_name(value: str) -> bool:
    if not value or value == "None" or len(value) > 128:
        return False
    bad = sum(1 for ch in value if ord(ch) < 0x20)
    if bad:
        return False
    return any(ch.isalpha() or ch == "_" for ch in value)

def _looks_like_property_class(value: str) -> bool:
    if not value or len(value) > 80:
        return False
    return value.endswith("Property") or value in {"FieldPath", "Function"}

def _decoded_ffield_score(
    *,
    field_name: str,
    property_class_name: str,
    array_dim: int,
    element_size: int,
    offset: int,
    flags: int,
    next_ptr: int,
    props_size: int,
) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []

    if _looks_like_ffield_name(field_name):
        score += 4
    else:
        reasons.append("bad field name")

    if _looks_like_property_class(property_class_name):
        score += 4
    else:
        reasons.append("bad property class")

    if 1 <= array_dim <= 4096:
        score += 3
        if array_dim == 1:
            score += 1
    else:
        score -= 5
        reasons.append(f"implausible ArrayDim={array_dim}")

    if 1 <= element_size <= 0x1000:
        score += 3
    else:
        score -= 5
        reasons.append(f"implausible ElementSize={element_size}")

    if 0 <= offset <= 0x200000:
        score += 2
        if props_size > 0 and offset <= props_size:
            score += 3
    else:
        score -= 4
        reasons.append(f"implausible Offset_Internal=0x{offset:X}")

    total_size = element_size * max(array_dim, 1)
    if props_size > 0 and 0 <= offset and total_size > 0:
        if offset + total_size <= max(props_size, offset + 0x1000):
            score += 2
        if offset + total_size > props_size and total_size > 0x1000:
            score -= 4
            reasons.append(
                f"field size exceeds PropertiesSize ({offset}+{total_size}>{props_size})"
            )

    if next_ptr == 0 or _plausible_runtime_ptr(next_ptr):
        score += 1
    else:
        score -= 2
        reasons.append(f"bad Next=0x{next_ptr:X}")

    if _plausible_runtime_ptr(flags):
        score -= 2
        reasons.append(f"flags look like a pointer: 0x{flags:X}")

    if offset == 0x202 or array_dim > 0x100000 or element_size > 0x100000:
        score -= 6
        reasons.append("classic shifted FProperty decode pattern")

    return score, reasons

def score_ffield_layout_blob(
    raw: bytes,
    offsets: dict,
    *,
    props_size: int = 0,
    field_name: str = "",
    property_class_name: str = "",
) -> Tuple[int, List[str]]:
    try:
        need = max(
            offsets["FFIELD_NEXT"] + 8,
            offsets["FPROPERTY_ARRAY_DIM"] + 4,
            offsets["FPROPERTY_ELEMENT_SIZE"] + 4,
            offsets["FPROPERTY_FLAGS"] + 8,
            offsets["FPROPERTY_OFFSET"] + 4,
        )
        if len(raw) < need:
            return -20, ["short FField blob"]
        import struct as _struct

        next_ptr = _struct.unpack_from("<Q", raw, offsets["FFIELD_NEXT"])[0]
        array_dim = _struct.unpack_from("<i", raw, offsets["FPROPERTY_ARRAY_DIM"])[0]
        element_size = _struct.unpack_from("<i", raw, offsets["FPROPERTY_ELEMENT_SIZE"])[0]
        flags = _struct.unpack_from("<Q", raw, offsets["FPROPERTY_FLAGS"])[0]
        prop_off = _struct.unpack_from("<i", raw, offsets["FPROPERTY_OFFSET"])[0]
    except Exception as exc:
        return -20, [f"decode failed: {exc}"]

    return _decoded_ffield_score(
        field_name=field_name,
        property_class_name=property_class_name,
        array_dim=array_dim,
        element_size=element_size,
        offset=prop_off,
        flags=flags,
        next_ptr=next_ptr,
        props_size=props_size,
    )

def probe_ffield_layout(
    handle: int,
    gobjects_ptr: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    *,
    item_size: int = FUOBJECTITEM_SIZE_NORMAL,
    legacy_names: bool = False,
    sample_limit: int = 64,
) -> dict:
    if _is_pre_425_ue(ue_version):
        return {
            "layout": "pre425",
            "recommended_version": ue_version,
            "confidence": 1.0,
            "scores": {"pre425": sample_limit},
            "samples": 0,
            "reason": "pre-FField UE version",
        }

    import struct as _struct

    result = {
        "layout": "",
        "recommended_version": ue_version,
        "confidence": 0.0,
        "scores": {"ue427": 0, "ue52plus": 0},
        "samples": 0,
        "reason": "",
    }

    try:
        num_elements = get_object_count(handle, gobjects_ptr)
        objects_ptr = get_gobjects_objects_ptr(handle, gobjects_ptr)
    except Exception as exc:
        result["reason"] = f"could not read GObjects: {exc}"
        return result

    if not num_elements or not objects_ptr:
        result["reason"] = "empty GObjects"
        return result

    num_chunks = min((num_elements + OBJECTS_PER_CHUNK - 1) // OBJECTS_PER_CHUNK, 16)
    chunk_raw = read_bytes(handle, objects_ptr, num_chunks * 8)
    if not chunk_raw or len(chunk_raw) < 8:
        result["reason"] = "could not read GObjects chunks"
        return result

    chunk_ptrs = list(_struct.unpack_from(f"<{len(chunk_raw) // 8}Q", chunk_raw))
    ptr_floor = _pointer_floor_from_chunks(chunk_ptrs)
    class_name_cache: Dict[int, str] = {}

    def _class_name(ptr: int) -> str:
        cached = class_name_cache.get(ptr)
        if cached is not None:
            return cached
        if not _plausible_uobject_class_ptr(ptr):
            class_name_cache[ptr] = ""
            return ""
        idx = read_uint32(handle, ptr + UOBJECT_NAME)
        name = read_fname(
            handle, gnames_ptr, idx, ue_version, case_preserving, legacy=legacy_names
        ) or ""
        class_name_cache[ptr] = name
        return name

    samples = []
    max_slots = min(num_elements, OBJECTS_PER_CHUNK * len(chunk_ptrs), 200000)
    visited_slots = 0
    for chunk_idx, chunk_base in enumerate(chunk_ptrs):
        if len(samples) >= sample_limit or not chunk_base:
            continue
        remaining = max_slots - visited_slots
        if remaining <= 0:
            break
        slots = min(OBJECTS_PER_CHUNK, remaining)
        read_slots = min(slots, 4096)
        chunk_data_size = read_slots * item_size
        chunk_data = read_bytes(handle, chunk_base, chunk_data_size)
        visited_slots += slots
        if not chunk_data:
            continue
        if len(chunk_data) < chunk_data_size:
            chunk_data = chunk_data.ljust(chunk_data_size, b"\x00")
        obj_ptrs = []
        for within_idx in range(read_slots):
            obj_ptr = _struct.unpack_from("<Q", chunk_data, within_idx * item_size)[0]
            if _plausible_runtime_ptr(obj_ptr, ptr_floor):
                obj_ptrs.append(obj_ptr)
        if not obj_ptrs:
            continue
        headers = scatter_read_multiple(handle, [(ptr, 0x60) for ptr in obj_ptrs])
        for obj_ptr, raw in zip(obj_ptrs, headers):
            if len(samples) >= sample_limit:
                break
            if not raw or len(raw) < 0x60:
                continue
            class_ptr = _struct.unpack_from("<Q", raw, UOBJECT_CLASS)[0]
            cname = _class_name(class_ptr)
            if cname not in ("Class", "ScriptStruct", "Function"):
                continue
            child_prop = _struct.unpack_from("<Q", raw, USTRUCT_CHILD_PROPS)[0]
            if not _plausible_runtime_ptr(child_prop):
                continue
            props_size = _struct.unpack_from("<i", raw, USTRUCT_PROPERTIES_SIZE)[0]
            prop_raw = read_bytes(handle, child_prop, 0x58)
            if not prop_raw or len(prop_raw) < 0x50:
                continue
            samples.append((prop_raw, max(0, props_size)))

    if not samples:
        result["reason"] = "no ChildProperties samples"
        return result

    layout_offsets = {
        "ue427": get_ffield_offsets_for_layout("ue427"),
        "ue52plus": get_ffield_offsets_for_layout("ue52plus"),
    }
    layout_reasons: Dict[str, List[str]] = {"ue427": [], "ue52plus": []}

    for raw, props_size in samples:
        for layout, offsets in layout_offsets.items():
            field_name = ""
            property_class_name = ""
            try:
                name_idx = _struct.unpack_from("<I", raw, offsets["FFIELD_NAME"])[0]
                field_name = read_fname(
                    handle,
                    gnames_ptr,
                    name_idx,
                    ue_version,
                    case_preserving,
                    legacy=legacy_names,
                ) or ""
                class_priv = _struct.unpack_from("<Q", raw, offsets["FFIELD_CLASS_PRIVATE"])[0]
                if _plausible_runtime_ptr(class_priv):
                    type_idx = read_uint32(handle, class_priv + offsets["FFIELDCLASS_NAME"])
                    property_class_name = read_fname(
                        handle,
                        gnames_ptr,
                        type_idx,
                        ue_version,
                        case_preserving,
                        legacy=legacy_names,
                    ) or ""
            except Exception:
                pass
            score, reasons = score_ffield_layout_blob(
                raw,
                offsets,
                props_size=props_size,
                field_name=field_name,
                property_class_name=property_class_name,
            )
            result["scores"][layout] += score
            layout_reasons[layout].extend(reasons[:2])

    result["samples"] = len(samples)
    scores = result["scores"]
    best = "ue52plus" if scores["ue52plus"] > scores["ue427"] else "ue427"
    margin = abs(scores["ue52plus"] - scores["ue427"])
    result["layout"] = best
    result["recommended_version"] = ue_version_for_ffield_layout(best, fallback=ue_version)
    result["confidence"] = min(1.0, margin / max(10.0, len(samples) * 6.0))
    result["reason"] = (
        f"{best} scored {scores[best]} vs "
        f"{'ue427' if best == 'ue52plus' else 'ue52plus'} "
        f"{scores['ue427' if best == 'ue52plus' else 'ue52plus']} "
        f"across {len(samples)} ChildProperties sample(s)"
    )
    if best == "ue52plus" and layout_reasons["ue427"]:
        result["rejected_layout_reasons"] = list(dict.fromkeys(layout_reasons["ue427"][:8]))
    elif best == "ue427" and layout_reasons["ue52plus"]:
        result["rejected_layout_reasons"] = list(dict.fromkeys(layout_reasons["ue52plus"][:8]))
    return result

def _scatter_walk_ffield_chains(
    struct_ptrs: list,
    handle: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    offsets: dict,
    legacy_names: bool,
) -> dict:
    import struct as _struct

    if not struct_ptrs:
        return {}

    if offsets is None:
        offsets = get_ffield_offsets(ue_version)

    _fn_name      = offsets["FFIELD_NAME"]
    _fn_cls_priv  = offsets["FFIELD_CLASS_PRIVATE"]
    _fn_next      = offsets["FFIELD_NEXT"]
    _fn_arr_dim   = offsets["FPROPERTY_ARRAY_DIM"]
    _fn_elem_sz   = offsets["FPROPERTY_ELEMENT_SIZE"]
    _fn_flags     = offsets["FPROPERTY_FLAGS"]
    _fn_prop_off  = offsets["FPROPERTY_OFFSET"]
    _fn_fc_name   = offsets["FFIELDCLASS_NAME"]
    _NODE         = 0x50

    results: dict = {ptr: [] for ptr in struct_ptrs}

    reqs = [(ptr + USTRUCT_CHILD_PROPS, 8) for ptr in struct_ptrs]
    child_prop_results = scatter_read_multiple(handle, reqs)

    active: dict = {}
    for ptr, raw in zip(struct_ptrs, child_prop_results):
        if raw and len(raw) >= 8:
            first = _struct.unpack_from("<Q", raw)[0]
            if first and 0x10000 <= first <= 0x7FFFFFFFFFFF:
                active[ptr] = (first, set())

    max_per_struct = 500

    while active:
        items = list(active.items())
        reqs = [(curr, _NODE) for _, (curr, _) in items]
        raw_nodes = scatter_read_multiple(handle, reqs)

        next_active: dict = {}
        consecutive_wave_fails = 0
        for (struct_ptr, (curr_ptr, vis)), raw in zip(items, raw_nodes):
            if not raw:
                consecutive_wave_fails += 1
                breaker_limit = 1000000 if len(struct_ptrs) > 1000 else 5000
                if consecutive_wave_fails >= breaker_limit:
                    raise RuntimeError(f"Smart Circuit Breaker Tripped: {breaker_limit} consecutive wave property reads failed. Check CR3/PID.")
                continue
            
            consecutive_wave_fails = 0
            if len(raw) < _NODE:
                continue
            
            if curr_ptr in vis:
                continue
            vis.add(curr_ptr)
            if not (0x10000 <= curr_ptr <= 0x7FFFFFFFFFFF):
                continue

            name_idx   = _struct.unpack_from("<I", raw, _fn_name)[0]
            class_priv = _struct.unpack_from("<Q", raw, _fn_cls_priv)[0]
            next_ptr   = _struct.unpack_from("<Q", raw, _fn_next)[0]
            array_dim  = _struct.unpack_from("<i", raw, _fn_arr_dim)[0]
            elem_size  = _struct.unpack_from("<i", raw, _fn_elem_sz)[0]
            prop_off   = _struct.unpack_from("<i", raw, _fn_prop_off)[0]
            prop_flags = _struct.unpack_from("<Q", raw, _fn_flags)[0]

            type_name = _ffield_class_name_cache.get(class_priv)
            if type_name is None and _plausible_uobject_class_ptr(class_priv):
                type_idx  = read_uint32(handle, class_priv + _fn_fc_name)
                type_name = (
                    read_fname(
                        handle, gnames_ptr, type_idx, ue_version,
                        case_preserving, legacy=legacy_names,
                    )
                    or "Unknown"
                )
                _ffield_class_name_cache[class_priv] = type_name
            type_name = type_name or "Unknown"

            name = read_fname(
                handle, gnames_ptr, name_idx, ue_version,
                case_preserving, legacy=legacy_names,
            )

            if name and prop_off >= 0 and elem_size > 0:
                results[struct_ptr].append(
                    MemberInfo(
                        name=name,
                        offset=prop_off,
                        size=elem_size * max(array_dim, 1),
                        type_name=type_name,
                        array_dim=max(array_dim, 1),
                        flags=prop_flags,
                        property_ptr=curr_ptr,
                    )
                )

            member_count = len(results[struct_ptr])
            if (
                member_count < max_per_struct
                and next_ptr
                and 0x10000 <= next_ptr <= 0x7FFFFFFFFFFF
                and next_ptr not in vis
            ):
                next_active[struct_ptr] = (next_ptr, vis)

        active = next_active

    return results

def _probe_ufunction_flags_from_blob(raw: bytes, ue_version: str = "") -> int:
    import struct as _struct

    _COMMON_BITS = 0x04020400

    if ue_version and ue_version in _ufunction_flags_offset_cache:
        cached_off = _ufunction_flags_offset_cache[ue_version]
        if len(raw) >= cached_off + 4:
            val = _struct.unpack_from("<I", raw, cached_off)[0]
            if val and 0 < val <= 0xFFFFFFFF and (val & _COMMON_BITS):
                return val

    for off in _UFUNCTION_FLAGS_PROBE_OFFSETS:
        if len(raw) < off + 4:
            continue
        val = _struct.unpack_from("<I", raw, off)[0]
        if val and 0 < val <= 0xFFFFFFFF and (val & _COMMON_BITS):
            if ue_version:
                _ufunction_flags_offset_cache[ue_version] = off
                logger.debug(
                    "UFunction flags offset cached from preread blob: 0x%X for UE %s",
                    off,
                    ue_version,
                )
            return val
    return 0

def _scan_exec_ptr_from_blob(
    raw: bytes,
    base: int,
    size: int,
    ue_version: str = "",
) -> Tuple[int, int]:
    import struct as _struct

    if not base or not size:
        return 0, 0

    cached_attr = f"_cached_{ue_version}_exec_off"
    if hasattr(_read_ufunction, cached_attr):
        exec_off = getattr(_read_ufunction, cached_attr)
        if len(raw) >= exec_off + 8:
            ptr = _struct.unpack_from("<Q", raw, exec_off)[0]
            if base <= ptr < base + size:
                return ptr, exec_off

    cached_flags_off = _ufunction_flags_offset_cache.get(ue_version)
    scan_start = (cached_flags_off - 0x20) if cached_flags_off else 0x40
    scan_end = (cached_flags_off + 0x40) if cached_flags_off else 0xC0
    for off in range(max(0, scan_start), min(len(raw) - 7, scan_end), 8):
        ptr = _struct.unpack_from("<Q", raw, off)[0]
        if base <= ptr < base + size:
            setattr(_read_ufunction, cached_attr, off)
            return ptr, off
    return 0, 0

def _batch_preread_function_info(
    func_ptrs: List[int],
    handle: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    legacy_names: bool = False,
    base: int = 0,
    size: int = 0,
) -> dict:
    import struct as _struct

    unique_func_ptrs: List[int] = []
    seen: set = set()
    for ptr in func_ptrs:
        if ptr and ptr not in seen:
            seen.add(ptr)
            unique_func_ptrs.append(ptr)

    if not unique_func_ptrs:
        return {}

    _HEADER_SIZE = 0xC0
    header_reqs = [(ptr, _HEADER_SIZE) for ptr in unique_func_ptrs]
    header_results = scatter_read_multiple(handle, header_reqs)

    func_info_map: dict = {}
    for ptr, raw in zip(unique_func_ptrs, header_results):
        if not raw or len(raw) < UOBJECT_NAME + 4:
            continue

        name_idx = _struct.unpack_from("<I", raw, UOBJECT_NAME)[0]
        name = ""
        if name_idx:
            name = read_fname(
                handle,
                gnames_ptr,
                name_idx,
                ue_version,
                case_preserving,
                legacy=legacy_names,
            )
            if name:
                _uobject_name_cache[ptr] = name

        flags = _probe_ufunction_flags_from_blob(raw, ue_version)
        exec_func = 0
        rva = 0
        if base and size:
            exec_func, _ = _scan_exec_ptr_from_blob(raw, base, size, ue_version)
            if exec_func:
                rva = exec_func - base

        func_info_map[ptr] = {
            "name": name,
            "flags": flags,
            "exec_func": exec_func,
            "rva": rva,
        }

    return func_info_map

def _prebuild_super_chain_cache(
    handle: int,
    struct_header_map: dict,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    legacy_names: bool = False,
) -> None:
    import struct as _struct

    if not struct_header_map:
        return

    next_off = USTRUCT_SUPER
    frontier = {
        _struct.unpack_from("<Q", raw, USTRUCT_SUPER)[0]
        for raw in struct_header_map.values()
        if raw and len(raw) >= USTRUCT_SUPER + 8
    }
    frontier = {
        ptr for ptr in frontier if 0x10000 <= ptr <= 0x7FFFFFFFFFFF and ptr not in _super_chain_cache
    }
    if not frontier:
        return

    adjacency: dict = {}
    all_ptrs = set(frontier)

    for _ in range(50):
        current = [ptr for ptr in frontier if ptr not in adjacency]
        if not current:
            break

        next_results = scatter_read_multiple(handle, [(ptr + next_off, 8) for ptr in current])
        next_frontier = set()
        for ptr, raw in zip(current, next_results):
            if not raw or len(raw) < 8:
                continue
            next_ptr = _struct.unpack_from("<Q", raw)[0]
            adjacency[ptr] = next_ptr
            if 0x10000 <= next_ptr <= 0x7FFFFFFFFFFF:
                all_ptrs.add(next_ptr)
                if next_ptr not in adjacency and next_ptr not in _super_chain_cache:
                    next_frontier.add(next_ptr)
        frontier = next_frontier
        if not frontier:
            break

    unresolved_name_ptrs = [ptr for ptr in all_ptrs if ptr not in _uobject_name_cache]
    if unresolved_name_ptrs:
        name_results = scatter_read_multiple(handle, [(ptr + UOBJECT_NAME, 4) for ptr in unresolved_name_ptrs])
        for ptr, raw in zip(unresolved_name_ptrs, name_results):
            if raw and len(raw) >= 4:
                name_idx = _struct.unpack_from("<I", raw)[0]
                name = read_fname(
                    handle,
                    gnames_ptr,
                    name_idx,
                    ue_version,
                    case_preserving,
                    legacy=legacy_names,
                )
                if name:
                    _uobject_name_cache[ptr] = name

    def _build_chain(ptr: int) -> Tuple[List[str], bool]:
        if ptr in _super_chain_cache:
            return list(_super_chain_cache[ptr]), True

        chain: List[str] = []
        seen_ptrs = set()
        curr = ptr
        while curr and curr > 0x10000 and len(chain) < 50:
            if curr in seen_ptrs:
                return chain, False
            if curr in _super_chain_cache:
                chain.extend(_super_chain_cache[curr])
                return chain, True
            if curr not in adjacency:
                return chain, False
            seen_ptrs.add(curr)
            curr_name = _uobject_name_cache.get(curr, "")
            if curr_name:
                chain.append(curr_name)
            curr = adjacency[curr]
        return chain, curr == 0 or curr <= 0x10000

    for ptr in list(all_ptrs):
        chain, complete = _build_chain(ptr)
        if complete and ptr not in _super_chain_cache:
            _super_chain_cache[ptr] = chain

def walk_sdk(
    handle: int,
    gobjects_ptr: int,
    gnames_ptr: int,
    ue_version: str = "4.27",
    case_preserving: bool = False,
    legacy_names: bool = False,
    item_size: int = FUOBJECTITEM_SIZE_NORMAL,
    base: int = 0,
    size: int = 0,
    progress_callback=None,
) -> SDKDump:
    import struct
    from src.core.memory import USE_DRIVER
    if USE_DRIVER:
        from src.core.memory import TARGET_PID
        logger.debug("Starting SDK walk with PID %s", TARGET_PID)
    else:
        logger.debug("Starting SDK walk with handle %s", handle)

    _ffield_class_name_cache.clear()
    _uobject_name_cache.clear()
    _super_chain_cache.clear()

    dump = SDKDump()
    dump.gobjects_ptr = gobjects_ptr
    dump.gnames_ptr = gnames_ptr

    offsets = get_ffield_offsets(ue_version)

    num_elements = get_object_count(handle, gobjects_ptr)
    dump.object_count = num_elements

    objects_ptr = get_gobjects_objects_ptr(handle, gobjects_ptr)

    num_chunks = (num_elements + OBJECTS_PER_CHUNK - 1) // OBJECTS_PER_CHUNK
    chunk_ptrs = []
    if objects_ptr and num_chunks > 0:
        raw_chunks = read_bytes(handle, objects_ptr, num_chunks * 8)
        if raw_chunks and len(raw_chunks) >= num_chunks * 8:
            fmt = f"<{num_chunks}Q"
            chunk_ptrs = list(struct.unpack_from(fmt, raw_chunks))

    from src.core.memory import clear_memory_snapshots, USE_DRIVER
    ptr_floor = _pointer_floor_from_chunks(chunk_ptrs)

    last_progress_current = -1

    def _emit_progress_fraction(fraction: float) -> None:
        nonlocal last_progress_current
        if not progress_callback or num_elements <= 0:
            return
        frac = max(0.0, min(1.0, float(fraction)))
        current = int(frac * num_elements)
        if current == last_progress_current:
            return
        if current < last_progress_current and current != num_elements:
            return
        last_progress_current = current
        progress_callback(current, num_elements)

    _emit_progress_fraction(0.0)

    _bulk_ctx = None
    if USE_DRIVER:
        from src.core.driver import bulk_read_mode
        _bulk_ctx = bulk_read_mode()
        _bulk_ctx.__enter__()

    try:
        from src.engines.ue.gnames import cache_all_fnames

        def _fname_cache_progress(done_blocks: int, total_blocks: int) -> None:
            if total_blocks <= 0:
                return
            block_frac = max(0.0, min(1.0, float(done_blocks) / float(total_blocks)))
            _emit_progress_fraction(0.01 + (0.04 * block_frac))

        cache_all_fnames(
            handle,
            gnames_ptr,
            ue_version,
            case_preserving,
            legacy=legacy_names,
            progress_callback=_fname_cache_progress,
            max_snapshot_blocks=8192,
            max_snapshot_seconds=120.0,
        )
        _emit_progress_fraction(0.05)

        global_obj_fields = []

        def _collect_global_obj_fields(active_item_size: int) -> Tuple[List[Tuple[int, int, int, int, int]], int]:
            collected: List[Tuple[int, int, int, int, int]] = []
            consecutive_invalid_objs = 0
            total_valid_objs = 0

            for chunk_idx, chunk_base in enumerate(chunk_ptrs):
                if not chunk_base:
                    continue
                items_in_chunk = min(OBJECTS_PER_CHUNK, num_elements - chunk_idx * OBJECTS_PER_CHUNK)
                if items_in_chunk <= 0:
                    break

                chunk_data_size = items_in_chunk * active_item_size
                chunk_data = read_bytes(handle, chunk_base, chunk_data_size)
                if not chunk_data:
                    continue

                if len(chunk_data) < chunk_data_size:
                    chunk_data = chunk_data.ljust(chunk_data_size, b'\x00')

                obj_ptrs = []
                for within_idx in range(items_in_chunk):
                    item_offset = within_idx * active_item_size
                    if active_item_size >= 8:
                        obj_ptr = struct.unpack_from("<Q", chunk_data, item_offset)[0]
                    else:
                        obj_ptr = 0

                    if not _plausible_runtime_ptr(obj_ptr, ptr_floor):
                        consecutive_invalid_objs += 1
                        breaker_limit = 1000000 if total_valid_objs > 1000 else 5000
                        if consecutive_invalid_objs >= breaker_limit:
                            raise RuntimeError(
                                f"Smart Circuit Breaker Tripped: {breaker_limit} consecutive UObjects failed to read "
                                f"(chunk {chunk_idx}, item {within_idx}). CR3 or PID is likely incorrect."
                            )
                        continue

                    consecutive_invalid_objs = 0
                    total_valid_objs += 1
                    global_idx = chunk_idx * OBJECTS_PER_CHUNK + within_idx
                    obj_ptrs.append((global_idx, obj_ptr))

                header_reads = scatter_read_multiple(
                    handle, [(obj_ptr, 0x28) for _, obj_ptr in obj_ptrs]
                )
                for (global_idx, obj_ptr), fields_raw in zip(obj_ptrs, header_reads):
                    if not fields_raw or len(fields_raw) < 0x28:
                        continue
                    class_ptr = struct.unpack_from("<Q", fields_raw, UOBJECT_CLASS)[0]
                    if not _plausible_uobject_class_ptr(class_ptr):
                        continue
                    name_idx = struct.unpack_from("<I", fields_raw, UOBJECT_NAME)[0]
                    outer_ptr = struct.unpack_from("<Q", fields_raw, UOBJECT_OUTER)[0]
                    collected.append((global_idx, obj_ptr, class_ptr, name_idx, outer_ptr))

                if num_elements > 0 and ((chunk_idx & 0x7) == 0 or chunk_idx == len(chunk_ptrs) - 1):
                    scanned = min(num_elements, (chunk_idx + 1) * OBJECTS_PER_CHUNK)
                    scan_frac = scanned / max(1, num_elements)
                    _emit_progress_fraction(0.05 + (0.30 * scan_frac))

            return collected, total_valid_objs

        global_obj_fields, total_valid_objs = _collect_global_obj_fields(item_size)
        _emit_progress_fraction(0.35)

        if num_elements > 0 and not global_obj_fields:
            best_fields = global_obj_fields
            best_stride = item_size
            for alt_stride in (FUOBJECTITEM_SIZE_STATS, FUOBJECTITEM_SIZE_LEGACY, FUOBJECTITEM_SIZE_NORMAL):
                if alt_stride == item_size:
                    continue
                trial_fields, _ = _collect_global_obj_fields(alt_stride)
                if len(trial_fields) > len(best_fields):
                    best_fields = trial_fields
                    best_stride = alt_stride
            if best_stride != item_size and best_fields:
                logger.warning(
                    "SDK walk stride auto-correct: %d -> %d (%d viable UObject headers)",
                    item_size,
                    best_stride,
                    len(best_fields),
                )
                item_size = best_stride
                global_obj_fields = best_fields
            elif not best_fields:
                logger.warning(
                    "SDK walk found 0 viable UObject headers from %d object slots (stride=%d, ptr_floor=0x%X)",
                    num_elements,
                    item_size,
                    ptr_floor,
                )
                    
        type_classes = {}
        unique_class_ptrs = list(
            set(cptr for _, _, cptr, _, _ in global_obj_fields if _plausible_uobject_class_ptr(cptr))
        )
        
        if unique_class_ptrs:
            class_name_queries = [(cptr + UOBJECT_NAME, 4) for cptr in unique_class_ptrs]
            c_results = scatter_read_multiple(handle, class_name_queries)
            for cptr, raw in zip(unique_class_ptrs, c_results):
                if raw and len(raw) >= 4:
                    c_name_idx = struct.unpack("<I", raw)[0]
                    type_classes[cptr] = read_fname(handle, gnames_ptr, c_name_idx, ue_version, case_preserving, legacy=legacy_names)
        _emit_progress_fraction(0.45)

        struct_objs = []
        enum_objs = []
        for global_idx, obj_ptr, class_ptr, name_idx, outer_ptr in global_obj_fields:
            cname = type_classes.get(class_ptr, "")
            if cname in ("Class", "ScriptStruct"):
                struct_objs.append((global_idx, obj_ptr, class_ptr, name_idx, outer_ptr, cname == "Class"))
            elif cname == "Enum":
                enum_objs.append(obj_ptr)

        preread_map = {}
        phase_b_function_map: dict = {}
        preread_function_info_map: dict = {}
        if USE_DRIVER and not _is_pre_425_ue(ue_version):
            target_ptrs_for_ffields = [obj_ptr for _, obj_ptr, _, _, _, _ in struct_objs]
            phase_b_function_map = {obj_ptr: [] for obj_ptr in target_ptrs_for_ffields}
            visited_children = set()

            children_reqs = [(obj_ptr + USTRUCT_CHILDREN, 8) for obj_ptr in target_ptrs_for_ffields]
            children_results = scatter_read_multiple(handle, children_reqs)

            active_chains: list = []
            for raw in children_results:
                if raw and len(raw) >= 8:
                    cptr = struct.unpack_from("<Q", raw)[0]
                    if cptr and 0x10000 <= cptr <= 0x7FFFFFFFFFFF:
                        active_chains.append((cptr, 0))
                    else:
                        active_chains.append(None)
                else:
                    active_chains.append(None)

            _CHILDREN_NODE_SIZE = 0x30
            max_waves = 500
            for _wave in range(max_waves):
                wave_items: list = []
                for ci, entry in enumerate(active_chains):
                    if entry is None:
                        continue
                    cptr, found = entry
                    if cptr in visited_children or found >= 500:
                        active_chains[ci] = None
                        continue
                    if not (0x10000 <= cptr <= 0x7FFFFFFFFFFF):
                        active_chains[ci] = None
                        continue
                    wave_items.append((ci, cptr))

                if not wave_items:
                    break

                node_reqs = [(cptr, _CHILDREN_NODE_SIZE) for _, cptr in wave_items]
                node_results = scatter_read_multiple(handle, node_reqs)

                unknown_class_ptrs = set()
                node_class_ptrs = []
                for (ci, cptr), raw in zip(wave_items, node_results):
                    if not raw or len(raw) < _CHILDREN_NODE_SIZE:
                        node_class_ptrs.append(0)
                        continue
                    fc_ptr = struct.unpack_from("<Q", raw, UOBJECT_CLASS)[0]
                    node_class_ptrs.append(fc_ptr)
                    if _plausible_uobject_class_ptr(fc_ptr) and fc_ptr not in type_classes:
                        unknown_class_ptrs.add(fc_ptr)

                if unknown_class_ptrs:
                    name_reqs = [(fc + UOBJECT_NAME, 4) for fc in unknown_class_ptrs]
                    name_results = scatter_read_multiple(handle, name_reqs)
                    for fc, raw in zip(unknown_class_ptrs, name_results):
                        if raw and len(raw) >= 4:
                            fc_idx = struct.unpack_from("<I", raw)[0]
                            fc_name = read_fname(handle, gnames_ptr, fc_idx, ue_version, case_preserving, legacy=legacy_names)
                            type_classes[fc] = fc_name

                for (ci, cptr), raw, fc_ptr in zip(wave_items, node_results, node_class_ptrs):
                    visited_children.add(cptr)
                    entry = active_chains[ci]
                    if entry is None:
                        continue
                    _, found = entry

                    if not raw or len(raw) < _CHILDREN_NODE_SIZE:
                        active_chains[ci] = None
                        continue

                    fc_name = type_classes.get(fc_ptr, "")
                    if "Function" in fc_name:
                        owner_struct_ptr = target_ptrs_for_ffields[ci]
                        phase_b_function_map.setdefault(owner_struct_ptr, []).append(cptr)
                        target_ptrs_for_ffields.append(cptr)

                    next_ptr = struct.unpack_from("<Q", raw, 0x28)[0]
                    if next_ptr and 0x10000 <= next_ptr <= 0x7FFFFFFFFFFF and next_ptr not in visited_children:
                        active_chains[ci] = (next_ptr, found + 1)
                    else:
                        active_chains[ci] = None

            if target_ptrs_for_ffields:
                logger.info(f"Unleashing Massive Scatter-Wave on {len(target_ptrs_for_ffields)} chains...")
                preread_map = _scatter_walk_ffield_chains(
                    target_ptrs_for_ffields,
                    handle,
                    gnames_ptr,
                    ue_version,
                    case_preserving,
                    offsets,
                    legacy_names,
                )

                missing_prereads = [
                    obj_ptr for _, obj_ptr, _, _, _, _ in struct_objs if obj_ptr not in preread_map
                ]
                if missing_prereads:
                    logger.warning(
                        "Scatter preread map missed %d struct(s); those will fall back to slower reads.",
                        len(missing_prereads),
                    )

                preread_function_info_map = _batch_preread_function_info(
                    [func_ptr for func_ptrs in phase_b_function_map.values() for func_ptr in func_ptrs],
                    handle,
                    gnames_ptr,
                    ue_version,
                    case_preserving,
                    legacy_names=legacy_names,
                    base=base,
                    size=size,
                )
        _emit_progress_fraction(0.55)

        _HEADER_SIZE = 0x60
        struct_header_map: dict = {}
        if USE_DRIVER and struct_objs:
            header_reqs = [(obj_ptr, _HEADER_SIZE) for _, obj_ptr, _, _, _, _ in struct_objs]
            header_results = scatter_read_multiple(handle, header_reqs)
            for (_, obj_ptr, _, _, _, _), raw in zip(struct_objs, header_results):
                if raw and len(raw) >= _HEADER_SIZE:
                    struct_header_map[obj_ptr] = raw
                    nidx = struct.unpack_from("<I", raw, UOBJECT_NAME)[0]
                    if nidx and obj_ptr not in _uobject_name_cache:
                        n = read_fname(handle, gnames_ptr, nidx, ue_version, case_preserving, legacy=legacy_names)
                        _uobject_name_cache[obj_ptr] = n

            outer_ptrs_to_resolve = set()
            for raw in struct_header_map.values():
                optr = struct.unpack_from("<Q", raw, UOBJECT_OUTER)[0]
                if optr and 0x10000 <= optr <= 0x7FFFFFFFFFFF and optr not in _uobject_name_cache:
                    outer_ptrs_to_resolve.add(optr)
            if outer_ptrs_to_resolve:
                outer_name_reqs = [(optr + UOBJECT_NAME, 4) for optr in outer_ptrs_to_resolve]
                outer_name_results = scatter_read_multiple(handle, outer_name_reqs)
                for optr, raw in zip(outer_ptrs_to_resolve, outer_name_results):
                    if raw and len(raw) >= 4:
                        oidx = struct.unpack_from("<I", raw)[0]
                        n = read_fname(handle, gnames_ptr, oidx, ue_version, case_preserving, legacy=legacy_names)
                        _uobject_name_cache[optr] = n

            if not _is_pre_423_ue(ue_version):
                super_ptrs_to_resolve = set()
                for raw in struct_header_map.values():
                    sptr = struct.unpack_from("<Q", raw, USTRUCT_SUPER)[0]
                    if sptr and 0x10000 <= sptr <= 0x7FFFFFFFFFFF and sptr not in _uobject_name_cache:
                        super_ptrs_to_resolve.add(sptr)
                if super_ptrs_to_resolve:
                    super_name_reqs = [(sptr + UOBJECT_NAME, 4) for sptr in super_ptrs_to_resolve]
                    super_name_results = scatter_read_multiple(handle, super_name_reqs)
                    for sptr, raw in zip(super_ptrs_to_resolve, super_name_results):
                        if raw and len(raw) >= 4:
                            sidx = struct.unpack_from("<I", raw)[0]
                            n = read_fname(handle, gnames_ptr, sidx, ue_version, case_preserving, legacy=legacy_names)
                            _uobject_name_cache[sptr] = n

                _prebuild_super_chain_cache(
                    handle,
                    struct_header_map,
                    gnames_ptr,
                    ue_version,
                    case_preserving,
                    legacy_names=legacy_names,
                )

        total_structs = max(1, len(struct_objs))
        for struct_idx, (global_idx, obj_ptr, class_ptr, name_idx, outer_ptr, is_class) in enumerate(struct_objs, start=1):
            if (struct_idx & 0x3F) == 0 or struct_idx == total_structs:
                struct_frac = struct_idx / total_structs
                _emit_progress_fraction(0.55 + (0.40 * struct_frac))

            info = _walk_struct(
                handle,
                obj_ptr,
                gnames_ptr,
                ue_version,
                case_preserving,
                is_class=is_class,
                offsets=offsets,
                legacy_names=legacy_names,
                base=base,
                size=size,
                preread_members=preread_map.get(obj_ptr),
                global_preread_map=preread_map,
                preread_header=struct_header_map.get(obj_ptr),
                preread_func_ptrs=phase_b_function_map.get(obj_ptr),
                global_preread_function_info=preread_function_info_map,
            )
            if info:
                dump.structs.append(info)

        total_enums = max(1, len(enum_objs))
        for enum_idx, eptr in enumerate(enum_objs, start=1):
            info = _walk_enum(
                handle,
                eptr,
                gnames_ptr,
                ue_version,
                case_preserving,
                legacy_names=legacy_names,
            )
            if info and info.values:
                dump.enums.append(info)
            if (enum_idx & 0x3F) == 0 or enum_idx == total_enums:
                enum_frac = enum_idx / total_enums
                _emit_progress_fraction(0.95 + (0.04 * enum_frac))

    finally:
        if _bulk_ctx is not None:
            _bulk_ctx.__exit__(None, None, None)
        clear_memory_snapshots()

    _enrich_ue_dump_metadata(
        dump,
        handle,
        gnames_ptr,
        ue_version,
        case_preserving,
        legacy_names=legacy_names,
    )

    if progress_callback:
        progress_callback(num_elements, num_elements)

    return dump

def _compute_desc_signature_name(desc: Optional[TypeDesc]) -> str:
    if desc is None:
        return "void"

    if desc.signature_name:
        return desc.signature_name

    if desc.kind in {"primitive", "opaque"}:
        desc.signature_name = desc.display_name or "uint8_t"
        return desc.signature_name

    if desc.kind == "enum":
        desc.signature_name = desc.display_name or desc.full_name.split(".")[-1]
        return desc.signature_name

    if desc.kind == "named_struct":
        desc.signature_name = desc.display_name or desc.full_name.split(".")[-1]
        return desc.signature_name

    if desc.kind == "object":
        target = _compute_desc_signature_name(desc.pointee) if desc.pointee else "UObject"
        desc.signature_name = f"{target}*"
        return desc.signature_name

    if desc.kind == "object_ptr":
        target = _compute_desc_signature_name(desc.pointee) if desc.pointee else "UObject"
        desc.signature_name = f"TObjectPtr<{target}>"
        return desc.signature_name

    if desc.kind == "class":
        target = _compute_desc_signature_name(desc.pointee) if desc.pointee else "UObject"
        desc.signature_name = (
            f"TSubclassOf<{target}>"
            if desc.metadata.get("is_subclass_of")
            else "UClass*"
        )
        return desc.signature_name

    if desc.kind == "class_ptr":
        target = _compute_desc_signature_name(desc.pointee) if desc.pointee else "UObject"
        desc.signature_name = f"TObjectPtr<UClass>"
        if target and target != "UObject":
            desc.signature_name = f"TObjectPtr<UClass /* {target} */>"
        return desc.signature_name

    if desc.kind == "weak_object":
        target = _compute_desc_signature_name(desc.pointee) if desc.pointee else "UObject"
        desc.signature_name = f"TWeakObjectPtr<{target}>"
        return desc.signature_name

    if desc.kind == "lazy_object":
        target = _compute_desc_signature_name(desc.pointee) if desc.pointee else "UObject"
        desc.signature_name = f"TLazyObjectPtr<{target}>"
        return desc.signature_name

    if desc.kind == "soft_object":
        target = _compute_desc_signature_name(desc.pointee) if desc.pointee else "UObject"
        desc.signature_name = f"TSoftObjectPtr<{target}>"
        return desc.signature_name

    if desc.kind == "soft_class":
        target = _compute_desc_signature_name(desc.pointee) if desc.pointee else "UObject"
        desc.signature_name = f"TSoftClassPtr<{target}>"
        return desc.signature_name

    if desc.kind == "interface":
        target = _compute_desc_signature_name(desc.pointee) if desc.pointee else "UInterface"
        desc.signature_name = f"TScriptInterface<{target}>"
        return desc.signature_name

    if desc.kind == "field_path":
        target = _compute_desc_signature_name(desc.pointee) if desc.pointee else "FField"
        desc.signature_name = f"TFieldPath<{target}>"
        return desc.signature_name

    if desc.kind == "array":
        inner = _compute_desc_signature_name(desc.inner) if desc.inner else "uint8_t"
        desc.signature_name = f"TArray<{inner}>"
        return desc.signature_name

    if desc.kind == "set":
        inner = _compute_desc_signature_name(desc.inner) if desc.inner else "uint8_t"
        desc.signature_name = f"TSet<{inner}>"
        return desc.signature_name

    if desc.kind == "map":
        key = _compute_desc_signature_name(desc.key) if desc.key else "uint8_t"
        value = _compute_desc_signature_name(desc.value) if desc.value else "uint8_t"
        desc.signature_name = f"TMap<{key}, {value}>"
        return desc.signature_name

    if desc.kind == "delegate":
        target = desc.signature_name or desc.metadata.get("delegate_type_name") or "FScriptDelegate"
        desc.signature_name = target
        return target

    if desc.kind == "multicast_delegate":
        target = desc.signature_name or desc.metadata.get("delegate_type_name") or "FMulticastScriptDelegate"
        desc.signature_name = target
        return target

    if desc.kind == "pair":
        key = _compute_desc_signature_name(desc.key) if desc.key else "uint8_t"
        value = _compute_desc_signature_name(desc.value) if desc.value else "uint8_t"
        desc.signature_name = f"TPair<{key}, {value}>"
        return desc.signature_name

    desc.signature_name = desc.display_name or desc.kind or "uint8_t"
    return desc.signature_name

def _type_align_from_display(display_name: str, size_hint: int = 0) -> int:
    base = _sanitize_signature_type(display_name)
    fixed = {
        "bool": 1,
        "uint8_t": 1,
        "int8_t": 1,
        "uint16_t": 2,
        "int16_t": 2,
        "uint32_t": 4,
        "int32_t": 4,
        "float": 4,
        "FName": 4,
        "uint64_t": 8,
        "int64_t": 8,
        "double": 8,
        "UClass*": 8,
        "FString": 8,
        "FText": 8,
    }
    if base.endswith("*"):
        return 8
    if base.startswith(("TArray<", "TMap<", "TSet<", "TWeakObjectPtr<", "TLazyObjectPtr<", "TSoftObjectPtr<", "TSoftClassPtr<", "TScriptInterface<", "TFieldPath<", "TObjectPtr<", "TSubclassOf<")):
        return 8
    if base in fixed:
        return fixed[base]
    if size_hint >= 8:
        return 8
    if size_hint >= 4:
        return 4
    if size_hint >= 2:
        return 2
    return 1

def _desc_alignment(desc: Optional[TypeDesc], size_hint: int = 0) -> int:
    if desc is None:
        return _type_align_from_display("", size_hint)
    if desc.align:
        return int(desc.align)
    return _type_align_from_display(_compute_desc_signature_name(desc), size_hint or desc.size)

def _make_named_type_desc(kind: str, full_name: str, size: int = 0, align: int = 0) -> TypeDesc:
    full_name = _normalize_ue_full_name(full_name)
    short_name = full_name.split(".")[-1] if full_name else ""
    package = full_name.split(".", 1)[0] if "." in full_name else ""
    return TypeDesc(
        kind=kind,
        display_name=short_name,
        full_name=full_name,
        package=package,
        size=size,
        align=align,
    )

def _make_primitive_desc(property_name: str, size_hint: int = 0) -> TypeDesc:
    display_name, known_size, known_align = _UE_PRIMITIVE_TYPES.get(
        property_name,
        ("uint8_t", size_hint or 1, _type_align_from_display("uint8_t", size_hint or 1)),
    )
    size_value = size_hint or known_size
    return TypeDesc(
        kind="primitive",
        display_name=display_name,
        size=size_value,
        align=known_align or _type_align_from_display(display_name, size_value),
    )

def _resolve_property_type_desc(
    handle: int,
    prop_ptr: int,
    property_name: str,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    legacy_names: bool = False,
    property_flags: int = 0,
    size_hint: int = 0,
    _stack: Optional[set] = None,
) -> TypeDesc:
    if prop_ptr in _type_desc_cache:
        return _type_desc_cache[prop_ptr]

    if _stack is None:
        _stack = set()
    if prop_ptr in _stack:
        return TypeDesc(kind="opaque", display_name="uint8_t", size=size_hint or 1, align=1)
    _stack.add(prop_ptr)

    base_size = _ue_property_base_size(ue_version)
    result = TypeDesc(
        kind="opaque",
        display_name="uint8_t",
        size=size_hint or 1,
        align=_type_align_from_display("uint8_t", size_hint or 1),
        metadata={"property_name": property_name},
    )
    _type_desc_cache[prop_ptr] = result

    try:
        if property_name == "ByteProperty":
            enum_ptr = read_uint64(handle, prop_ptr + base_size)
            if enum_ptr and _plausible_runtime_ptr(enum_ptr):
                enum_name = _cached_full_object_name(
                    handle, enum_ptr, gnames_ptr, ue_version, case_preserving, legacy_names
                )
                result = _make_named_type_desc("enum", enum_name, size=1, align=1)
                result.enum_underlying = _make_primitive_desc("ByteProperty", size_hint=1)
            else:
                result = _make_primitive_desc(property_name, size_hint=size_hint)
        elif property_name in _UE_PRIMITIVE_TYPES:
            result = _make_primitive_desc(property_name, size_hint=size_hint)
        elif property_name == "EnumProperty":
            underlying_ptr = read_uint64(handle, prop_ptr + base_size)
            enum_ptr = read_uint64(handle, prop_ptr + base_size + 8)
            underlying = _resolve_property_type_desc(
                handle,
                underlying_ptr,
                _resolve_property_class_name(
                    handle,
                    underlying_ptr,
                    gnames_ptr,
                    ue_version,
                    case_preserving,
                    legacy_names,
                ) if underlying_ptr else "ByteProperty",
                gnames_ptr,
                ue_version,
                case_preserving,
                legacy_names,
                size_hint=1,
                _stack=_stack,
            ) if underlying_ptr else _make_primitive_desc("ByteProperty", 1)
            enum_name = _cached_full_object_name(
                handle, enum_ptr, gnames_ptr, ue_version, case_preserving, legacy_names
            )
            if enum_name:
                result = _make_named_type_desc(
                    "enum",
                    enum_name,
                    size=underlying.size or size_hint or 1,
                    align=underlying.align or 1,
                )
                result.enum_underlying = underlying
            else:
                result = underlying
        elif property_name in _OBJECT_PROPERTY_NAMES:
            target_ptr = read_uint64(handle, prop_ptr + base_size)
            target_name = _cached_full_object_name(
                handle, target_ptr, gnames_ptr, ue_version, case_preserving, legacy_names
            )
            target = _make_named_type_desc("named_struct", target_name or "CoreUObject.Object", size=0, align=8)
            kind = {
                "WeakObjectProperty": "weak_object",
                "LazyObjectProperty": "lazy_object",
                "SoftObjectProperty": "soft_object",
                "ObjectPtrProperty": "object_ptr",
            }.get(property_name, "object")
            result = TypeDesc(
                kind=kind,
                pointee=target,
                size=size_hint or 8,
                align=8,
            )
        elif property_name in _CLASS_PROPERTY_NAMES:
            meta_offset = base_size + 8
            if property_name in {"SoftClassProperty", "AssetClassProperty"}:
                meta_offset = base_size
            meta_ptr = read_uint64(handle, prop_ptr + meta_offset)
            meta_name = _cached_full_object_name(
                handle, meta_ptr, gnames_ptr, ue_version, case_preserving, legacy_names
            )
            pointee = _make_named_type_desc("named_struct", meta_name or "CoreUObject.Object", size=0, align=8)
            if property_name in {"SoftClassProperty", "AssetClassProperty"}:
                result = TypeDesc(kind="soft_class", pointee=pointee, size=size_hint or 0x28, align=8)
            elif property_name == "ClassPtrProperty":
                result = TypeDesc(kind="class_ptr", pointee=pointee, size=size_hint or 8, align=8)
            else:
                result = TypeDesc(
                    kind="class",
                    pointee=pointee,
                    size=size_hint or 8,
                    align=8,
                    metadata={"is_subclass_of": bool(property_flags & CPF_UOBJECT_WRAPPER)},
                )
        elif property_name == "StructProperty":
            struct_ptr = read_uint64(handle, prop_ptr + base_size)
            struct_name = _cached_full_object_name(
                handle, struct_ptr, gnames_ptr, ue_version, case_preserving, legacy_names
            )
            result = _make_named_type_desc("named_struct", struct_name, size=size_hint, align=0)
        elif property_name == "ArrayProperty":
            inner_ptr = read_uint64(handle, prop_ptr + base_size)
            inner_type_name = _resolve_property_class_name(
                handle, inner_ptr, gnames_ptr, ue_version, case_preserving, legacy_names
            )
            result = TypeDesc(
                kind="array",
                inner=_resolve_property_type_desc(
                    handle,
                    inner_ptr,
                    inner_type_name,
                    gnames_ptr,
                    ue_version,
                    case_preserving,
                    legacy_names,
                    size_hint=0,
                    _stack=_stack,
                ) if inner_ptr else _make_primitive_desc("ByteProperty", 1),
                size=size_hint or 0x10,
                align=8,
            )
        elif property_name == "SetProperty":
            element_ptr = read_uint64(handle, prop_ptr + base_size)
            inner_type_name = _resolve_property_class_name(
                handle, element_ptr, gnames_ptr, ue_version, case_preserving, legacy_names
            )
            result = TypeDesc(
                kind="set",
                inner=_resolve_property_type_desc(
                    handle,
                    element_ptr,
                    inner_type_name,
                    gnames_ptr,
                    ue_version,
                    case_preserving,
                    legacy_names,
                    size_hint=0,
                    _stack=_stack,
                ) if element_ptr else _make_primitive_desc("ByteProperty", 1),
                size=size_hint or 0x50,
                align=8,
            )
        elif property_name == "MapProperty":
            key_ptr = read_uint64(handle, prop_ptr + base_size)
            value_ptr = read_uint64(handle, prop_ptr + base_size + 8)
            key_name = _resolve_property_class_name(
                handle, key_ptr, gnames_ptr, ue_version, case_preserving, legacy_names
            )
            value_name = _resolve_property_class_name(
                handle, value_ptr, gnames_ptr, ue_version, case_preserving, legacy_names
            )
            result = TypeDesc(
                kind="map",
                key=_resolve_property_type_desc(
                    handle,
                    key_ptr,
                    key_name,
                    gnames_ptr,
                    ue_version,
                    case_preserving,
                    legacy_names,
                    _stack=_stack,
                ) if key_ptr else _make_primitive_desc("ByteProperty", 1),
                value=_resolve_property_type_desc(
                    handle,
                    value_ptr,
                    value_name,
                    gnames_ptr,
                    ue_version,
                    case_preserving,
                    legacy_names,
                    _stack=_stack,
                ) if value_ptr else _make_primitive_desc("ByteProperty", 1),
                size=size_hint or 0x50,
                align=8,
            )
        elif property_name == "InterfaceProperty":
            class_ptr = read_uint64(handle, prop_ptr + base_size)
            class_name = _cached_full_object_name(
                handle, class_ptr, gnames_ptr, ue_version, case_preserving, legacy_names
            )
            result = TypeDesc(
                kind="interface",
                pointee=_make_named_type_desc("named_struct", class_name or "CoreUObject.Interface", size=0, align=8),
                size=size_hint or 0x10,
                align=8,
            )
        elif property_name == "FieldPathProperty":
            field_class_ptr = read_uint64(handle, prop_ptr + base_size)
            field_name = ""
            if field_class_ptr and _plausible_runtime_ptr(field_class_ptr):
                field_name_idx = read_uint32(handle, field_class_ptr + 0x0)
                field_name = read_fname(
                    handle,
                    gnames_ptr,
                    field_name_idx,
                    ue_version,
                    case_preserving,
                    legacy=legacy_names,
                )
            pointee_name = f"CoreUObject.{field_name}" if field_name else "CoreUObject.Field"
            result = TypeDesc(
                kind="field_path",
                pointee=_make_named_type_desc("named_struct", pointee_name, size=0, align=8),
                size=size_hint or 0x10,
                align=8,
            )
        elif property_name in _DELEGATE_PROPERTY_NAMES:
            signature_ptr = read_uint64(handle, prop_ptr + base_size)
            signature_name = _cached_full_object_name(
                handle, signature_ptr, gnames_ptr, ue_version, case_preserving, legacy_names
            )
            kind = "multicast_delegate" if "Multicast" in property_name else "delegate"
            default_name = "FMulticastScriptDelegate" if kind == "multicast_delegate" else "FScriptDelegate"
            result = TypeDesc(
                kind=kind,
                display_name=default_name,
                signature_name=default_name,
                size=size_hint or (0x10 if kind == "multicast_delegate" else 0x10),
                align=8,
                metadata={"signature_name": signature_name},
            )
        else:
            result = TypeDesc(
                kind="opaque",
                display_name="uint8_t",
                size=size_hint or 1,
                align=_type_align_from_display("uint8_t", size_hint or 1),
                metadata={"property_name": property_name},
            )
    finally:
        _stack.discard(prop_ptr)

    result.signature_name = _compute_desc_signature_name(result)
    if not result.display_name:
        result.display_name = result.signature_name
    _type_desc_cache[prop_ptr] = result
    return result

def _resolve_property_class_name(
    handle: int,
    prop_ptr: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    legacy_names: bool = False,
) -> str:
    if not prop_ptr or not _plausible_runtime_ptr(prop_ptr):
        return ""
    if _is_pre_425_ue(ue_version):
        class_ptr = read_uint64(handle, prop_ptr + UOBJECT_CLASS)
        return _cached_uobject_name(
            handle, class_ptr, gnames_ptr, ue_version, case_preserving, legacy_names
        )
    offsets = get_ffield_offsets(ue_version)
    class_ptr = read_uint64(handle, prop_ptr + offsets["FFIELD_CLASS_PRIVATE"])
    if not class_ptr:
        return ""
    cached = _ffield_class_name_cache.get(class_ptr)
    if cached:
        return cached
    type_name_idx = read_uint32(handle, class_ptr + offsets["FFIELDCLASS_NAME"])
    type_name = read_fname(
        handle,
        gnames_ptr,
        type_name_idx,
        ue_version,
        case_preserving,
        legacy=legacy_names,
    )
    if type_name:
        _ffield_class_name_cache[class_ptr] = type_name
    return type_name or ""

def _resolve_bool_meta(
    handle: int,
    prop_ptr: int,
    property_name: str,
    ue_version: str,
) -> Optional[BoolMeta]:
    if property_name != "BoolProperty" or not prop_ptr or not _plausible_runtime_ptr(prop_ptr):
        return None
    base_size = _ue_property_base_size(ue_version)
    raw = read_bytes(handle, prop_ptr + base_size, 4)
    if not raw or len(raw) < 4:
        return None
    byte_offset = raw[1]
    field_mask = raw[3]
    bit_index = -1 if field_mask == 0xFF else _ctz8(field_mask)
    return BoolMeta(
        is_native=field_mask == 0xFF,
        field_mask=field_mask,
        byte_offset=byte_offset,
        bit_index=bit_index,
    )

def _enrich_ue_dump_metadata(
    dump: SDKDump,
    handle: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    legacy_names: bool = False,
) -> None:
    _type_desc_cache.clear()
    _layout_cache.clear()

    structs_by_full = {s.full_name: s for s in dump.structs if s.full_name}
    structs_by_addr = {s.address: s for s in dump.structs if s.address}
    enums_by_full = {e.full_name: e for e in dump.enums if e.full_name}
    structs_by_name: Dict[str, List[StructInfo]] = {}
    for struct_info in dump.structs:
        structs_by_name.setdefault(struct_info.name, []).append(struct_info)
    enum_underlying: Dict[str, str] = {}

    def _apply_struct_desc_metadata(desc: Optional[TypeDesc]) -> None:
        if desc is None:
            return
        if desc.kind == "named_struct" and desc.full_name in structs_by_full:
            target = structs_by_full[desc.full_name]
            desc.size = target.size
            desc.align = (target.layout.min_alignment if target.layout else 0) or desc.align
        if desc.kind == "enum":
            underlying = desc.enum_underlying
            if underlying:
                enum_underlying[desc.full_name] = _compute_desc_signature_name(underlying)
        for child in (desc.pointee, desc.inner, desc.key, desc.value, desc.enum_underlying):
            _apply_struct_desc_metadata(child)

    for struct_info in dump.structs:
        super_ptr = int((struct_info.metadata or {}).get("super_ptr", 0) or 0)
        if super_ptr and super_ptr in structs_by_addr:
            struct_info.super_full_name = structs_by_addr[super_ptr].full_name
        elif struct_info.super_name:
            matches = structs_by_name.get(struct_info.super_name, [])
            if len(matches) == 1:
                struct_info.super_full_name = matches[0].full_name

        for member in struct_info.members:
            if member.property_ptr:
                member.type_desc = _resolve_property_type_desc(
                    handle,
                    member.property_ptr,
                    member.type_name,
                    gnames_ptr,
                    ue_version,
                    case_preserving,
                    legacy_names=legacy_names,
                    property_flags=member.flags,
                    size_hint=max(1, member.size // max(1, member.array_dim)),
                )
                member.bool_meta = _resolve_bool_meta(handle, member.property_ptr, member.type_name, ue_version)
            member.storage_offset = member.offset + (member.bool_meta.byte_offset if member.bool_meta else 0)
            _apply_struct_desc_metadata(member.type_desc)

        for func in struct_info.functions:
            func.return_param = None
            for param in func.params:
                if param.property_ptr:
                    param.type_desc = _resolve_property_type_desc(
                        handle,
                        param.property_ptr,
                        param.type_name,
                        gnames_ptr,
                        ue_version,
                        case_preserving,
                        legacy_names=legacy_names,
                        property_flags=param.flags,
                        size_hint=max(1, param.size // 1),
                    )
                    param.bool_meta = _resolve_bool_meta(handle, param.property_ptr, param.type_name, ue_version)
                param.storage_offset = param.offset + (param.bool_meta.byte_offset if param.bool_meta else 0)
                if param.type_desc:
                    param.type_desc.is_const = bool(param.flags & CPF_CONST_PARM)
                    param.type_desc.is_ref = bool(param.flags & (CPF_REFERENCE_PARM | CPF_OUT_PARM)) and not bool(param.flags & CPF_RETURN_PARM)
                _apply_struct_desc_metadata(param.type_desc)
                if param.flags & CPF_RETURN_PARM:
                    func.return_param = param

            func.params.sort(key=lambda p: (p.storage_offset if p.storage_offset >= 0 else p.offset, p.name))

    def _compute_layout(struct_info: StructInfo) -> StructLayoutMeta:
        cached = _layout_cache.get(struct_info.address)
        if cached is not None:
            return cached

        super_layout = None
        super_size = 0
        if struct_info.super_full_name and struct_info.super_full_name in structs_by_full:
            super_struct = structs_by_full[struct_info.super_full_name]
            super_layout = _compute_layout(super_struct)
            super_size = super_layout.aligned_size or super_struct.size

        min_alignment = int((struct_info.metadata or {}).get("min_alignment", 0) or 0)
        highest_member_alignment = max(1, super_layout.min_alignment if super_layout else 1)
        last_member_end = super_layout.last_member_end if super_layout else 0
        first_own_member_offset = None

        ordered_members = sorted(
            struct_info.members,
            key=lambda m: (
                m.storage_offset if m.storage_offset >= 0 else m.offset,
                (m.bool_meta.bit_index if m.bool_meta and m.bool_meta.bit_index >= 0 else 0),
                m.name,
            ),
        )
        struct_info.members[:] = ordered_members

        for member in ordered_members:
            storage_offset = member.storage_offset if member.storage_offset >= 0 else member.offset
            if first_own_member_offset is None:
                first_own_member_offset = storage_offset
            element_size = max(1, member.size // max(1, member.array_dim))
            field_alignment = _desc_alignment(member.type_desc, element_size)
            highest_member_alignment = max(highest_member_alignment, field_alignment)
            field_storage_size = max(1, element_size if member.array_dim <= 1 else member.size)
            if member.bool_meta and not member.bool_meta.is_native:
                field_storage_size = 1
            last_member_end = max(last_member_end, storage_offset + field_storage_size)

        if min_alignment <= 0:
            min_alignment = highest_member_alignment or 1
        aligned_size = _align_up(struct_info.size, min_alignment)
        reuses_super_tail_padding = bool(
            super_layout
            and first_own_member_offset is not None
            and first_own_member_offset < (super_layout.aligned_size or super_size)
            and first_own_member_offset >= super_layout.last_member_end
        )
        layout = StructLayoutMeta(
            min_alignment=max(1, min_alignment),
            aligned_size=max(struct_info.size, aligned_size),
            unaligned_size=struct_info.size,
            highest_member_alignment=max(1, highest_member_alignment),
            last_member_end=max(last_member_end, super_layout.last_member_end if super_layout else 0),
            super_size=super_size,
            reuses_super_tail_padding=reuses_super_tail_padding,
        )
        struct_info.layout = layout
        _layout_cache[struct_info.address] = layout
        return layout

    for struct_info in dump.structs:
        _compute_layout(struct_info)

    for struct_info in dump.structs:
        for member in struct_info.members:
            _apply_struct_desc_metadata(member.type_desc)
        for func in struct_info.functions:
            for param in func.params:
                _apply_struct_desc_metadata(param.type_desc)

    for desc_full_name, underlying_name in enum_underlying.items():
        enum_info = enums_by_full.get(desc_full_name)
        if enum_info is not None:
            enum_info.metadata["underlying_type"] = underlying_name

def _walk_struct(
    handle: int,
    struct_ptr: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    is_class: bool = False,
    offsets: dict = None,
    legacy_names: bool = False,
    base: int = 0,
    size: int = 0,
    preread_members=None,
    global_preread_map=None,
    preread_header=None,
    preread_func_ptrs=None,
    global_preread_function_info=None,
) -> Optional[StructInfo]:
    import struct as _s
    pre_425 = _is_pre_425_ue(ue_version)
    pre_423 = _is_pre_423_ue(ue_version)

    if pre_423:
        super_off = USTRUCT_SUPER_LEGACY
        children_off = USTRUCT_CHILDREN_LEGACY
        props_size_off = USTRUCT_PROPERTIES_SIZE_LEGACY
        min_alignment_off = USTRUCT_MIN_ALIGNMENT_LEGACY
    else:
        super_off = USTRUCT_SUPER
        children_off = USTRUCT_CHILDREN
        props_size_off = USTRUCT_PROPERTIES_SIZE
        min_alignment_off = USTRUCT_MIN_ALIGNMENT

    def _cached_obj_name(ptr: int) -> str:
        cached = _uobject_name_cache.get(ptr)
        if cached is not None:
            return cached
        nidx = read_uint32(handle, ptr + UOBJECT_NAME)
        n = read_fname(
            handle, gnames_ptr, nidx, ue_version, case_preserving, legacy=legacy_names
        )
        _uobject_name_cache[ptr] = n
        return n

    _hdr = preread_header
    if _hdr and len(_hdr) >= 0x60 and not pre_423:
        name = _cached_obj_name(struct_ptr)
        if not name:
            return None
        outer_ptr = _s.unpack_from("<Q", _hdr, UOBJECT_OUTER)[0]
        package = _normalize_ue_full_name(_cached_obj_name(outer_ptr)) if outer_ptr else ""
        props_size = _s.unpack_from("<i", _hdr, props_size_off)[0]
        if props_size <= 0:
            return None
        super_ptr = _s.unpack_from("<Q", _hdr, super_off)[0]
        super_name = _cached_obj_name(super_ptr) if super_ptr else ""
        child_ptr = _s.unpack_from("<Q", _hdr, children_off)[0]
        min_alignment = _s.unpack_from("<I", _hdr, min_alignment_off)[0] if len(_hdr) >= min_alignment_off + 4 else 0
    else:
        name = _cached_obj_name(struct_ptr)
        if not name:
            return None
        outer_ptr = read_uint64(handle, struct_ptr + UOBJECT_OUTER)
        package = _normalize_ue_full_name(_cached_obj_name(outer_ptr)) if outer_ptr else ""
        props_size = read_int32(handle, struct_ptr + props_size_off)
        if props_size <= 0:
            return None
        super_ptr = read_uint64(handle, struct_ptr + super_off)
        super_name = _cached_obj_name(super_ptr) if super_ptr else ""
        child_ptr = None
        min_alignment = read_uint32(handle, struct_ptr + min_alignment_off)

    full_name = _normalize_ue_full_name(f"{package}.{name}" if package else name)

    _sc_next_off = USTRUCT_SUPER_LEGACY if pre_423 else USTRUCT_SUPER
    if super_ptr and super_ptr in _super_chain_cache:
        super_chain = list(_super_chain_cache[super_ptr])
    else:
        super_chain = []
        _sc_ptr = super_ptr
        _sc_visited = set()
        while _sc_ptr and _sc_ptr > 0x10000 and len(super_chain) < 50:
            if _sc_ptr in _sc_visited:
                break
            if _sc_ptr in _super_chain_cache:
                super_chain.extend(_super_chain_cache[_sc_ptr])
                break
            _sc_visited.add(_sc_ptr)
            _sc_name = _cached_obj_name(_sc_ptr)
            if _sc_name:
                super_chain.append(_sc_name)
            _sc_ptr = read_uint64(handle, _sc_ptr + _sc_next_off)
        if super_ptr and super_ptr > 0x10000:
            _super_chain_cache[super_ptr] = super_chain

    info = StructInfo(
        name=name,
        full_name=full_name,
        address=struct_ptr,
        size=props_size,
        super_name=super_name,
        is_class=is_class,
        package=package,
        super_chain=super_chain,
    )
    info.metadata["super_ptr"] = super_ptr
    info.metadata["min_alignment"] = int(min_alignment or 0)

    visited: set = set()
    max_props = 500

    if preread_func_ptrs is not None and not pre_425:
        for func_ptr in preread_func_ptrs[:max_props]:
            if not (0x10000 <= func_ptr <= 0x7FFFFFFFFFFF):
                continue
            func = _read_ufunction(
                handle,
                func_ptr,
                gnames_ptr,
                ue_version,
                case_preserving,
                offsets=offsets,
                legacy_names=legacy_names,
                base=base,
                size=size,
                preread_members=global_preread_map.get(func_ptr) if global_preread_map else None,
                preread_info=global_preread_function_info.get(func_ptr) if global_preread_function_info else None,
            )
            if func:
                info.functions.append(func)
        child_ptr = 0

    if child_ptr is None:
        child_ptr = read_uint64(handle, struct_ptr + children_off)
    
    from src.core.memory import add_memory_snapshot, USE_DRIVER

    _skip_prescan = preread_members is not None or preread_func_ptrs is not None
    if USE_DRIVER and not _skip_prescan:
        from src.core.driver import COMM_DATA_MAXSIZE, read_memory_kernel_ex
        from src.core.memory import TARGET_PID, _snapshot_pages
        page_size = 0x1000

        def _ensure_page_snapshotted(ptr, snapped_pages):
            page = ptr & ~(page_size - 1)
            if page not in snapped_pages and page not in _snapshot_pages:
                result = read_memory_kernel_ex(TARGET_PID, page, page_size)
                actual = result.actual_byte_count(page_size, COMM_DATA_MAXSIZE)
                if actual:
                    data = result.data
                    if len(data) < page_size:
                        data = data.ljust(page_size, b"\x00")
                    add_memory_snapshot(page, data)
                snapped_pages.add(page)

        snapped = set()

        curr = child_ptr
        while curr and not (curr in visited) and (0x10000 <= curr <= 0x7FFFFFFFFFFF):
            _ensure_page_snapshotted(curr, snapped)
            field_class_ptr = read_uint64(handle, curr + UOBJECT_CLASS)
            if field_class_ptr:
                _ensure_page_snapshotted(field_class_ptr, snapped)
            curr = read_uint64(handle, curr + UPROPERTY_NEXT)
            if len(snapped) > 2000:
                break

        if not pre_425:
            if offsets is None:
                offsets = get_ffield_offsets(ue_version)
            child_prop_prescan = read_uint64(handle, struct_ptr + USTRUCT_CHILD_PROPS)
            curr = child_prop_prescan
            while curr and not (curr in visited) and (0x10000 <= curr <= 0x7FFFFFFFFFFF):
                _ensure_page_snapshotted(curr, snapped)
                class_priv = read_uint64(handle, curr + offsets["FFIELD_CLASS_PRIVATE"])
                if class_priv:
                    _ensure_page_snapshotted(class_priv, snapped)
                curr = read_uint64(handle, curr + offsets["FFIELD_NEXT"])
                if len(snapped) > 2000:
                    break

    child_ptr_run = child_ptr
    while child_ptr_run and len(info.members) + len(info.functions) < max_props:
        if child_ptr_run in visited:
            break
        visited.add(child_ptr_run)

        if not (0x10000 <= child_ptr_run <= 0x7FFFFFFFFFFF):
            break

        field_class_ptr = read_uint64(handle, child_ptr_run + UOBJECT_CLASS)
        field_class_name = ""
        if _plausible_uobject_class_ptr(field_class_ptr):
            field_class_name = _ffield_class_name_cache.get(field_class_ptr, "")
            if not field_class_name:
                fcn_idx = read_uint32(handle, field_class_ptr + UOBJECT_NAME)
                field_class_name = read_fname(
                    handle, gnames_ptr, fcn_idx, ue_version, case_preserving, legacy=legacy_names
                )
                if field_class_name:
                    _ffield_class_name_cache[field_class_ptr] = field_class_name
        if "Function" in field_class_name:
            func = _read_ufunction(
                handle, child_ptr_run, gnames_ptr, ue_version, case_preserving,
                offsets=offsets, legacy_names=legacy_names, base=base, size=size,
                preread_members=global_preread_map.get(child_ptr_run) if global_preread_map else None,
                preread_info=global_preread_function_info.get(child_ptr_run) if global_preread_function_info else None,
            )
            if func:
                info.functions.append(func)
        elif pre_425 and "Property" in field_class_name:
            member = _read_uproperty(
                handle, child_ptr_run, gnames_ptr, ue_version, case_preserving,
                field_class_name, legacy_names=legacy_names,
            )
            if member:
                info.members.append(member)

        child_ptr_run = read_uint64(handle, child_ptr_run + UPROPERTY_NEXT)

    if not pre_425:
        if offsets is None:
            offsets = get_ffield_offsets(ue_version)

        if preread_members is not None:
            info.members.extend(preread_members)
        else:
            from src.core.memory import USE_DRIVER as _USE_DRV
            if _USE_DRV:
                fallback_map = _scatter_walk_ffield_chains(
                    [struct_ptr], handle, gnames_ptr, ue_version,
                    case_preserving, offsets, legacy_names,
                )
                info.members.extend(fallback_map.get(struct_ptr, []))
            else:
                child_prop_run = read_uint64(handle, struct_ptr + USTRUCT_CHILD_PROPS)
                while child_prop_run and len(info.members) < max_props:
                    if child_prop_run in visited:
                        break
                    visited.add(child_prop_run)
                    if not (0x10000 <= child_prop_run <= 0x7FFFFFFFFFFF):
                        break
                    member = _read_property(
                        handle, child_prop_run, gnames_ptr, ue_version, case_preserving,
                        offsets=offsets, legacy_names=legacy_names,
                    )
                    if member:
                        info.members.append(member)
                    child_prop_run = read_uint64(handle, child_prop_run + offsets["FFIELD_NEXT"])

    for m in info.members:
        if m.offset + m.size > props_size:
            logger.warning(
                f"Size violation in {name}: {m.name} "
                f"offset=0x{m.offset:X} size={m.size} "
                f"exceeds PropertiesSize={props_size}"
            )

    return info

def _probe_ufunction_flags(handle: int, func_ptr: int, ue_version: str = "") -> int:
    _COMMON_BITS = 0x04020400

    if ue_version and ue_version in _ufunction_flags_offset_cache:
        cached_off = _ufunction_flags_offset_cache[ue_version]
        return read_uint32(handle, func_ptr + cached_off)

    for off in _UFUNCTION_FLAGS_PROBE_OFFSETS:
        val = read_uint32(handle, func_ptr + off)
        if val and 0 < val <= 0xFFFFFFFF and (val & _COMMON_BITS):
            if ue_version:
                _ufunction_flags_offset_cache[ue_version] = off
                logger.debug(
                    "UFunction flags offset cached: 0x%X for UE %s", off, ue_version
                )
            return val
    return 0

def _read_ufunction(
    handle: int,
    func_ptr: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    offsets: dict = None,
    legacy_names: bool = False,
    base: int = 0,
    size: int = 0,
    preread_members=None,
    preread_info=None,
) -> Optional[FunctionInfo]:
    name = ""
    if preread_info is not None:
        name = preread_info.get("name", "") or _uobject_name_cache.get(func_ptr, "")
    if not name:
        name_idx = read_uint32(handle, func_ptr + UOBJECT_NAME)
        name = read_fname(
            handle, gnames_ptr, name_idx, ue_version, case_preserving, legacy=legacy_names
        )
    if not name:
        return None
    _uobject_name_cache[func_ptr] = name

    func_flags = preread_info.get("flags", 0) if preread_info is not None else 0
    if not func_flags:
        func_flags = _probe_ufunction_flags(handle, func_ptr, ue_version)

    func_info = FunctionInfo(name=name, address=func_ptr, flags=func_flags)

    if preread_info is not None:
        func_info.exec_func = preread_info.get("exec_func", 0)
        func_info.rva = preread_info.get("rva", 0)
    elif base and size:
        cached_off = _ufunction_flags_offset_cache.get(ue_version)
        if hasattr(_read_ufunction, f"_cached_{ue_version}_exec_off"):
            exec_off = getattr(_read_ufunction, f"_cached_{ue_version}_exec_off")
            ptr = read_uint64(handle, func_ptr + exec_off)
            if base <= ptr < base + size:
                func_info.exec_func = ptr
                func_info.rva = ptr - base
        else:
            scan_start = (cached_off - 0x20) if cached_off else 0x40
            scan_end = (cached_off + 0x40) if cached_off else 0xC0
            for off in range(max(0, scan_start), scan_end, 8):
                ptr = read_uint64(handle, func_ptr + off)
                if base <= ptr < base + size:
                    func_info.exec_func = ptr
                    func_info.rva = ptr - base
                    setattr(_read_ufunction, f"_cached_{ue_version}_exec_off", off)
                    break

    pre_425 = _is_pre_425_ue(ue_version)
    pre_423 = _is_pre_423_ue(ue_version)

    if pre_423:
        children_off = USTRUCT_CHILDREN_LEGACY
    else:
        children_off = USTRUCT_CHILDREN

    visited: set = set()
    max_params = 64

    if pre_425:
        child_ptr = read_uint64(handle, func_ptr + children_off)
        while child_ptr and len(func_info.params) < max_params:
            if child_ptr in visited:
                break
            visited.add(child_ptr)

            if not (0x10000 <= child_ptr <= 0x7FFFFFFFFFFF):
                break

            member = _read_uproperty(
                handle,
                child_ptr,
                gnames_ptr,
                ue_version,
                case_preserving,
                legacy_names=legacy_names,
            )
            if member:
                flags = read_uint64(handle, child_ptr + UPROPERTY_PROPERTY_FLAGS)
                param = FunctionParamInfo(
                    name=member.name,
                    offset=member.offset,
                    size=member.size,
                    type_name=member.type_name,
                    flags=flags,
                    property_ptr=child_ptr,
                )
                func_info.params.append(param)

            child_ptr = read_uint64(handle, child_ptr + UPROPERTY_NEXT)
    else:
        if offsets is None:
            offsets = get_ffield_offsets(ue_version)

        _members = preread_members
        if _members is None:
            from src.core.memory import USE_DRIVER as _USE_DRV
            if _USE_DRV:
                _fback = _scatter_walk_ffield_chains(
                    [func_ptr], handle, gnames_ptr, ue_version,
                    case_preserving, offsets, legacy_names,
                )
                _members = _fback.get(func_ptr, [])

        if _members is not None:
            for member in _members:
                param = FunctionParamInfo(
                    name=member.name,
                    offset=member.offset,
                    size=member.size,
                    type_name=member.type_name,
                    flags=getattr(member, 'flags', 0),
                    property_ptr=getattr(member, "property_ptr", 0),
                )
                func_info.params.append(param)
        else:
            child_prop = read_uint64(handle, func_ptr + USTRUCT_CHILD_PROPS)

            while child_prop and len(func_info.params) < max_params:
                if child_prop in visited:
                    break
                visited.add(child_prop)

                if not (0x10000 <= child_prop <= 0x7FFFFFFFFFFF):
                    break

                member = _read_property(
                    handle,
                    child_prop,
                    gnames_ptr,
                    ue_version,
                    case_preserving,
                    offsets=offsets,
                    legacy_names=legacy_names,
                )
                if member:
                    flags = read_uint64(handle, child_prop + offsets["FPROPERTY_FLAGS"])
                    param = FunctionParamInfo(
                        name=member.name,
                        offset=member.offset,
                        size=member.size,
                        type_name=member.type_name,
                        flags=flags,
                    )
                    func_info.params.append(param)

                child_prop = read_uint64(handle, child_prop + offsets["FFIELD_NEXT"])

    return func_info

def _read_uproperty(
    handle: int,
    prop_ptr: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    type_name: str = "",
    legacy_names: bool = False,
) -> Optional[MemberInfo]:
    name_idx = read_uint32(handle, prop_ptr + UOBJECT_NAME)
    name = read_fname(
        handle, gnames_ptr, name_idx, ue_version, case_preserving, legacy=legacy_names
    )
    if not name:
        return None

    if not type_name:
        class_ptr = read_uint64(handle, prop_ptr + UOBJECT_CLASS)
        if class_ptr:
            type_name_idx = read_uint32(handle, class_ptr + UOBJECT_NAME)
            type_name = read_fname(
                handle,
                gnames_ptr,
                type_name_idx,
                ue_version,
                case_preserving,
                legacy=legacy_names,
            )

    array_dim = read_int32(handle, prop_ptr + UPROPERTY_ARRAY_DIM)
    element_size = read_int32(handle, prop_ptr + UPROPERTY_ELEMENT_SIZE)
    offset = read_int32(handle, prop_ptr + UPROPERTY_OFFSET_INTERNAL)

    if offset < 0 or element_size <= 0:
        return None

    size = element_size * max(array_dim, 1)

    return MemberInfo(
        name=name,
        offset=offset,
        size=size,
        type_name=type_name or "Unknown",
        array_dim=array_dim if array_dim > 1 else 1,
        property_ptr=prop_ptr,
    )

def _read_property(
    handle: int,
    prop_ptr: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    offsets: dict = None,
    legacy_names: bool = False,
) -> Optional[MemberInfo]:
    if offsets is None:
        offsets = get_ffield_offsets(ue_version)

    name_idx = read_uint32(handle, prop_ptr + offsets["FFIELD_NAME"])
    name = read_fname(
        handle, gnames_ptr, name_idx, ue_version, case_preserving, legacy=legacy_names
    )
    if not name:
        return None

    class_private = read_uint64(handle, prop_ptr + offsets["FFIELD_CLASS_PRIVATE"])
    type_name = ""
    if class_private:
        type_name_idx = read_uint32(handle, class_private + offsets["FFIELDCLASS_NAME"])
        type_name = read_fname(
            handle,
            gnames_ptr,
            type_name_idx,
            ue_version,
            case_preserving,
            legacy=legacy_names,
        )

    offset = read_int32(handle, prop_ptr + offsets["FPROPERTY_OFFSET"])
    element_size = read_int32(handle, prop_ptr + offsets["FPROPERTY_ELEMENT_SIZE"])
    array_dim = read_int32(handle, prop_ptr + offsets["FPROPERTY_ARRAY_DIM"])
    flags = read_uint64(handle, prop_ptr + offsets["FPROPERTY_FLAGS"])

    if offset < 0 or element_size <= 0:
        return None

    size = element_size * max(array_dim, 1)

    return MemberInfo(
        name=name,
        offset=offset,
        size=size,
        type_name=type_name or "Unknown",
        array_dim=array_dim if array_dim > 1 else 1,
        flags=flags,
        property_ptr=prop_ptr,
    )

def _walk_enum(
    handle: int,
    enum_ptr: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    legacy_names: bool = False,
) -> Optional[EnumInfo]:

    name_idx = read_uint32(handle, enum_ptr + UOBJECT_NAME)
    name = read_fname(
        handle, gnames_ptr, name_idx, ue_version, case_preserving, legacy=legacy_names
    )
    if not name:
        return None

    outer_ptr = read_uint64(handle, enum_ptr + UOBJECT_OUTER)
    package = ""
    if outer_ptr:
        outer_name_idx = read_uint32(handle, outer_ptr + UOBJECT_NAME)
        package = read_fname(
            handle,
            gnames_ptr,
            outer_name_idx,
            ue_version,
            case_preserving,
            legacy=legacy_names,
        )

    full_name = _normalize_ue_full_name(f"{package}.{name}" if package else name)

    info = EnumInfo(name=name, full_name=full_name, address=enum_ptr)

    names_data_ptr = 0
    names_count = 0
    for off in _UENUM_NAMES_PROBE_OFFSETS:
        p = read_uint64(handle, enum_ptr + off)
        c = read_int32(handle, enum_ptr + off + 8)
        if p and 1 <= c <= 500:
            names_data_ptr = p
            names_count = c
            break

    if not names_data_ptr or names_count <= 0:
        return info

    tarray_size = names_count * 16
    tarray_data = read_bytes(handle, names_data_ptr, tarray_size)

    if tarray_data and len(tarray_data) >= tarray_size:
        for i in range(names_count):
            off = i * 16
            entry_name_idx = struct.unpack_from("<I", tarray_data, off)[0]
            entry_value = struct.unpack_from("<q", tarray_data, off + 8)[0]

            entry_name = read_fname(
                handle,
                gnames_ptr,
                entry_name_idx,
                ue_version,
                case_preserving,
                legacy=legacy_names,
            )
            if entry_name:
                info.values.append((entry_name, entry_value))
    else:
        for i in range(names_count):
            entry_addr = names_data_ptr + i * 16
            entry_name_idx = read_uint32(handle, entry_addr)
            entry_value = read_uint64(handle, entry_addr + 8)

            entry_name = read_fname(
                handle,
                gnames_ptr,
                entry_name_idx,
                ue_version,
                case_preserving,
                legacy=legacy_names,
            )
            if entry_name:
                info.values.append((entry_name, entry_value))

    return info
