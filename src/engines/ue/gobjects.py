
import time as _time
import struct
from typing import Dict, List, Optional, Tuple
from collections import Counter

from src.core.memory import read_bytes, read_uint64, read_uint32, read_int32
from src.core.pe_parser import get_pe_rdata_data_scan_ranges
from src.core.scanner import scan_pattern, resolve_rip
from src.engines.ue.signatures import get_gobjects_signatures
from src.engines.ue.offsets_override import load_game_offsets_override
from src.engines.ue.gnames import read_fname

import logging

logger = logging.getLogger(__name__)

BRUTE_TIMEOUT = 20.0

OBJECTS_PER_CHUNK = 0x10000
FUOBJECTITEM_SIZE_LEGACY = 16
FUOBJECTITEM_SIZE_NORMAL = 24
FUOBJECTITEM_SIZE_STATS = 32
FUOBJECTITEM_SIZE_UE5 = 48

_PLAUSIBLE_PTR_LO = 0x10000
_PLAUSIBLE_PTR_HI = 0x7FFFFFFFFFFF
_PLAUSIBLE_64BIT_HEAP_LO = 0x100000000
PAGE_SIZE = 0x1000
FUOBJECTARRAY_SEARCH_BYTES = 0x40
FUOBJECTARRAY_OBJECT_PTR_OFFSETS = (0x0, 0x8, 0x10, 0x18)
FUOBJECTARRAY_COUNTER_SCAN_MAX = 0x2C
FUOBJECTARRAY_CANDIDATE_LIMIT = 4096
FUOBJECTARRAY_SAMPLE_SLOTS = 16

BRUTE_TIMEOUT = 45.0
FUOBJECTARRAY_OBJECT_PTR_OFFSETS = tuple(range(0, 0x31, 8))
FUOBJECTARRAY_COUNTER_SCAN_MAX = 0x30
FUOBJECTARRAY_CANDIDATE_LIMIT = 8192
FUOBJECTARRAY_SIGNATURE_BACKTRACK = 0x38
FUOBJECTARRAY_SIGNATURE_FORWARD = 0x10
FUOBJECTARRAY_HEAP_POINTER_LIMIT = 60000
FUOBJECTARRAY_HEAP_SHAPE_LIMIT = 256
FUOBJECTARRAY_HEAP_SAMPLE_MAX = 32
FUOBJECTARRAY_STAGE2_LIMIT = 512
FUOBJECTARRAY_PREFETCH_PAGE_LIMIT = 512
GOBJECTS_KERNEL_AOB_MAX_BYTES = 4 * 1024 * 1024

_gobjects_brute_last_meta: Dict[str, int] = {}
_gobjects_names_seeded_last_meta: Dict[str, int] = {}
_gobjects_objects_offset: Dict[int, int] = {}
_gobjects_objects_mode: Dict[int, str] = {}
_gobjects_resolution_meta: Dict[str, object] = {}
FUOBJECTARRAY_LAYOUT_BONUSES = {
    (0x0, 0x8): 4,
    (0x0, 0x10): 3,
    (0x10, 0x18): 6,
    (0x20, 0x30): 6,
}
_KNOWN_GOBJECT_CLASS_NAMES = {
    "Class",
    "Package",
    "World",
    "Level",
    "Function",
    "Enum",
    "ScriptStruct",
    "Struct",
    "Property",
    "ObjectProperty",
    "ClassProperty",
}

def get_last_gobjects_resolution_meta() -> Dict[str, object]:
    return dict(_gobjects_resolution_meta)

def _start_gobjects_resolution_meta(ue_version: str) -> None:
    _gobjects_resolution_meta.clear()
    _gobjects_resolution_meta.update(
        {
            "status": "scanning",
            "ue_version": ue_version,
            "selected_signatures": [],
            "signature_details": {},
            "signature_hit_count": 0,
            "signature_resolved_count": 0,
            "normalized_candidate_attempts": 0,
            "normalized_candidate_matches": 0,
            "signature_rejections": {},
            "structural": {},
            "names_seeded": {
                "attempted": False,
                "gnames_recovered": False,
                "succeeded": False,
            },
        }
    )

def _record_gobjects_failure(
    failure_kind: str,
    detail: str,
    *,
    signature_rejections: Optional[Counter] = None,
) -> None:
    _gobjects_resolution_meta.update(
        {
            "status": "failed",
            "failure_kind": failure_kind,
            "failure_detail": detail,
        }
    )
    if signature_rejections is not None:
        _gobjects_resolution_meta["signature_rejections"] = dict(
            signature_rejections.most_common()
        )

def _set_gobjects_resolution_meta(
    *,
    address: int,
    item_size: int,
    method: str,
    objects_offset: Optional[int] = None,
    objects_mode: Optional[str] = None,
) -> None:
    _gobjects_resolution_meta.update(
        {
            "status": "resolved",
            "address": address,
            "item_size": item_size,
            "method": method,
            "objects_offset": (
                FUOBJECTARRAY_OBJECTS_OFFSET
                if objects_offset is None
                else objects_offset
            ),
            "objects_mode": objects_mode
            or _gobjects_objects_mode.get(address, "chunked"),
        }
    )

def clear_gobjects_scan_state() -> None:
    _gobjects_brute_cache.clear()
    _gobjects_brute_last_meta.clear()
    _gobjects_names_seeded_last_meta.clear()
    _gobjects_objects_offset.clear()
    _gobjects_objects_mode.clear()
    _gobjects_resolution_meta.clear()

def get_gobjects_objects_offset(gobjects_ptr: int) -> int:
    return _gobjects_objects_offset.get(gobjects_ptr, FUOBJECTARRAY_OBJECTS_OFFSET)

def get_gobjects_objects_mode(gobjects_ptr: int) -> str:
    return _gobjects_objects_mode.get(gobjects_ptr, "chunked")

def get_gobjects_objects_ptr(handle: int, gobjects_ptr: int) -> int:
    return read_uint64(handle, gobjects_ptr + get_gobjects_objects_offset(gobjects_ptr))

def _plausible_ue_ptr64(p: int) -> bool:
    return _PLAUSIBLE_PTR_LO < p < _PLAUSIBLE_PTR_HI

def _plausible_module_ptr(value: int, module_base: int, module_end: int) -> bool:
    return bool(module_base and module_base <= value < module_end)

def _plausible_runtime_heap_ptr(value: int, module_base: int, module_end: int) -> bool:
    if not _plausible_ue_ptr64(value):
        return False
    if module_base >= _PLAUSIBLE_64BIT_HEAP_LO and value < _PLAUSIBLE_64BIT_HEAP_LO:
        return False
    return not _plausible_module_ptr(value, module_base, module_end)

def _try_read_qword(handle: int, address: int) -> Tuple[bool, int]:
    data = read_bytes(handle, address, 8)
    if len(data) < 8:
        return False, 0
    return True, int.from_bytes(data, "little")

def _shape_looks_like_fuobjectarray(
    num_elements: int,
    max_elements: int,
    num_chunks: int,
    max_chunks: int,
) -> bool:
    if not (GOBJECTS_BRUTE_MIN_OBJECT_COUNT <= num_elements <= 5_000_000):
        return False
    if max_elements and max_elements < num_elements:
        return False
    if max_elements and max_elements > 16_000_000:
        return False
    if not (1 <= num_chunks <= 0x4000):
        return False
    if max_chunks and max_chunks < num_chunks:
        return False
    if max_chunks and max_chunks > 0x4000:
        return False

    expected_chunks = max(
        1, (num_elements + OBJECTS_PER_CHUNK - 1) // OBJECTS_PER_CHUNK
    )
    if num_chunks < expected_chunks:
        return False
    if max_chunks and max_chunks < expected_chunks:
        return False
    return True

def _probe_fuobjectarray_shape(handle: int, base: int) -> Optional[Dict[str, int]]:
    raw = read_bytes(handle, base, FUOBJECTARRAY_SEARCH_BYTES)
    if len(raw) < 0x20:
        return None
    return _probe_fuobjectarray_candidate_bytes(raw, base_addr=base)

def _normalize_gobjects_signature_candidates(
    handle: int,
    target: int,
    module_base: int,
    module_size: int,
) -> List[Dict[str, object]]:
    module_end = module_base + module_size
    aligned_target = target & ~0x7
    starts: List[int] = []
    seen = set()

    for delta in range(0, FUOBJECTARRAY_SIGNATURE_BACKTRACK + 1, 8):
        starts.append(aligned_target - delta)
    for delta in range(8, FUOBJECTARRAY_SIGNATURE_FORWARD + 1, 8):
        starts.append(aligned_target + delta)

    candidates: List[Dict[str, object]] = []
    for base in starts:
        if base in seen or not (module_base <= base < module_end):
            continue
        seen.add(base)
        shape = _probe_fuobjectarray_shape(handle, base)
        if shape is None:
            continue
        candidate: Dict[str, object] = dict(shape)
        candidate["base_addr"] = base
        candidate["source_addr"] = target
        candidate["source_delta"] = base - target
        candidate["normalized"] = base != target
        candidates.append(candidate)

    candidates.sort(
        key=lambda item: (
            int(item.get("score", 0)),
            -abs(int(item.get("source_delta", 0))),
            -int(item.get("base_addr", 0)),
        ),
        reverse=True,
    )

    if target not in seen and module_base <= target < module_end:
        candidates.append(
            {
                "base_addr": target,
                "source_addr": target,
                "source_delta": 0,
                "normalized": False,
            }
        )
    elif (
        module_base <= target < module_end
        and not any(int(item["base_addr"]) == target for item in candidates)
    ):
        candidates.append(
            {
                "base_addr": target,
                "source_addr": target,
                "source_delta": 0,
                "normalized": False,
            }
        )
    return candidates

def _probe_fuobjectarray_candidate_bytes(
    raw: bytes,
    *,
    base_addr: int = 0,
    module_base: int = 0,
    module_end: int = 0,
) -> Optional[Dict[str, int]]:
    if len(raw) < 0x20:
        return None

    best: Optional[Dict[str, int]] = None
    best_score = -1
    ptr_checker = (
        (lambda value: _plausible_runtime_heap_ptr(value, module_base, module_end))
        if module_base and module_end
        else _plausible_ue_ptr64
    )

    max_counter_off = min(len(raw) - 16, FUOBJECTARRAY_COUNTER_SCAN_MAX)
    for objects_off in FUOBJECTARRAY_OBJECT_PTR_OFFSETS:
        if objects_off + 8 > len(raw):
            continue
        objects_ptr = struct.unpack_from("<Q", raw, objects_off)[0]
        if not ptr_checker(objects_ptr):
            continue

        for counter_off in range(0, max_counter_off + 1, 4):
            max_elements = struct.unpack_from("<i", raw, counter_off + 0x0)[0]
            num_elements = struct.unpack_from("<i", raw, counter_off + 0x4)[0]
            max_chunks = struct.unpack_from("<i", raw, counter_off + 0x8)[0]
            num_chunks = struct.unpack_from("<i", raw, counter_off + 0xC)[0]

            if not _shape_looks_like_fuobjectarray(
                num_elements=num_elements,
                max_elements=max_elements,
                num_chunks=num_chunks,
                max_chunks=max_chunks,
            ):
                continue

            expected_chunks = max(
                1, (num_elements + OBJECTS_PER_CHUNK - 1) // OBJECTS_PER_CHUNK
            )
            score = 0
            score += max(0, 4 - abs(objects_off - 0x10) // 8)
            score += max(
                0,
                8
                - abs(
                    counter_off - min(objects_off + 8, FUOBJECTARRAY_COUNTER_SCAN_MAX)
                ),
            )
            score += 2 if max_elements >= num_elements else 0
            score += 2 if max_chunks >= num_chunks else 0
            score += 2 if num_chunks == expected_chunks else 1
            score += 1 if max_elements else 0
            score += 1 if max_chunks else 0
            score += FUOBJECTARRAY_LAYOUT_BONUSES.get((objects_off, counter_off), 0)

            candidate = {
                "layout": "scored",
                "base_addr": base_addr,
                "objects_ptr": objects_ptr,
                "objects_off": objects_off,
                "max_elements": max_elements,
                "num_elements": num_elements,
                "max_chunks": max_chunks,
                "num_chunks": num_chunks,
                "counter_off": counter_off,
                "score": score,
            }
            if score > best_score:
                best_score = score
                best = candidate

    return best

def _page_align(value: int) -> int:
    return value & ~(PAGE_SIZE - 1)

def _cap_ranges_by_total(
    ranges: List[Tuple[int, int]],
    max_bytes: int,
) -> Tuple[List[Tuple[int, int]], bool]:
    if max_bytes <= 0:
        return ranges, False

    capped: List[Tuple[int, int]] = []
    remaining = max_bytes
    capped_any = False
    for start, end in ranges:
        if remaining <= 0:
            capped_any = True
            break
        span = max(0, end - start)
        if span <= remaining:
            capped.append((start, end))
            remaining -= span
            continue
        capped.append((start, start + remaining))
        capped_any = True
        remaining = 0
        break
    return capped, capped_any or len(capped) < len(ranges)

def _iter_fuobjectarray_counter_clusters(data: bytes):
    usable = len(data) & ~0x3
    if usable < 16:
        return

    words = memoryview(data)[:usable].cast("I")
    max_index = len(words) - 3
    for idx in range(max_index):
        num_elements = int(words[idx + 1])
        if not (GOBJECTS_BRUTE_MIN_OBJECT_COUNT <= num_elements <= 5_000_000):
            continue

        max_elements = int(words[idx + 0])
        if max_elements and (max_elements < num_elements or max_elements > 16_000_000):
            continue

        max_chunks = int(words[idx + 2])
        num_chunks = int(words[idx + 3])
        if not (1 <= num_chunks <= 0x4000):
            continue
        if max_chunks and (max_chunks < num_chunks or max_chunks > 0x4000):
            continue

        expected_chunks = max(
            1, (num_elements + OBJECTS_PER_CHUNK - 1) // OBJECTS_PER_CHUNK
        )
        if num_chunks < expected_chunks:
            continue
        if max_chunks and max_chunks < expected_chunks:
            continue

        yield idx * 4

def _enumerate_fuobjectarray_candidates(
    handle: int,
    ranges: List[Tuple[int, int]],
    module_base: int,
    module_end: int,
    deadline: float,
) -> List[Dict[str, int]]:
    candidates: Dict[Tuple[int, int, int, int, int], Dict[str, int]] = {}
    counter_offsets = tuple(range(0, FUOBJECTARRAY_COUNTER_SCAN_MAX + 1, 4))

    for start, end in ranges:
        if _time.monotonic() > deadline:
            break
        data = read_bytes(handle, start, end - start)
        if len(data) < FUOBJECTARRAY_SEARCH_BYTES:
            continue

        for cluster_rel in _iter_fuobjectarray_counter_clusters(data):
            if (cluster_rel & 0x1FF) == 0 and _time.monotonic() > deadline:
                break

            for counter_off in counter_offsets:
                if cluster_rel < counter_off:
                    continue
                base_rel = cluster_rel - counter_off
                if base_rel & 0x7:
                    continue
                if base_rel + FUOBJECTARRAY_SEARCH_BYTES > len(data):
                    continue

                base_addr = start + base_rel
                probe = _probe_fuobjectarray_candidate_bytes(
                    data[base_rel : base_rel + FUOBJECTARRAY_SEARCH_BYTES],
                    base_addr=base_addr,
                    module_base=module_base,
                    module_end=module_end,
                )
                if probe is None:
                    continue

                shape_key = (
                    probe["objects_ptr"],
                    probe["max_elements"],
                    probe["num_elements"],
                    probe["max_chunks"],
                    probe["num_chunks"],
                )
                current = candidates.get(shape_key)
                if current is None:
                    candidates[shape_key] = probe
                    continue
                if probe["score"] > current["score"]:
                    candidates[shape_key] = probe
                    continue
                if (
                    probe["score"] == current["score"]
                    and probe["base_addr"] < current["base_addr"]
                ):
                    candidates[shape_key] = probe

    ordered = sorted(
        candidates.values(),
        key=lambda item: (
            item["score"],
            item["num_elements"],
            item["objects_off"],
            -item["base_addr"],
        ),
        reverse=True,
    )
    return ordered[:FUOBJECTARRAY_CANDIDATE_LIMIT]

UOBJECT_VTABLE = 0x00
UOBJECT_FLAGS = 0x08
UOBJECT_INDEX = 0x0C
UOBJECT_CLASS = 0x10
UOBJECT_NAME = 0x18
UOBJECT_OUTER = 0x20

FUOBJECTARRAY_OBJECTS_OFFSET = 0x00
FUOBJECTARRAY_NUMELEMENTS_CANDIDATES = [0x14, 0x0C, 0x18, 0x08, 0x10]

GOBJECTS_BRUTE_MIN_OBJECT_COUNT = 1000
_gobjects_brute_cache: Dict[int, Tuple[int, int]] = {}

def _read_gobject_item_object_ptr(
    handle: int,
    objects_ptr: int,
    index: int,
    item_size: int,
    objects_mode: str,
) -> int:
    if not objects_ptr:
        return 0
    if objects_mode == "direct":
        return read_uint64(handle, objects_ptr + index * item_size)

    chunk_idx = index // OBJECTS_PER_CHUNK
    within_idx = index % OBJECTS_PER_CHUNK
    chunk_base = read_uint64(handle, objects_ptr + chunk_idx * 8)
    if not chunk_base:
        return 0
    return read_uint64(handle, chunk_base + within_idx * item_size)

def _gobject_item_object_ptr(
    handle: int,
    gobjects_ptr: int,
    index: int,
    item_size: int,
) -> int:
    objects_ptr = get_gobjects_objects_ptr(handle, gobjects_ptr)
    return _read_gobject_item_object_ptr(
        handle,
        objects_ptr,
        index,
        item_size,
        get_gobjects_objects_mode(gobjects_ptr),
    )

def probe_gobjects_item_size(handle: int, gobjects_ptr: int) -> int:
    best_size = 0
    best_valid = -1
    best_mode = "chunked"
    objects_ptr = get_gobjects_objects_ptr(handle, gobjects_ptr)
    if not objects_ptr:
        return 0

    for objects_mode in ("chunked", "direct"):
        for item_size in (
            FUOBJECTITEM_SIZE_NORMAL,
            FUOBJECTITEM_SIZE_STATS,
            FUOBJECTITEM_SIZE_UE5,
            FUOBJECTITEM_SIZE_LEGACY,
        ):
            valid = 0
            for i in range(10):
                obj_ptr = _read_gobject_item_object_ptr(
                    handle, objects_ptr, i, item_size, objects_mode
                )
                if not obj_ptr or not _plausible_ue_ptr64(obj_ptr):
                    continue
                vtable = read_uint64(handle, obj_ptr + UOBJECT_VTABLE)
                if _plausible_ue_ptr64(vtable):
                    valid += 1
            if valid > best_valid:
                best_valid = valid
                best_size = item_size
                best_mode = objects_mode
    if best_valid <= 3:
        return 0
    _gobjects_objects_mode[gobjects_ptr] = best_mode
    return best_size

def find_gobjects_brute(handle: int, base: int, size: int) -> Tuple[int, int]:
    if base in _gobjects_brute_cache:
        return _gobjects_brute_cache[base]

    ranges = get_pe_rdata_data_scan_ranges(handle, base)
    if not ranges:
        _gobjects_brute_cache[base] = (0, 0)
        return 0, 0

    from src.core.debug import dbg
    from src.core.memory import (
        USE_DRIVER,
        snapshot_mark,
        snapshot_memory_ranges,
        snapshot_restore_mark,
    )

    global _gobjects_brute_last_meta
    _gobjects_brute_last_meta = {
        "timed_out": 0,
        "candidate_count": 0,
        "stage2_count": 0,
        "stage2_validation_count": 0,
        "stage2_chunked_count": 0,
        "stage2_direct_count": 0,
        "scored_count": 0,
        "heap_slot_count": 0,
        "heap_unique_pointer_count": 0,
        "heap_shape_count": 0,
        "heap_stage2_count": 0,
        "heap_stage2_validation_count": 0,
        "heap_scored_count": 0,
        "heap_best_valid": 0,
        "heap_best_index_equal": 0,
        "heap_best_index_near": 0,
        "heap_timed_out": 0,
        "candidate_cap_hit": 0,
        "tolerant_requested": 1,
        "tolerant_supported": 0,
    }

    tolerant_supported = False
    if USE_DRIVER:
        from src.core.driver import supports_tolerant_bulk_read

        tolerant_supported = supports_tolerant_bulk_read()
        _gobjects_brute_last_meta["tolerant_supported"] = 1 if tolerant_supported else 0

    dbg("find_gobjects_brute: %d scan ranges from PE sections", len(ranges))
    for sec_start, sec_end in ranges:
        dbg(
            "  section 0x%X..0x%X (%d KB)",
            sec_start,
            sec_end,
            (sec_end - sec_start) // 1024,
        )
    if USE_DRIVER:
        dbg(
            "find_gobjects_brute: tolerant bulk scan path %s",
            "ENABLED"
            if tolerant_supported
            else "UNAVAILABLE (old driver fallback to strict reads)",
        )

    snap_mark = snapshot_mark()
    try:
        stats = snapshot_memory_ranges(handle, ranges, tolerant=True)
        for stat in stats:
            dbg(
                "find_gobjects_brute: section 0x%X read OK (%d KB, %d%% non-zero, %s)",
                stat["start"],
                stat["size"] // 1024,
                stat["nonzero_pct"],
                "tolerant" if stat.get("tolerant") else "strict-fallback",
            )
        result = _find_gobjects_brute_inner_buffered(handle, base, size, ranges)
    finally:
        snapshot_restore_mark(snap_mark)

    _gobjects_brute_cache[base] = result
    return result

def _find_gobjects_brute_inner(handle, base, size, ranges):
    from src.core.debug import dbg

    best_key: Optional[Tuple[int, int, int, int]] = None
    best_pair: Optional[Tuple[int, int]] = None
    t0 = _time.monotonic()
    candidates_checked = 0
    consecutive_read_fails = 0
    MAX_CONSECUTIVE_FAILS = 200
    module_end = base + size

    for start, end in ranges:
        addr = start
        if addr % 8:
            addr += 8 - (addr % 8)
        _timed_out = False
        while addr < end:
            candidates_checked += 1
            if (candidates_checked & 0x3F) == 0:
                elapsed = _time.monotonic() - t0
                if elapsed > BRUTE_TIMEOUT:
                    dbg(
                        "_find_gobjects_brute_inner: TIMEOUT after %.1fs "
                        "(%d candidates checked)",
                        elapsed,
                        candidates_checked,
                    )
                    _timed_out = True
                    break

            ok_chunks, chunks_ptr = _try_read_qword(handle, addr)
            if not ok_chunks:
                addr += 8
                continue
            if not _plausible_ue_ptr64(chunks_ptr):
                addr += 8
                continue
            ok_chunk0, chunk0 = _try_read_qword(handle, chunks_ptr)
            if not ok_chunk0:
                consecutive_read_fails += 1
                if consecutive_read_fails >= MAX_CONSECUTIVE_FAILS:
                    dbg(
                        "_find_gobjects_brute_inner: %d consecutive read "
                        "failures, skipping rest of section",
                        consecutive_read_fails,
                    )
                    break
                addr += 8
                continue
            consecutive_read_fails = 0
            if not _plausible_runtime_heap_ptr(chunk0, base, module_end):
                addr += 8
                continue

            shape = _probe_fuobjectarray_shape(handle, addr)
            if shape is None:
                addr += 8
                continue

            if shape["num_chunks"] > 1 and shape["num_elements"] > OBJECTS_PER_CHUNK:
                ok_chunk1, chunk1 = _try_read_qword(handle, chunks_ptr + 8)
                if not ok_chunk1 or not _plausible_runtime_heap_ptr(
                    chunk1, base, module_end
                ):
                    addr += 8
                    continue

            for stride in (
                FUOBJECTITEM_SIZE_NORMAL,
                FUOBJECTITEM_SIZE_STATS,
                FUOBJECTITEM_SIZE_UE5,
                FUOBJECTITEM_SIZE_LEGACY,
            ):
                valid = 0
                readable_slots = 0
                for slot in range(8):
                    ok_obj, obj_ptr = _try_read_qword(handle, chunk0 + slot * stride)
                    if not ok_obj:
                        continue
                    readable_slots += 1
                    if not _plausible_runtime_heap_ptr(obj_ptr, base, module_end):
                        continue
                    ok_vtable, vtable = _try_read_qword(
                        handle, obj_ptr + UOBJECT_VTABLE
                    )
                    if ok_vtable and _plausible_module_ptr(vtable, base, module_end):
                        valid += 1
                if readable_slots < 4:
                    continue
                if valid < 6:
                    continue

                obj_count = shape["num_elements"]
                if obj_count < GOBJECTS_BRUTE_MIN_OBJECT_COUNT:
                    logger.debug(
                        f"GObjects brute rejected 0x{addr:X} — object count too low ({obj_count})"
                    )
                    continue

                key = (obj_count, valid, -stride, addr)
                if best_key is None or key > best_key:
                    best_key = key
                    best_pair = (addr, stride)
            addr += 8

        if _timed_out:
            break

    elapsed = _time.monotonic() - t0
    if best_pair is None:
        dbg(
            "_find_gobjects_brute_inner: no valid GObjects found "
            "(%.1fs, %d candidates)",
            elapsed,
            candidates_checked,
        )
        return 0, 0

    oc, vv, _, winner_addr = best_key
    winner_stride = best_pair[1]
    dbg(
        "_find_gobjects_brute_inner: found 0x%X stride=%d valid=%d/8 "
        "count=%d (%.1fs, %d candidates)",
        winner_addr,
        winner_stride,
        vv,
        oc,
        elapsed,
        candidates_checked,
    )
    return best_pair

def _find_gobjects_brute_inner_buffered(handle, base, size, ranges):
    from src.core.debug import dbg
    from src.core.memory import prefetch_memory_pages

    global _gobjects_brute_last_meta
    t0 = _time.monotonic()
    module_end = base + size
    deadline = t0 + BRUTE_TIMEOUT

    candidates = _enumerate_fuobjectarray_candidates(
        handle, ranges, base, module_end, deadline
    )
    _gobjects_brute_last_meta["candidate_count"] = len(candidates)
    _gobjects_brute_last_meta["candidate_cap_hit"] = (
        1 if len(candidates) >= FUOBJECTARRAY_CANDIDATE_LIMIT else 0
    )
    if _time.monotonic() > deadline:
        _gobjects_brute_last_meta["timed_out"] = 1
        elapsed = _time.monotonic() - t0
        dbg(
            "_find_gobjects_brute_inner: TIMEOUT after %.1fs (%d candidates checked)",
            elapsed,
            len(candidates),
        )
        return 0, 0

    dbg("_find_gobjects_brute_inner: %d local structural candidates", len(candidates))
    if not candidates:
        heap_result = _find_gobjects_heap_pointer_buffered(
            handle,
            base,
            size,
            ranges,
            deadline,
        )
        if heap_result[0]:
            return heap_result
        elapsed = _time.monotonic() - t0
        dbg(
            "_find_gobjects_brute_inner: no valid GObjects found (%.1fs, 0 candidates)",
            elapsed,
        )
        return 0, 0

    if len(candidates) >= FUOBJECTARRAY_CANDIDATE_LIMIT:
        dbg(
            "_find_gobjects_brute_inner: candidate cap reached (%d); validation may not cover the full section",
            FUOBJECTARRAY_CANDIDATE_LIMIT,
        )

    object_source_pages: List[int] = []
    for candidate in candidates:
        object_source_pages.append(_page_align(candidate["objects_ptr"]))
        if candidate["num_chunks"] > 1:
            object_source_pages.append(_page_align(candidate["objects_ptr"] + 8))
    prefetch_memory_pages(handle, object_source_pages, tolerant=True)

    stage2: List[Dict[str, int]] = []
    for candidate in candidates:
        if _time.monotonic() > deadline:
            break

        ok_chunk0, chunk0 = _try_read_qword(handle, candidate["objects_ptr"])
        if ok_chunk0 and _plausible_runtime_heap_ptr(chunk0, base, module_end):
            chunked_candidate = dict(candidate)
            chunked_candidate["item_base"] = chunk0
            chunked_candidate["objects_mode"] = "chunked"
            if (
                chunked_candidate["num_chunks"] > 1
                and chunked_candidate["num_elements"] > OBJECTS_PER_CHUNK
            ):
                ok_chunk1, chunk1 = _try_read_qword(
                    handle, chunked_candidate["objects_ptr"] + 8
                )
                if ok_chunk1 and _plausible_runtime_heap_ptr(
                    chunk1, base, module_end
                ):
                    chunked_candidate["chunk1"] = chunk1
                    stage2.append(chunked_candidate)
            else:
                stage2.append(chunked_candidate)

        if _plausible_runtime_heap_ptr(candidate["objects_ptr"], base, module_end):
            direct_candidate = dict(candidate)
            direct_candidate["item_base"] = candidate["objects_ptr"]
            direct_candidate["objects_mode"] = "direct"
            stage2.append(direct_candidate)

    if not stage2:
        heap_result = _find_gobjects_heap_pointer_buffered(
            handle,
            base,
            size,
            ranges,
            deadline,
        )
        if heap_result[0]:
            return heap_result
        elapsed = _time.monotonic() - t0
        dbg(
            "_find_gobjects_brute_inner: no valid GObjects found (%.1fs, %d candidates)",
            elapsed,
            len(candidates),
        )
        return 0, 0
    _gobjects_brute_last_meta["stage2_count"] = len(stage2)
    _gobjects_brute_last_meta["stage2_chunked_count"] = sum(
        1 for candidate in stage2 if candidate["objects_mode"] == "chunked"
    )
    _gobjects_brute_last_meta["stage2_direct_count"] = sum(
        1 for candidate in stage2 if candidate["objects_mode"] == "direct"
    )
    stage2 = stage2[:FUOBJECTARRAY_STAGE2_LIMIT]
    _gobjects_brute_last_meta["stage2_validation_count"] = len(stage2)

    item_pages: List[int] = []
    for candidate in stage2:
        item_pages.append(_page_align(candidate["item_base"]))
        if "chunk1" in candidate:
            item_pages.append(_page_align(candidate["chunk1"]))
        if len(item_pages) >= FUOBJECTARRAY_PREFETCH_PAGE_LIMIT:
            break
    prefetch_memory_pages(
        handle,
        item_pages[:FUOBJECTARRAY_PREFETCH_PAGE_LIMIT],
        tolerant=True,
    )

    object_pages: List[int] = []
    for candidate in stage2:
        for stride in (
            FUOBJECTITEM_SIZE_NORMAL,
            FUOBJECTITEM_SIZE_STATS,
            FUOBJECTITEM_SIZE_UE5,
            FUOBJECTITEM_SIZE_LEGACY,
        ):
            for slot in range(FUOBJECTARRAY_SAMPLE_SLOTS):
                ok_obj, obj_ptr = _try_read_qword(
                    handle, candidate["item_base"] + slot * stride
                )
                if ok_obj and _plausible_runtime_heap_ptr(obj_ptr, base, module_end):
                    object_pages.append(_page_align(obj_ptr))
                    if len(object_pages) >= FUOBJECTARRAY_PREFETCH_PAGE_LIMIT:
                        break
            if len(object_pages) >= FUOBJECTARRAY_PREFETCH_PAGE_LIMIT:
                break
        if len(object_pages) >= FUOBJECTARRAY_PREFETCH_PAGE_LIMIT:
            break
    prefetch_memory_pages(
        handle,
        object_pages[:FUOBJECTARRAY_PREFETCH_PAGE_LIMIT],
        tolerant=True,
    )

    best_entry: Optional[Dict[str, int]] = None
    scored_count = 0
    for candidate in stage2:
        if _time.monotonic() > deadline:
            _gobjects_brute_last_meta["timed_out"] = 1
            break
        for stride in (
            FUOBJECTITEM_SIZE_NORMAL,
            FUOBJECTITEM_SIZE_STATS,
            FUOBJECTITEM_SIZE_UE5,
            FUOBJECTITEM_SIZE_LEGACY,
        ):
            valid = 0
            readable_slots = 0
            classish = 0
            nameish = 0
            indexish = 0

            for slot in range(FUOBJECTARRAY_SAMPLE_SLOTS):
                ok_obj, obj_ptr = _try_read_qword(
                    handle, candidate["item_base"] + slot * stride
                )
                if not ok_obj:
                    continue
                readable_slots += 1
                if not _plausible_runtime_heap_ptr(obj_ptr, base, module_end):
                    continue

                ok_vtable, vtable = _try_read_qword(handle, obj_ptr + UOBJECT_VTABLE)
                if ok_vtable and _plausible_module_ptr(vtable, base, module_end):
                    valid += 1

                ok_class, class_ptr = _try_read_qword(handle, obj_ptr + UOBJECT_CLASS)
                if ok_class and _plausible_runtime_heap_ptr(
                    class_ptr, base, module_end
                ):
                    classish += 1

                name_idx = read_int32(handle, obj_ptr + UOBJECT_NAME)
                if 0 <= name_idx <= 20_000_000:
                    nameish += 1

                internal_idx = read_int32(handle, obj_ptr + UOBJECT_INDEX)
                if -1 <= internal_idx <= candidate["num_elements"] + 0x1000:
                    indexish += 1

            if readable_slots < 6 or valid < 6:
                continue

            scored_count += 1
            entry = {
                "addr": candidate["base_addr"],
                "stride": stride,
                "objects_off": candidate["objects_off"],
                "objects_mode": candidate["objects_mode"],
                "score": candidate["score"] * 8
                + valid * 10
                + classish * 4
                + nameish * 3
                + indexish * 2,
                "valid": valid,
                "num_elements": candidate["num_elements"],
            }
            if best_entry is None or (
                entry["score"],
                entry["num_elements"],
                entry["valid"],
                -entry["stride"],
                -entry["addr"],
            ) > (
                best_entry["score"],
                best_entry["num_elements"],
                best_entry["valid"],
                -best_entry["stride"],
                -best_entry["addr"],
            ):
                best_entry = entry
    _gobjects_brute_last_meta["scored_count"] = scored_count

    elapsed = _time.monotonic() - t0
    if best_entry is None:
        heap_result = _find_gobjects_heap_pointer_buffered(
            handle,
            base,
            size,
            ranges,
            deadline,
        )
        if heap_result[0]:
            return heap_result
        dbg(
            "_find_gobjects_brute_inner: no valid GObjects found (%.1fs, %d candidates)",
            elapsed,
            len(candidates),
        )
        return 0, 0

    dbg(
        "_find_gobjects_brute_inner: found 0x%X stride=%d mode=%s valid=%d/%d count=%d (%.1fs, %d candidates)",
        best_entry["addr"],
        best_entry["stride"],
        best_entry["objects_mode"],
        best_entry["valid"],
        FUOBJECTARRAY_SAMPLE_SLOTS,
        best_entry["num_elements"],
        elapsed,
        len(candidates),
    )
    _gobjects_objects_offset[best_entry["addr"]] = best_entry["objects_off"]
    _gobjects_objects_mode[best_entry["addr"]] = best_entry["objects_mode"]
    return best_entry["addr"], best_entry["stride"]

def _sample_gobject_slots(num_elements: int) -> List[int]:
    upper = max(0, min(num_elements, 4096))
    if upper <= 0:
        return []

    slots = set(range(min(16, upper)))
    if upper > 16:
        remaining = max(1, FUOBJECTARRAY_HEAP_SAMPLE_MAX - len(slots))
        step = max(1, upper // remaining)
        for slot in range(0, upper, step):
            slots.add(slot)
            if len(slots) >= FUOBJECTARRAY_HEAP_SAMPLE_MAX:
                break
    return sorted(slots)

def _heap_shape_key(candidate: Dict[str, int]) -> Tuple[int, int, int, int, int]:
    return (
        candidate["base_addr"],
        candidate["objects_ptr"],
        candidate["num_elements"],
        candidate["num_chunks"],
        candidate["objects_off"],
    )

def _find_gobjects_heap_pointer_buffered(
    handle: int,
    base: int,
    size: int,
    ranges: List[Tuple[int, int]],
    deadline: float,
) -> Tuple[int, int]:
    from src.core.debug import dbg
    from src.core.memory import prefetch_memory_pages, scatter_read_multiple

    global _gobjects_brute_last_meta

    module_end = base + size
    heap_slots: Dict[int, int] = {}
    heap_slot_count = 0

    for start, end in ranges:
        if _time.monotonic() > deadline:
            _gobjects_brute_last_meta["heap_timed_out"] = 1
            break
        data = read_bytes(handle, start, end - start)
        if len(data) < 8:
            continue

        usable = len(data) - 7
        for off in range(0, usable, 8):
            if (off & 0x3FF) == 0 and _time.monotonic() > deadline:
                _gobjects_brute_last_meta["heap_timed_out"] = 1
                break
            value = struct.unpack_from("<Q", data, off)[0]
            if not _plausible_runtime_heap_ptr(value, base, module_end):
                continue
            if value & 0x7:
                continue
            heap_slot_count += 1
            heap_slots.setdefault(value, start + off)
            if len(heap_slots) >= FUOBJECTARRAY_HEAP_POINTER_LIMIT:
                break
        if len(heap_slots) >= FUOBJECTARRAY_HEAP_POINTER_LIMIT:
            break

    _gobjects_brute_last_meta["heap_slot_count"] = heap_slot_count
    _gobjects_brute_last_meta["heap_unique_pointer_count"] = len(heap_slots)
    if not heap_slots or _time.monotonic() > deadline:
        return 0, 0

    dbg(
        "_find_gobjects_heap_pointer: %d heap-like module pointer slot(s), %d unique target(s)",
        heap_slot_count,
        len(heap_slots),
    )

    heap_candidates: Dict[Tuple[int, int, int, int, int], Dict[str, int]] = {}
    ptr_items = list(heap_slots.items())[:FUOBJECTARRAY_HEAP_POINTER_LIMIT]
    batch_size = 512
    for batch_start in range(0, len(ptr_items), batch_size):
        if _time.monotonic() > deadline:
            _gobjects_brute_last_meta["heap_timed_out"] = 1
            break
        batch = ptr_items[batch_start : batch_start + batch_size]
        blobs = scatter_read_multiple(
            handle,
            [(ptr, FUOBJECTARRAY_SEARCH_BYTES) for ptr, _slot in batch],
        )
        for (ptr, slot_addr), raw in zip(batch, blobs):
            if len(raw) < 0x20:
                continue
            shape = _probe_fuobjectarray_candidate_bytes(
                raw,
                base_addr=ptr,
                module_base=base,
                module_end=module_end,
            )
            if shape is None:
                continue
            shape["global_slot"] = slot_addr
            key = _heap_shape_key(shape)
            current = heap_candidates.get(key)
            if current is None or shape["score"] > current["score"]:
                heap_candidates[key] = shape

    candidates = sorted(
        heap_candidates.values(),
        key=lambda item: (
            item["score"],
            item["num_elements"],
            -abs(item["base_addr"] - item["global_slot"]),
        ),
        reverse=True,
    )[:FUOBJECTARRAY_HEAP_SHAPE_LIMIT]
    _gobjects_brute_last_meta["heap_shape_count"] = len(candidates)
    if not candidates or _time.monotonic() > deadline:
        return 0, 0

    prefetch_memory_pages(
        handle,
        [_page_align(candidate["objects_ptr"]) for candidate in candidates],
        tolerant=True,
    )

    stage2: List[Dict[str, int]] = []
    for candidate in candidates:
        if _time.monotonic() > deadline:
            _gobjects_brute_last_meta["heap_timed_out"] = 1
            break

        ok_chunk0, chunk0 = _try_read_qword(handle, candidate["objects_ptr"])
        if ok_chunk0 and _plausible_runtime_heap_ptr(chunk0, base, module_end):
            chunked_candidate = dict(candidate)
            chunked_candidate["item_base"] = chunk0
            chunked_candidate["objects_mode"] = "chunked"
            if (
                chunked_candidate["num_chunks"] > 1
                and chunked_candidate["num_elements"] > OBJECTS_PER_CHUNK
            ):
                ok_chunk1, chunk1 = _try_read_qword(
                    handle,
                    chunked_candidate["objects_ptr"] + 8,
                )
                if ok_chunk1 and _plausible_runtime_heap_ptr(
                    chunk1,
                    base,
                    module_end,
                ):
                    chunked_candidate["chunk1"] = chunk1
                    stage2.append(chunked_candidate)
            else:
                stage2.append(chunked_candidate)

        if _plausible_runtime_heap_ptr(candidate["objects_ptr"], base, module_end):
            direct_candidate = dict(candidate)
            direct_candidate["item_base"] = candidate["objects_ptr"]
            direct_candidate["objects_mode"] = "direct"
            stage2.append(direct_candidate)

    _gobjects_brute_last_meta["heap_stage2_count"] = len(stage2)
    if not stage2:
        return 0, 0
    stage2 = stage2[:FUOBJECTARRAY_STAGE2_LIMIT]
    _gobjects_brute_last_meta["heap_stage2_validation_count"] = len(stage2)

    item_pages: List[int] = []
    for candidate in stage2:
        item_pages.append(_page_align(candidate["item_base"]))
        if "chunk1" in candidate:
            item_pages.append(_page_align(candidate["chunk1"]))
        if len(item_pages) >= FUOBJECTARRAY_PREFETCH_PAGE_LIMIT:
            break
    prefetch_memory_pages(
        handle,
        item_pages[:FUOBJECTARRAY_PREFETCH_PAGE_LIMIT],
        tolerant=True,
    )

    object_pages: List[int] = []
    for candidate in stage2:
        sample_slots = _sample_gobject_slots(candidate["num_elements"])
        for stride in (
            FUOBJECTITEM_SIZE_NORMAL,
            FUOBJECTITEM_SIZE_STATS,
            FUOBJECTITEM_SIZE_UE5,
            FUOBJECTITEM_SIZE_LEGACY,
        ):
            for slot in sample_slots:
                ok_obj, obj_ptr = _try_read_qword(
                    handle,
                    candidate["item_base"] + slot * stride,
                )
                if ok_obj and _plausible_runtime_heap_ptr(obj_ptr, base, module_end):
                    object_pages.append(_page_align(obj_ptr))
                    if len(object_pages) >= FUOBJECTARRAY_PREFETCH_PAGE_LIMIT:
                        break
            if len(object_pages) >= FUOBJECTARRAY_PREFETCH_PAGE_LIMIT:
                break
        if len(object_pages) >= FUOBJECTARRAY_PREFETCH_PAGE_LIMIT:
            break
    prefetch_memory_pages(handle, object_pages, tolerant=True)

    best_entry: Optional[Dict[str, int]] = None
    scored_count = 0
    for candidate in stage2:
        if _time.monotonic() > deadline:
            _gobjects_brute_last_meta["heap_timed_out"] = 1
            break

        sample_slots = _sample_gobject_slots(candidate["num_elements"])
        if len(sample_slots) < 8:
            continue

        for stride in (
            FUOBJECTITEM_SIZE_NORMAL,
            FUOBJECTITEM_SIZE_STATS,
            FUOBJECTITEM_SIZE_UE5,
            FUOBJECTITEM_SIZE_LEGACY,
        ):
            readable_slots = 0
            pointerish = 0
            valid_vtable = 0
            classish = 0
            nameish = 0
            indexish = 0
            index_equal = 0
            index_near = 0

            for slot in sample_slots:
                ok_obj, obj_ptr = _try_read_qword(
                    handle,
                    candidate["item_base"] + slot * stride,
                )
                if not ok_obj:
                    continue
                readable_slots += 1
                if not _plausible_runtime_heap_ptr(obj_ptr, base, module_end):
                    continue
                pointerish += 1

                ok_vtable, vtable = _try_read_qword(handle, obj_ptr + UOBJECT_VTABLE)
                if ok_vtable and _plausible_module_ptr(vtable, base, module_end):
                    valid_vtable += 1

                ok_class, class_ptr = _try_read_qword(handle, obj_ptr + UOBJECT_CLASS)
                if ok_class and _plausible_runtime_heap_ptr(
                    class_ptr,
                    base,
                    module_end,
                ):
                    classish += 1

                name_idx = read_int32(handle, obj_ptr + UOBJECT_NAME)
                if 0 <= name_idx <= 20_000_000:
                    nameish += 1

                internal_idx = read_int32(handle, obj_ptr + UOBJECT_INDEX)
                if -1 <= internal_idx <= candidate["num_elements"] + 0x1000:
                    indexish += 1
                if internal_idx == slot:
                    index_equal += 1
                elif abs(internal_idx - slot) <= 2:
                    index_near += 1

            if readable_slots < 8 or pointerish < 8 or valid_vtable < 8:
                continue

            scored_count += 1
            if (
                classish < 6
                or nameish < 6
                or indexish < 6
                or (index_equal < 4 and index_near < 8)
            ):
                rejected_key = (
                    valid_vtable,
                    index_equal,
                    index_near,
                    pointerish,
                )
                current_key = (
                    _gobjects_brute_last_meta.get("heap_best_valid", 0),
                    _gobjects_brute_last_meta.get("heap_best_index_equal", 0),
                    _gobjects_brute_last_meta.get("heap_best_index_near", 0),
                    0,
                )
                if rejected_key > current_key:
                    _gobjects_brute_last_meta["heap_best_valid"] = valid_vtable
                    _gobjects_brute_last_meta["heap_best_index_equal"] = index_equal
                    _gobjects_brute_last_meta["heap_best_index_near"] = index_near
                    _gobjects_brute_last_meta["heap_best_slot_rva"] = (
                        candidate["global_slot"] - base
                    )
                    _gobjects_brute_last_meta["heap_best_addr"] = candidate["base_addr"]
                continue

            entry = {
                "addr": candidate["base_addr"],
                "global_slot": candidate["global_slot"],
                "stride": stride,
                "objects_off": candidate["objects_off"],
                "objects_mode": candidate["objects_mode"],
                "score": candidate["score"] * 8
                + valid_vtable * 12
                + classish * 4
                + nameish * 3
                + indexish * 3
                + index_equal * 20
                + index_near * 10,
                "valid": valid_vtable,
                "index_equal": index_equal,
                "index_near": index_near,
                "num_elements": candidate["num_elements"],
            }
            if best_entry is None or (
                entry["score"],
                entry["index_equal"],
                entry["index_near"],
                entry["valid"],
                entry["num_elements"],
                -entry["stride"],
            ) > (
                best_entry["score"],
                best_entry["index_equal"],
                best_entry["index_near"],
                best_entry["valid"],
                best_entry["num_elements"],
                -best_entry["stride"],
            ):
                best_entry = entry

    _gobjects_brute_last_meta["heap_scored_count"] = scored_count
    if best_entry is None:
        dbg(
            "_find_gobjects_heap_pointer: no valid heap-backed GUObjectArray "
            "(%d shape(s), %d stage2, %d scored, best valid=%d eq=%d near=%d)",
            len(candidates),
            len(stage2),
            scored_count,
            _gobjects_brute_last_meta.get("heap_best_valid", 0),
            _gobjects_brute_last_meta.get("heap_best_index_equal", 0),
            _gobjects_brute_last_meta.get("heap_best_index_near", 0),
        )
        return 0, 0

    _gobjects_objects_offset[best_entry["addr"]] = best_entry["objects_off"]
    _gobjects_objects_mode[best_entry["addr"]] = best_entry["objects_mode"]
    _gobjects_brute_last_meta["heap_best_valid"] = best_entry["valid"]
    _gobjects_brute_last_meta["heap_best_index_equal"] = best_entry["index_equal"]
    _gobjects_brute_last_meta["heap_best_index_near"] = best_entry["index_near"]
    _gobjects_brute_last_meta["heap_best_slot_rva"] = (
        best_entry["global_slot"] - base
    )
    _gobjects_brute_last_meta["heap_best_addr"] = best_entry["addr"]
    dbg(
        "_find_gobjects_heap_pointer: found heap GUObjectArray 0x%X via slot +0x%X "
        "stride=%d mode=%s valid=%d eq=%d near=%d count=%d",
        best_entry["addr"],
        best_entry["global_slot"] - base,
        best_entry["stride"],
        best_entry["objects_mode"],
        best_entry["valid"],
        best_entry["index_equal"],
        best_entry["index_near"],
        best_entry["num_elements"],
    )
    return best_entry["addr"], best_entry["stride"]

def _looks_coherent_gobject_class_name(name: str) -> bool:
    if not name or len(name) > 96:
        return False
    if name in _KNOWN_GOBJECT_CLASS_NAMES:
        return True
    return any(
        name.endswith(suffix)
        for suffix in ("Class", "Struct", "Function", "Property", "Package", "World")
    )

def find_gobjects_names_seeded(
    handle: int,
    module_base: int,
    module_size: int,
    gnames_ptr: int,
    *,
    ue_version: str = "4.27",
    case_preserving: Optional[bool] = None,
    legacy_names: bool = False,
) -> Tuple[int, int]:
    _gobjects_names_seeded_last_meta.clear()
    _gobjects_names_seeded_last_meta.update(
        {
            "candidate_count": 0,
            "checked_count": 0,
            "stride_rejected": 0,
            "validation_rejected": 0,
            "timed_out": 0,
            "accepted": 0,
        }
    )
    if not gnames_ptr:
        return 0, 0

    ranges = get_pe_rdata_data_scan_ranges(handle, module_base)
    if not ranges:
        return 0, 0

    from src.core.memory import (
        snapshot_mark,
        snapshot_memory_ranges,
        snapshot_restore_mark,
    )

    deadline = _time.monotonic() + min(BRUTE_TIMEOUT, 20.0)
    best_entry: Optional[Dict[str, int]] = None
    snap_mark = snapshot_mark()
    try:
        snapshot_memory_ranges(handle, ranges, tolerant=True)
        candidates = _enumerate_fuobjectarray_candidates(
            handle,
            ranges,
            module_base,
            module_base + module_size,
            deadline,
        )
        _gobjects_names_seeded_last_meta["candidate_count"] = len(candidates)
        for candidate in candidates[:256]:
            if _time.monotonic() > deadline:
                _gobjects_names_seeded_last_meta["timed_out"] = 1
                break
            _gobjects_names_seeded_last_meta["checked_count"] += 1
            addr = candidate["base_addr"]
            _gobjects_objects_offset[addr] = candidate["objects_off"]
            item_size = probe_gobjects_item_size(handle, addr)
            if not item_size:
                _gobjects_names_seeded_last_meta["stride_rejected"] += 1
                continue
            if not validate_gobjects(
                handle,
                addr,
                gnames_ptr=gnames_ptr,
                ue_version=ue_version,
                case_preserving=case_preserving,
                item_size=item_size,
                legacy_names=legacy_names,
            ):
                _gobjects_names_seeded_last_meta["validation_rejected"] += 1
                continue

            entry = {
                "addr": addr,
                "stride": item_size,
                "score": candidate["score"],
                "objects_off": candidate["objects_off"],
            }
            if best_entry is None or (
                entry["score"],
                -entry["stride"],
                -entry["addr"],
            ) > (
                best_entry["score"],
                -best_entry["stride"],
                -best_entry["addr"],
            ):
                best_entry = entry
    finally:
        snapshot_restore_mark(snap_mark)

    if best_entry is None:
        return 0, 0

    _gobjects_objects_offset[best_entry["addr"]] = best_entry["objects_off"]
    _gobjects_names_seeded_last_meta["accepted"] = 1
    return best_entry["addr"], best_entry["stride"]

def _recover_gobjects_with_names(
    handle: int,
    module_base: int,
    module_size: int,
    ue_version: str,
    process_name: Optional[str],
    diag,
    *,
    gnames_ptr: int,
    case_preserving: Optional[bool],
    legacy_names: bool,
) -> Tuple[int, int]:
    fallback_gnames = gnames_ptr
    fallback_cp = case_preserving
    fallback_legacy = legacy_names
    names_meta = _gobjects_resolution_meta.setdefault("names_seeded", {})
    names_meta.update(
        {
            "attempted": True,
            "source": "provided" if fallback_gnames else "recovered",
            "gnames_recovered": bool(fallback_gnames),
            "succeeded": False,
        }
    )

    if not fallback_gnames:
        names_meta["scan"] = {}
        names_meta["failure_kind"] = "gnames_unavailable"
        if diag:
            diag.tried(
                "GObjects",
                "names_seeded_recovery",
                "GNames not provided; skipping slow names-first recovery during GObjects",
            )
        return 0, 0

    if diag:
        method = names_meta.get("gnames_method") or names_meta.get("source")
        diag.tried(
            "GObjects",
            "names_seeded_recovery",
            f"Scoring structural candidates with GNames ({method})",
        )

    names_seeded = find_gobjects_names_seeded(
        handle,
        module_base,
        module_size,
        fallback_gnames,
        ue_version=ue_version,
        case_preserving=fallback_cp,
        legacy_names=fallback_legacy,
    )
    names_meta["scan"] = dict(_gobjects_names_seeded_last_meta)
    names_meta["succeeded"] = bool(names_seeded[0])
    if not names_seeded[0]:
        names_meta["failure_kind"] = "candidate_validation_rejected"
        if diag:
            checked = _gobjects_names_seeded_last_meta.get("checked_count", 0)
            diag.tried(
                "GObjects",
                "names_seeded_validation",
                f"GNames-backed scoring rejected {checked} structural candidate(s)",
            )
        return names_seeded

    if diag:
        diag.passed(
            "GObjects",
            "names_seeded_validation",
            f"Found at +0x{names_seeded[0] - module_base:X} stride={names_seeded[1]} using GNames",
        )
        diag.set_confidence(
            "GObjects",
            0.7,
            "validated structural candidate using recovered GNames",
        )
    _set_gobjects_resolution_meta(
        address=names_seeded[0],
        item_size=names_seeded[1],
        method="names_seeded_structural",
        objects_offset=get_gobjects_objects_offset(names_seeded[0]),
    )
    return names_seeded

def find_gobjects(
    handle: int,
    module_base: int,
    module_size: int,
    ue_version: str = "4.27",
    process_name: Optional[str] = None,
    diag=None,
    gnames_ptr: int = 0,
    case_preserving: Optional[bool] = None,
    legacy_names: bool = False,
) -> Tuple[int, int]:
    _start_gobjects_resolution_meta(ue_version)
    override = load_game_offsets_override(process_name)
    if override is not None:
        _ogn, ogo, _ogw, item_stride, _legacy = override
        override_addr = module_base + ogo
        _gobjects_objects_offset[override_addr] = FUOBJECTARRAY_OBJECTS_OFFSET
        if validate_gobjects(
            handle,
            override_addr,
            gnames_ptr=gnames_ptr,
            ue_version=ue_version,
            case_preserving=case_preserving,
            item_size=item_stride,
            legacy_names=legacy_names,
        ):
            _set_gobjects_resolution_meta(
                address=override_addr,
                item_size=item_stride,
                method="offsets_override",
                objects_offset=FUOBJECTARRAY_OBJECTS_OFFSET,
            )
            logger.debug(
                f"GObjects from OffsetsInfo.json: +0x{ogo:X} stride={item_stride} "
                f"(validated)"
            )
            if diag:
                diag.info(
                    f"Using validated cached offset +0x{ogo:X} from OffsetsInfo.json",
                    "GObjects",
                )
            return override_addr, item_stride

        logger.warning(
            "Cached GObjects override +0x%X failed validation; continuing with live scan",
            ogo,
        )
        _gobjects_objects_offset.pop(override_addr, None)
        if process_name:
            try:
                from src.engines.ue.offsets_override import mark_offsets_stale

                mark_offsets_stale(process_name)
            except Exception:
                pass
        if diag:
            diag.warn(
                f"Cached offset +0x{ogo:X} failed validation; rescanning live",
                "GObjects",
            )

    votes: Counter = Counter()
    sig_details = []
    signature_rejections: Counter = Counter()
    selected_signatures = sorted(
        get_gobjects_signatures(ue_version),
        key=lambda s: s.priority,
    )
    _gobjects_resolution_meta["selected_signatures"] = [
        sig.name for sig in selected_signatures
    ]

    from src.core.memory import USE_DRIVER as _USE_DRV

    _bulk_ctx = None
    if _USE_DRV:
        from src.core.driver import bulk_read_mode as _brm

        _bulk_ctx = _brm()
        _bulk_ctx.__enter__()

    import struct as _struct
    from src.core.debug import dbg

    from src.core.pe_parser import get_pe_text_scan_ranges as _get_text_ranges

    _text_ranges = _get_text_ranges(handle, module_base)
    if not _text_ranges:
        _text_ranges = [(module_base, module_base + module_size)]
    _text_ranges_capped = False
    if _USE_DRV:
        original_total = sum(end - start for start, end in _text_ranges)
        _text_ranges, _text_ranges_capped = _cap_ranges_by_total(
            _text_ranges,
            GOBJECTS_KERNEL_AOB_MAX_BYTES,
        )
        if _text_ranges_capped:
            dbg(
                "find_gobjects: kernel AOB prepass capped to %d MB of %d MB",
                GOBJECTS_KERNEL_AOB_MAX_BYTES // (1024 * 1024),
                original_total // (1024 * 1024),
            )
            if diag:
                diag.info(
                    "Kernel AOB prepass is capped; full live signature scan is skipped if no votes are found",
                    "GObjects",
                )

    _text_total = sum(end - start for start, end in _text_ranges)
    dbg(
        "find_gobjects: reading .text section 0x%X + %d MB for AOB cache (vs full %d MB)...",
        _text_ranges[0][0] if _text_ranges else module_base,
        _text_total // (1024 * 1024),
        module_size // (1024 * 1024),
    )

    _text_sections: List[Tuple[int, bytes]] = []
    if _USE_DRV:
        from src.core.driver import read_memory_kernel_tolerant as _rmk
        from src.core.memory import TARGET_PID as _TPID

        for _start, _end in _text_ranges:
            _data = _rmk(_TPID, _start, _end - _start)
            if _data:
                _text_sections.append((_start, _data))
    else:
        for _start, _end in _text_ranges:
            _data = read_bytes(handle, _start, _end - _start)
            if _data:
                _text_sections.append((_start, _data))

    module_data = b"".join(data for _, data in _text_sections)
    _first_section_base = _text_sections[0][0] if _text_sections else module_base

    _have_data = module_data and len(module_data) > 0x1000
    if _have_data:
        _sample_pages = 256
        _page_size = max(len(module_data) // _sample_pages, 1)
        _nonzero = 0
        for _si in range(_sample_pages):
            _off = _si * _page_size
            if _off + 8 <= len(module_data):
                if module_data[_off : _off + 8] != b"\x00" * 8:
                    _nonzero += 1
        _readable_pct = _nonzero * 100 // _sample_pages
        dbg("find_gobjects: module data readability: %d%% non-zero", _readable_pct)
        min_readable_pct = 30 if _USE_DRV else 5
        if _readable_pct < min_readable_pct:
            dbg(
                "find_gobjects: <%d%% readable — skipping AOB in favor of brute force",
                min_readable_pct,
            )
            _have_data = False

    if _have_data:
        from src.core.scanner import _parse_pattern, _build_prefix, _match_full

        for sig in selected_signatures:
            pat_bytes, mask = _parse_pattern(sig.pattern)
            pat_len = len(pat_bytes)
            if pat_len == 0:
                continue
            prefix = _build_prefix(pat_bytes, mask)
            hits = []
            search_end = len(module_data) - pat_len + 1
            i = 0
            while i < search_end and len(hits) < 20:
                pos = module_data.find(prefix, i, len(module_data))
                if pos == -1:
                    break
                if pos < search_end and _match_full(
                    module_data, pos, pat_bytes, mask, pat_len
                ):
                    hits.append(_first_section_base + pos)
                i = pos + 1

            resolved = []
            for hit in hits:
                local_off = hit - _first_section_base
                disp_off = local_off + sig.disp_offset
                if disp_off + 4 <= len(module_data):
                    disp = _struct.unpack_from("<i", module_data, disp_off)[0]
                    target = hit + sig.instruction_size + disp
                    if target > module_base:
                        votes[target] += 1
                        resolved.append(target)

            detail = f"{len(hits)} hit(s), {len(resolved)} resolved"
            sig_details.append((sig.name, len(hits), len(resolved)))
            _gobjects_resolution_meta["signature_details"][sig.name] = {
                "hits": len(hits),
                "resolved": len(resolved),
            }
            _gobjects_resolution_meta["signature_hit_count"] += len(hits)
            _gobjects_resolution_meta["signature_resolved_count"] += len(resolved)
            if diag:
                diag.tried("GObjects", sig.name, detail)

        dbg("find_gobjects: local AOB scan done, %d unique candidates", len(votes))
    else:
        dbg(
            "find_gobjects: module read failed/unreadable (%d bytes), skipping AOB",
            len(module_data) if module_data else 0,
        )

    module_data = None

    if _bulk_ctx is not None:
        _bulk_ctx.__exit__(None, None, None)

    if not votes and _USE_DRV and not _text_ranges_capped:
        dbg("find_gobjects: cached AOB had no votes; retrying live scan_pattern pass")
        if diag:
            diag.info(
                "Cached module AOB yielded no votes in kernel mode; retrying live pattern scan",
                "GObjects",
            )
        _fallback_bulk = None
        try:
            from src.core.driver import bulk_read_mode as _brm

            _fallback_bulk = _brm()
            _fallback_bulk.__enter__()
            for sig in selected_signatures:
                hits = scan_pattern(
                    handle,
                    module_base,
                    module_size,
                    sig.pattern,
                    max_results=20,
                )
                resolved = []
                for hit in hits:
                    target = resolve_rip(
                        handle, hit, sig.disp_offset, sig.instruction_size
                    )
                    if target is None or target <= module_base:
                        continue
                    votes[target] += 1
                    resolved.append(target)

                detail = f"{len(hits)} hit(s), {len(resolved)} resolved"
                sig_details.append((f"{sig.name}_live", len(hits), len(resolved)))
                _gobjects_resolution_meta["signature_details"][f"{sig.name}_live"] = {
                    "hits": len(hits),
                    "resolved": len(resolved),
                }
                _gobjects_resolution_meta["signature_hit_count"] += len(hits)
                _gobjects_resolution_meta["signature_resolved_count"] += len(resolved)
                if diag:
                    diag.tried("GObjects", f"{sig.name}_live", detail)
        finally:
            if _fallback_bulk is not None:
                _fallback_bulk.__exit__(None, None, None)
    elif not votes and _USE_DRV and _text_ranges_capped:
        dbg("find_gobjects: skipping full live scan_pattern pass after capped kernel AOB miss")
        if diag:
            diag.tried(
                "GObjects",
                "live_pattern_scan",
                "Skipped full .text live scan after capped kernel AOB prepass missed",
            )

    if votes:
        candidate_bases_seen = set()
        for addr, vote_count in votes.most_common():
            raw = read_bytes(handle, addr, 0x30)
            if raw and len(raw) >= 0x28:
                hexdump = " ".join(f"{b:02X}" for b in raw[:0x30])
                i32_vals = [
                    struct.unpack_from("<i", raw, o)[0] for o in range(0, 0x28, 4)
                ]
                i64_vals = [
                    struct.unpack_from("<q", raw, o)[0] for o in range(0, 0x28, 8)
                ]
                dbg("GObjects struct raw at +0x%X (%d votes):", addr, vote_count)
                dbg("  hex: %s", hexdump)
                dbg("  i32: %s", i32_vals)
                dbg("  i64: %s", i64_vals)

            candidates = _normalize_gobjects_signature_candidates(
                handle,
                addr,
                module_base,
                module_size,
            )
            _gobjects_resolution_meta["normalized_candidate_matches"] += sum(
                1 for candidate in candidates if "objects_off" in candidate
            )
            for candidate in candidates:
                candidate_addr = int(candidate["base_addr"])
                if candidate_addr in candidate_bases_seen:
                    continue
                candidate_bases_seen.add(candidate_addr)
                _gobjects_resolution_meta["normalized_candidate_attempts"] += 1

                if "objects_off" in candidate:
                    _gobjects_objects_offset[candidate_addr] = int(
                        candidate["objects_off"]
                    )
                else:
                    _gobjects_objects_offset.setdefault(
                        candidate_addr,
                        FUOBJECTARRAY_OBJECTS_OFFSET,
                    )

                item_size = probe_gobjects_item_size(handle, candidate_addr)
                candidate_detail = f"addr=+0x{candidate_addr - module_base:X}"
                if candidate_addr != addr:
                    candidate_detail += f" from hit +0x{addr - module_base:X}"
                if not item_size:
                    signature_rejections["stride_probe"] += 1
                    if diag:
                        diag.tried(
                            "GObjects",
                            "probe_item_size",
                            f"{candidate_detail} rejected (structure validation failed)",
                        )
                    continue

                is_valid = validate_gobjects(
                    handle,
                    candidate_addr,
                    gnames_ptr=gnames_ptr,
                    ue_version=ue_version,
                    case_preserving=case_preserving,
                    item_size=item_size,
                    legacy_names=legacy_names,
                )
                if is_valid:
                    if diag:
                        diag.passed(
                            "GObjects",
                            "probe_item_size",
                            f"{candidate_detail} stride={item_size} ({vote_count} votes)",
                        )
                        diag.set_confidence(
                            "GObjects",
                            min(1.0, vote_count / 3),
                            f"{vote_count} signature votes, stride={item_size}",
                        )
                    _gobjects_resolution_meta["signature_rejections"] = dict(
                        signature_rejections.most_common()
                    )
                    _set_gobjects_resolution_meta(
                        address=candidate_addr,
                        item_size=item_size,
                        method=(
                            "signature_normalized_probe"
                            if candidate_addr != addr
                            else "signature_probe"
                        ),
                        objects_offset=get_gobjects_objects_offset(candidate_addr),
                    )
                    return candidate_addr, item_size

                signature_rejections["candidate_validation"] += 1
                if diag:
                    diag.tried(
                        "GObjects",
                        "validate_candidate",
                        f"{candidate_detail} rejected after structural/name validation",
                    )

    total_hits = sum(d[1] for d in sig_details)
    _gobjects_resolution_meta["signature_failure_kind"] = (
        "signature_miss" if total_hits == 0 else "signature_validation_rejected"
    )
    _gobjects_resolution_meta["signature_rejections"] = dict(
        signature_rejections.most_common()
    )
    if diag:
        if total_hits == 0:
            diag.failed(
                "GObjects",
                "AOB signatures",
                f"0 hits across {len(selected_signatures)} patterns — "
                f"this game's code patterns don't match any known UE build",
            )
        else:
            diag.failed(
                "GObjects",
                "AOB validation",
                f"{total_hits} raw hits but none passed structure validation",
            )

    names_seeded = _recover_gobjects_with_names(
        handle,
        module_base,
        module_size,
        ue_version,
        process_name,
        diag,
        gnames_ptr=gnames_ptr,
        case_preserving=case_preserving,
        legacy_names=legacy_names,
    )
    if names_seeded[0]:
        return names_seeded

    logger.debug("GObjects names-seeded recovery failed, trying brute force...")
    if diag:
        diag.tried(
            "GObjects",
            "brute_force_scan",
            "Scanning .rdata/.data sections without name-backed validation",
        )

    result = find_gobjects_brute(handle, module_base, module_size)
    _gobjects_resolution_meta["structural"] = dict(_gobjects_brute_last_meta)
    if result[0]:
        if diag:
            if _plausible_module_ptr(result[0], module_base, module_base + module_size):
                found_detail = f"Found at +0x{result[0] - module_base:X} stride={result[1]}"
            else:
                slot_rva = _gobjects_brute_last_meta.get("heap_best_slot_rva", 0)
                found_detail = (
                    f"Found heap FUObjectArray at 0x{result[0]:X} "
                    f"via global slot +0x{slot_rva:X} stride={result[1]}"
                )
            diag.passed(
                "GObjects",
                "brute_force_scan",
                found_detail,
            )
            diag.set_confidence(
                "GObjects", 0.6, "found via brute-force (no signature match)"
            )
        _set_gobjects_resolution_meta(
            address=result[0],
            item_size=result[1],
            method=(
                "heap_pointer_structural_scan"
                if not _plausible_module_ptr(result[0], module_base, module_base + module_size)
                else "structural_scan"
            ),
            objects_offset=get_gobjects_objects_offset(result[0]),
        )
    else:
        if diag:
            if _gobjects_brute_last_meta.get("timed_out"):
                detail = "Timed out while scoring local FUObjectArray candidates"
                if _gobjects_brute_last_meta.get("candidate_cap_hit"):
                    detail += " (candidate cap reached)"
                diag.failed("GObjects", "brute_force_scan", detail)
            else:
                candidate_count = _gobjects_brute_last_meta.get("candidate_count", 0)
                stage2_count = _gobjects_brute_last_meta.get("stage2_count", 0)
                heap_shapes = _gobjects_brute_last_meta.get("heap_shape_count", 0)
                heap_stage2 = _gobjects_brute_last_meta.get("heap_stage2_count", 0)
                heap_best_valid = _gobjects_brute_last_meta.get("heap_best_valid", 0)
                heap_best_equal = _gobjects_brute_last_meta.get(
                    "heap_best_index_equal", 0
                )
                heap_best_near = _gobjects_brute_last_meta.get(
                    "heap_best_index_near", 0
                )
                heap_detail = ""
                if heap_shapes or _gobjects_brute_last_meta.get("heap_slot_count", 0):
                    heap_detail = (
                        f"; heap-pointer scan: {heap_shapes} shape(s), "
                        f"{heap_stage2} readable item source candidate(s), "
                        f"best valid={heap_best_valid}, index_eq={heap_best_equal}, "
                        f"index_near={heap_best_near}"
                    )
                diag.failed(
                    "GObjects",
                    "brute_force_scan",
                    "No valid FUObjectArray found in .rdata/.data sections "
                    f"({candidate_count} shape(s), {stage2_count} readable item source candidate(s))"
                    f"{heap_detail}",
                )
            diag.set_confidence("GObjects", 0.0, "all methods exhausted")
        candidate_count = _gobjects_brute_last_meta.get("candidate_count", 0)
        _gobjects_resolution_meta["structural_failure_kind"] = (
            "structural_validation_rejected"
            if candidate_count
            else "structural_candidate_miss"
        )
        if total_hits == 0 and candidate_count == 0:
            failure_kind = "signature_and_structural_miss"
        elif candidate_count:
            failure_kind = "structural_validation_rejected"
        elif total_hits:
            failure_kind = "signature_validation_rejected"
        else:
            failure_kind = "structural_candidate_miss"
        _record_gobjects_failure(
            failure_kind,
            "GObjects live recovery exhausted signature, name-backed, and structural paths",
            signature_rejections=signature_rejections,
        )
    return result

def get_object_count(handle: int, gobjects_ptr: int) -> int:
    return _try_read_num_elements(handle, gobjects_ptr) or 0

def _try_read_num_elements(handle: int, base: int) -> int:
    for off in FUOBJECTARRAY_NUMELEMENTS_CANDIDATES:
        val = read_int32(handle, base + off)
        if val == 0:
            continue
        if 1 <= val <= 5_000_000:
            return val
    return 0

def read_uobject(
    handle: int,
    gobjects_ptr: int,
    index: int,
    item_size: int = FUOBJECTITEM_SIZE_NORMAL,
) -> Optional[Dict]:
    obj_ptr = _gobject_item_object_ptr(handle, gobjects_ptr, index, item_size)
    if not obj_ptr:
        return None

    flags = read_int32(handle, obj_ptr + UOBJECT_FLAGS)
    internal_index = read_int32(handle, obj_ptr + UOBJECT_INDEX)
    class_ptr = read_uint64(handle, obj_ptr + UOBJECT_CLASS)
    name_index = read_uint32(handle, obj_ptr + UOBJECT_NAME)
    outer_ptr = read_uint64(handle, obj_ptr + UOBJECT_OUTER)

    return {
        "address": obj_ptr,
        "flags": flags,
        "internal_index": internal_index,
        "class_ptr": class_ptr,
        "name_index": name_index,
        "outer_ptr": outer_ptr,
    }

def get_object_name(
    handle: int,
    gobjects_ptr: int,
    gnames_ptr: int,
    index: int,
    ue_version: str = "4.27",
    case_preserving: bool = False,
    item_size: int = FUOBJECTITEM_SIZE_NORMAL,
) -> str:
    obj = read_uobject(handle, gobjects_ptr, index, item_size)
    if not obj:
        return ""

    return read_fname(
        handle, gnames_ptr, obj["name_index"], ue_version, case_preserving
    )

def get_object_class_name(
    handle: int,
    gnames_ptr: int,
    class_ptr: int,
    ue_version: str = "4.27",
    case_preserving: bool = False,
) -> str:
    if not class_ptr:
        return ""

    class_name_index = read_uint32(handle, class_ptr + UOBJECT_NAME)
    return read_fname(handle, gnames_ptr, class_name_index, ue_version, case_preserving)

def get_object_full_name(
    handle: int,
    gobjects_ptr: int,
    gnames_ptr: int,
    index: int,
    ue_version: str = "4.27",
    case_preserving: bool = False,
    item_size: int = FUOBJECTITEM_SIZE_NORMAL,
) -> str:
    obj = read_uobject(handle, gobjects_ptr, index, item_size)
    if not obj:
        return ""

    obj_name = read_fname(
        handle, gnames_ptr, obj["name_index"], ue_version, case_preserving
    )
    class_name = get_object_class_name(
        handle, gnames_ptr, obj["class_ptr"], ue_version, case_preserving
    )

    outers = []
    current_outer = obj["outer_ptr"]
    max_depth = 20
    while current_outer and max_depth > 0:
        outer_name_idx = read_uint32(handle, current_outer + UOBJECT_NAME)
        outer_name = read_fname(
            handle, gnames_ptr, outer_name_idx, ue_version, case_preserving
        )
        if outer_name:
            outers.append(outer_name)
        current_outer = read_uint64(handle, current_outer + UOBJECT_OUTER)
        max_depth -= 1

    outers.reverse()
    path = ".".join(outers + [obj_name]) if outers else obj_name
    return f"{class_name} {path}" if class_name else path

def validate_gobjects(
    handle: int,
    gobjects_ptr: int,
    gnames_ptr: int = 0,
    ue_version: str = "4.27",
    case_preserving: Optional[bool] = False,
    item_size: int = FUOBJECTITEM_SIZE_NORMAL,
    legacy_names: bool = False,
) -> bool:
    count = get_object_count(handle, gobjects_ptr)
    if count <= 0:
        return False

    valid = 0
    valid_names = 0
    coherent_classes = 0
    class_name_cache: Dict[int, str] = {}
    for i in range(min(12, count)):
        obj = read_uobject(handle, gobjects_ptr, i, item_size)
        if not obj:
            continue
        if _plausible_ue_ptr64(obj["class_ptr"]):
            valid += 1
        if not gnames_ptr:
            continue

        obj_name = read_fname(
            handle,
            gnames_ptr,
            obj["name_index"],
            ue_version,
            case_preserving,
            legacy=legacy_names,
        )
        if obj_name and obj_name != "None":
            valid_names += 1

        class_ptr = obj["class_ptr"]
        if not class_ptr:
            continue
        class_name = class_name_cache.get(class_ptr)
        if class_name is None:
            class_name_index = read_uint32(handle, class_ptr + UOBJECT_NAME)
            class_name = read_fname(
                handle,
                gnames_ptr,
                class_name_index,
                ue_version,
                case_preserving,
                legacy=legacy_names,
            )
            class_name_cache[class_ptr] = class_name
        if _looks_coherent_gobject_class_name(class_name):
            coherent_classes += 1

    if not gnames_ptr:
        return valid >= 5
    return valid >= 5 and (valid_names >= 3 or coherent_classes >= 2)

def probe_item_size(
    handle: int,
    gobjects_ptr: int,
) -> int:
    sz = probe_gobjects_item_size(handle, gobjects_ptr)
    return sz if sz else FUOBJECTITEM_SIZE_NORMAL
