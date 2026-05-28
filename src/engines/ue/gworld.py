
import logging
import struct
import time
from typing import Dict, List, Optional
from collections import Counter

from src.core.memory import (
    read_bytes,
    read_uint64,
    read_uint32,
    snapshot_mark,
    snapshot_memory_ranges,
    snapshot_restore_mark,
    prefetch_memory_pages,
    scatter_read_multiple,
)
from src.core.pe_parser import get_pe_rdata_data_scan_ranges, get_pe_text_scan_ranges
from src.core.scanner import scan_pattern, resolve_rip
from src.engines.ue.signatures import GWORLD_SIGS
from src.engines.ue.gnames import read_fname
from src.engines.ue.gobjects import (
    UOBJECT_CLASS,
    UOBJECT_NAME,
    UOBJECT_OUTER,
    OBJECTS_PER_CHUNK,
    get_gobjects_objects_ptr,
    get_object_count,
)

logger = logging.getLogger(__name__)

_GWORLD_MODULE_SLOT_LIMIT = 16
_GWORLD_WORLD_CANDIDATE_LIMIT = 8
_GWORLD_OBJECT_SCAN_BYTES = 0x180
_GWORLD_SUPPORT_TOKENS = ("Level", "GameInstance")
_HIGH_MODULE_LIKE_PTR = 0x700000000000

def _looks_like_world_class(class_name: str) -> bool:
    return class_name == "World" or class_name.endswith("World")

def _plausible_heap_ptr(value: int) -> bool:
    if value & 0x7:
        return False
    return 0x100000 <= value <= 0x7FFFFFFFFFFF

def _likely_runtime_object_ptr(value: int) -> bool:
    return _plausible_heap_ptr(value) and value < _HIGH_MODULE_LIKE_PTR

def _deadline_reached(deadline: float) -> bool:
    return bool(deadline) and time.monotonic() >= deadline

def _case_preserving_modes(case_preserving: bool) -> List[Optional[bool]]:
    modes: List[Optional[bool]] = [case_preserving]
    alt_mode = not bool(case_preserving)
    if alt_mode not in modes:
        modes.append(alt_mode)
    if None not in modes:
        modes.append(None)
    return modes

def _read_uobject_name(
    handle: int,
    obj_ptr: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
) -> str:
    if not _plausible_heap_ptr(obj_ptr):
        return ""
    name_idx = read_uint32(handle, obj_ptr + UOBJECT_NAME)
    if not name_idx:
        return ""
    return read_fname(handle, gnames_ptr, name_idx, ue_version, case_preserving)

def _object_references_support_type(
    handle: int,
    obj_ptr: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
) -> bool:
    raw = read_bytes(handle, obj_ptr, _GWORLD_OBJECT_SCAN_BYTES)
    if len(raw) < 0x40:
        return False

    matched = set()
    for off in range(0, len(raw) - 7, 8):
        ref = struct.unpack_from("<Q", raw, off)[0]
        if not _likely_runtime_object_ptr(ref) or ref == obj_ptr:
            continue
        class_name = _get_uobject_class_name(
            handle, ref, gnames_ptr, ue_version, case_preserving
        )
        for token in _GWORLD_SUPPORT_TOKENS:
            if token in class_name:
                matched.add(token)
        if matched:
            return True
    return False

def _validate_world_object(
    handle: int,
    obj_ptr: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
) -> bool:
    class_name = _get_uobject_class_name(
        handle, obj_ptr, gnames_ptr, ue_version, case_preserving
    )
    if not _looks_like_world_class(class_name):
        return False
    if not _read_uobject_name(handle, obj_ptr, gnames_ptr, ue_version, case_preserving):
        return False
    return _object_references_support_type(
        handle, obj_ptr, gnames_ptr, ue_version, case_preserving
    )

def _find_module_pointer_slots(
    handle: int,
    module_base: int,
    module_size: int,
    target_ptr: int,
    diag=None,
    deadline: float = 0.0,
) -> List[int]:
    ranges = get_pe_rdata_data_scan_ranges(handle, module_base)
    if not ranges and module_size > 0:
        ranges = [(module_base, module_base + module_size)]
    if not ranges:
        return []

    snap_mark = snapshot_mark()
    slots: List[int] = []
    try:
        stats = snapshot_memory_ranges(handle, ranges, tolerant=True)
        if diag and stats:
            diag.info(
                f"Snapshotted {len(stats)} module data range(s) for structural slot search",
                "GWorld",
            )

        needle = struct.pack("<Q", target_ptr)
        for start, end in ranges:
            if _deadline_reached(deadline):
                break
            data = read_bytes(handle, start, end - start)
            if len(data) < 8:
                continue
            pos = data.find(needle)
            while pos != -1 and len(slots) < _GWORLD_MODULE_SLOT_LIMIT:
                if _deadline_reached(deadline):
                    break
                if (pos & 0x7) == 0:
                    slots.append(start + pos)
                pos = data.find(needle, pos + 1)
            if len(slots) >= _GWORLD_MODULE_SLOT_LIMIT:
                break
    finally:
        snapshot_restore_mark(snap_mark)

    return slots

def _find_gworld_via_data_section(
    handle: int,
    module_base: int,
    module_size: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    deadline: float = 0.0,
) -> int:
    data_ranges = get_pe_rdata_data_scan_ranges(handle, module_base)
    if not data_ranges:
        return 0

    _prefetch_fname_pool(handle, gnames_ptr)

    snap_mark = snapshot_mark()
    try:
        snapshot_memory_ranges(handle, data_ranges, tolerant=True)

        for sec_start, sec_end in data_ranges:
            if _deadline_reached(deadline):
                break
            sec_data = read_bytes(handle, sec_start, sec_end - sec_start)
            if not sec_data or len(sec_data) < 8:
                continue

            slots_vals: List[tuple] = []
            for off in range(0, len(sec_data) - 7, 8):
                val = struct.unpack_from("<Q", sec_data, off)[0]
                if _likely_runtime_object_ptr(val):
                    slots_vals.append((sec_start + off, val))
            if not slots_vals:
                continue

            _BATCH = 5000
            all_class_ptrs: List[int] = []
            for i in range(0, len(slots_vals), _BATCH):
                if _deadline_reached(deadline):
                    break
                batch = slots_vals[i : i + _BATCH]
                reqs = [(val + UOBJECT_CLASS, 8) for _, val in batch]
                results = scatter_read_multiple(handle, reqs)
                for raw in results:
                    if len(raw) >= 8:
                        all_class_ptrs.append(struct.unpack_from("<Q", raw)[0])
                    else:
                        all_class_ptrs.append(0)

            if len(all_class_ptrs) != len(slots_vals):
                continue

            unique_classes = list({p for p in all_class_ptrs if _plausible_heap_ptr(p)})
            class_name_map: Dict[int, str] = {}
            cp_modes = _case_preserving_modes(case_preserving)
            if unique_classes:
                name_reqs = [(cptr + UOBJECT_NAME, 4) for cptr in unique_classes]
                name_results = scatter_read_multiple(handle, name_reqs)
                for cptr, raw in zip(unique_classes, name_results):
                    if _deadline_reached(deadline):
                        break
                    if len(raw) < 4:
                        continue
                    name_idx = struct.unpack_from("<I", raw)[0]
                    for cp_mode in cp_modes:
                        try:
                            name = read_fname(
                                handle, gnames_ptr, name_idx, ue_version, cp_mode
                            )
                            if name:
                                class_name_map[cptr] = name
                                break
                        except Exception:
                            continue

            for (slot_va, _obj_ptr), class_ptr in zip(slots_vals, all_class_ptrs):
                if _deadline_reached(deadline):
                    break
                if _looks_like_world_class(class_name_map.get(class_ptr, "")):
                    return slot_va
    finally:
        snapshot_restore_mark(snap_mark)

    return 0

_FNAMEPOOL_BLOCK_SIZE = 0x20000
_FNAMEPOOL_MAX_PREFETCH_BLOCKS = 8

def _prefetch_fname_pool(handle: int, gnames_ptr: int) -> None:
    if not gnames_ptr:
        return

    header_size = 0x10 + _FNAMEPOOL_MAX_PREFETCH_BLOCKS * 8
    header_data = read_bytes(handle, gnames_ptr, header_size)
    if len(header_data) < 0x14:
        return

    current_block = struct.unpack_from("<I", header_data, 0x08)[0]
    if current_block > 64:
        return
    num_blocks = min(current_block + 1, _FNAMEPOOL_MAX_PREFETCH_BLOCKS)

    block_ptrs = []
    for i in range(num_blocks):
        off = 0x10 + i * 8
        if off + 8 > len(header_data):
            break
        ptr = struct.unpack_from("<Q", header_data, off)[0]
        if _plausible_heap_ptr(ptr):
            block_ptrs.append((ptr, i))

    if not block_ptrs:
        return

    cursor = struct.unpack_from("<I", header_data, 0x0C)[0]
    ranges = []
    for ptr, block_idx in block_ptrs:
        if block_idx == current_block:
            size = min(cursor + 0x1000, _FNAMEPOOL_BLOCK_SIZE)
        else:
            size = _FNAMEPOOL_BLOCK_SIZE
        ranges.append((ptr, ptr + size))

    if ranges:
        snapshot_memory_ranges(handle, ranges, tolerant=True)

def _iter_world_candidates_from_gobjects(
    handle: int,
    gobjects_ptr: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    item_size: int,
    deadline: float = 0.0,
) -> List[int]:
    if not gobjects_ptr or not gnames_ptr:
        return []

    count = get_object_count(handle, gobjects_ptr)
    if count <= 0:
        return []

    objects_ptr = get_gobjects_objects_ptr(handle, gobjects_ptr)
    if not objects_ptr:
        return []

    num_chunks = (count + OBJECTS_PER_CHUNK - 1) // OBJECTS_PER_CHUNK
    raw_chunks = read_bytes(handle, objects_ptr, num_chunks * 8)
    actual_chunk_bytes = len(raw_chunks)
    if actual_chunk_bytes < 8:
        return []
    usable_chunks = actual_chunk_bytes // 8
    if usable_chunks < num_chunks:
        logger.debug(
            "GWorld structural: expected %d chunks (%d objects) but only read %d — "
            "race condition likely, continuing with %d chunks",
            num_chunks, count, usable_chunks, usable_chunks,
        )
    chunk_ptrs = struct.unpack_from(f"<{usable_chunks}Q", raw_chunks)

    _prefetch_fname_pool(handle, gnames_ptr)

    cp_modes = _case_preserving_modes(case_preserving)

    candidates: List[int] = []
    seen = set()
    for chunk_idx, chunk_base in enumerate(chunk_ptrs):
        if _deadline_reached(deadline):
            break
        if len(candidates) >= _GWORLD_WORLD_CANDIDATE_LIMIT:
            break
        if not _plausible_heap_ptr(chunk_base):
            continue

        items_in_chunk = min(OBJECTS_PER_CHUNK, count - chunk_idx * OBJECTS_PER_CHUNK)
        if items_in_chunk <= 0:
            break

        chunk_data = read_bytes(handle, chunk_base, items_in_chunk * item_size)
        if len(chunk_data) < 8:
            continue

        obj_ptrs: List[int] = []
        for within_idx in range(items_in_chunk):
            item_off = within_idx * item_size
            if item_off + 8 > len(chunk_data):
                break
            obj_ptr = struct.unpack_from("<Q", chunk_data, item_off)[0]
            if _likely_runtime_object_ptr(obj_ptr):
                obj_ptrs.append(obj_ptr)
        if not obj_ptrs:
            continue

        class_read_requests = [(ptr + UOBJECT_CLASS, 8) for ptr in obj_ptrs]
        class_results = scatter_read_multiple(handle, class_read_requests)

        class_ptrs: List[int] = []
        for raw in class_results:
            if len(raw) >= 8:
                class_ptrs.append(struct.unpack_from("<Q", raw)[0])
            else:
                class_ptrs.append(0)

        unique_classes = [ptr for ptr in set(class_ptrs) if _plausible_heap_ptr(ptr)]

        class_name_map: Dict[int, str] = {}
        if unique_classes:
            name_read_requests = [(cptr + UOBJECT_NAME, 4) for cptr in unique_classes]
            name_results = scatter_read_multiple(handle, name_read_requests)

            for class_ptr_val, raw in zip(unique_classes, name_results):
                if _deadline_reached(deadline):
                    break
                if len(raw) < 4:
                    continue
                name_idx = struct.unpack_from("<I", raw)[0]
                for cp_mode in cp_modes:
                    if _deadline_reached(deadline):
                        break
                    try:
                        name = read_fname(
                            handle, gnames_ptr, name_idx, ue_version, cp_mode
                        )
                        if name:
                            class_name_map[class_ptr_val] = name
                            break
                    except Exception:
                        continue

        for obj_ptr, class_ptr in zip(obj_ptrs, class_ptrs):
            if _deadline_reached(deadline):
                break
            if obj_ptr in seen:
                continue
            if not _looks_like_world_class(class_name_map.get(class_ptr, "")):
                continue
            seen.add(obj_ptr)
            candidates.append(obj_ptr)
            if len(candidates) >= _GWORLD_WORLD_CANDIDATE_LIMIT:
                break

    return candidates

def _find_gworld_via_gobjects(
    handle: int,
    module_base: int,
    module_size: int,
    gobjects_ptr: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    item_size: int,
    diag=None,
    deadline: float = 0.0,
) -> int:
    world_candidates = _iter_world_candidates_from_gobjects(
        handle,
        gobjects_ptr,
        gnames_ptr,
        ue_version,
        case_preserving,
        item_size,
        deadline=deadline,
    )
    if diag:
        diag.tried(
            "GWorld",
            "gobjects_structural",
            f"{len(world_candidates)} live World candidate(s) discovered",
        )
    if not world_candidates:
        count = get_object_count(handle, gobjects_ptr)
        logger.debug(
            "GWorld structural: 0 World candidates from %d GObjects "
            "(case_preserving=%s, item_size=%d)",
            count, case_preserving, item_size,
        )

    for world_ptr in world_candidates:
        if _deadline_reached(deadline):
            break
        cp_modes = _case_preserving_modes(case_preserving)
        class_name = ""
        for cp_mode in cp_modes:
            class_name = _get_uobject_class_name(
                handle, world_ptr, gnames_ptr, ue_version, cp_mode
            )
            if class_name:
                break
        if not _looks_like_world_class(class_name):
            continue
        world_name = ""
        for cp_mode in cp_modes:
            world_name = _read_uobject_name(
                handle, world_ptr, gnames_ptr, ue_version, cp_mode
            )
            if world_name:
                break
        if not world_name:
            continue
        support_refs_ok = _object_references_support_type(
            handle, world_ptr, gnames_ptr, ue_version, case_preserving
        )
        slots = _find_module_pointer_slots(
            handle, module_base, module_size, world_ptr, diag=diag, deadline=deadline
        )
        if not slots and diag:
            diag.info(
                f"World candidate at 0x{world_ptr:X} (name={world_name!r}) "
                f"found in GObjects but no module slot contains this pointer",
                "GWorld",
            )
        for slot in slots:
            if _deadline_reached(deadline):
                break
            if validate_gworld(
                handle,
                slot,
                module_base=module_base,
                module_size=module_size,
                gnames_ptr=gnames_ptr,
                ue_version=ue_version,
                case_preserving=case_preserving,
                deadline=deadline,
            ):
                if diag:
                    diag.passed(
                        "GWorld",
                        "gobjects_structural",
                        f"Recovered module slot +0x{slot - module_base:X} -> 0x{world_ptr:X}",
                    )
                    diag.set_confidence(
                        "GWorld",
                        0.95 if support_refs_ok else 0.9,
                        (
                            "validated live World object traced back to module slot"
                            if support_refs_ok
                            else "validated World-class object traced back to module slot"
                        ),
                    )
                return slot
    return 0

def _find_gworld_legacy(
    handle: int,
    module_base: int,
    module_size: int,
    ue_version: str = "4.27",
    override_rva: Optional[int] = None,
    diag=None,
    gobjects_ptr: int = 0,
    gnames_ptr: int = 0,
    item_size: int = 24,
) -> int:
    if override_rva is not None:
        if diag:
            diag.info(f"Using cached offset +0x{override_rva:X} from OffsetsInfo.json", "GWorld")
        return module_base + override_rva

    if gobjects_ptr and gnames_ptr:
        if diag:
            diag.info("Attempting fast GWorld extraction via GObjects caching...", "GWorld")
        
        from src.engines.ue.gobjects import get_gobjects_objects_ptr, get_object_count, OBJECTS_PER_CHUNK
        from src.core.memory import USE_DRIVER, read_uint64, read_bytes, read_uint32
        import struct

        count = get_object_count(handle, gobjects_ptr)
        if count > 0:
            objects_ptr = get_gobjects_objects_ptr(handle, gobjects_ptr)
            if objects_ptr:
                num_chunks = (count + OBJECTS_PER_CHUNK - 1) // OBJECTS_PER_CHUNK
                chunk_bytes_size = OBJECTS_PER_CHUNK * item_size
                
                world_candidate = 0
                for chunk_idx in range(num_chunks):
                    if world_candidate:
                        break
                        
                    chunk_base = read_uint64(handle, objects_ptr + chunk_idx * 8)
                    if not chunk_base:
                        continue
                        
                    if USE_DRIVER:
                        from src.core.driver import read_memory_kernel
                        from src.core.memory import TARGET_PID
                        chunk_data = read_memory_kernel(TARGET_PID, chunk_base, chunk_bytes_size)
                    else:
                        chunk_data = read_bytes(handle, chunk_base, chunk_bytes_size)
                        
                    if not chunk_data:
                        continue
                        
                    valid_objects = []
                    for i in range(OBJECTS_PER_CHUNK):
                        if chunk_idx * OBJECTS_PER_CHUNK + i >= count:
                            break
                        offset = i * item_size
                        if offset + 8 > len(chunk_data):
                            break
                        obj_ptr = struct.unpack_from("<Q", chunk_data, offset)[0]
                        if obj_ptr and obj_ptr > 0x10000:
                            valid_objects.append(obj_ptr)
                            
                    if not valid_objects:
                        continue
                        
                    from src.core.memory import prefetch_memory_pages
                    prefetch_memory_pages(
                        handle, 
                        [(ptr + UOBJECT_CLASS) & ~0xFFF for ptr in valid_objects],
                        tolerant=True
                    )
                    
                    class_ptrs = []
                    for ptr in valid_objects:
                        class_ptrs.append(read_uint64(handle, ptr + UOBJECT_CLASS))
                            
                    unique_classes = {cptr for cptr in class_ptrs if cptr > 0x10000}
                    
                    class_names_map = {}
                    if unique_classes:
                        unique_list = list(unique_classes)
                        prefetch_memory_pages(
                            handle, 
                            [(cptr + UOBJECT_NAME) & ~0xFFF for cptr in unique_list],
                            tolerant=True
                        )
                        
                        for cptr in unique_classes:
                            name_idx = read_uint32(handle, cptr + UOBJECT_NAME)
                            class_names_map[cptr] = read_fname(handle, gnames_ptr, name_idx, ue_version, False)
                            
                    for obj_ptr, cptr in zip(valid_objects, class_ptrs):
                        if cptr in class_names_map and class_names_map[cptr] == "World":
                            if diag:
                                diag.passed("GWorld", "object_iteration", f"Found UWorld directly via Bulk Cache at 0x{obj_ptr:X}")
                                diag.set_confidence("GWorld", 1.0, "found securely via GObjects hierarchy matching")
                            
                            world_candidate = obj_ptr 
                            break

                if world_candidate:
                    return world_candidate - 0

    from src.core.memory import USE_DRIVER

    text_ranges = []
    snapshots_added = False

    if USE_DRIVER:
        from src.core.driver import bulk_read_mode, read_memory_kernel
        from src.core.memory import TARGET_PID, add_memory_snapshot, clear_memory_snapshots
        from src.core.pe_parser import get_pe_text_scan_ranges

        text_ranges = get_pe_text_scan_ranges(handle, module_base)
        if text_ranges:
            with bulk_read_mode():
                for sec_start, sec_end in text_ranges:
                    sec_size = sec_end - sec_start
                    data = read_memory_kernel(TARGET_PID, sec_start, sec_size)
                    if len(data) == sec_size:
                        add_memory_snapshot(sec_start, data)
                        snapshots_added = True

    votes: Counter = Counter()
    module_end = module_base + module_size if module_size > 0 else 0

    try:
        for sig in sorted(GWORLD_SIGS, key=lambda s: s.priority):
            if text_ranges:
                hits = []
                for sec_start, sec_end in text_ranges:
                    hits.extend(
                        scan_pattern(handle, sec_start, sec_end - sec_start,
                                     sig.pattern, max_results=20)
                    )
            else:
                hits = scan_pattern(handle, module_base, module_size, sig.pattern, max_results=20)
            resolved = []
            for hit in hits:
                try:
                    target = resolve_rip(handle, hit, sig.disp_offset, sig.instruction_size)
                    if target is None:
                        continue
                    if module_size > 0:
                        if not (module_base <= target < module_end):
                            continue
                    elif target < module_base:
                        continue
                    votes[target] += 1
                    resolved.append(target)
                except Exception as e:
                    continue
            if diag:
                diag.tried("GWorld", sig.name,
                            f"{len(hits)} hit(s), {len(resolved)} resolved")
    finally:
        if snapshots_added:
            from src.core.memory import clear_memory_snapshots
            clear_memory_snapshots()

    if not votes:
        if diag:
            diag.failed("GWorld", "all_signatures",
                        f"0 valid hits across {len(GWORLD_SIGS)} patterns — "
                        f"GWorld has no brute-force fallback")
            diag.set_confidence("GWorld", 0.0, "no signatures matched")
        return 0

    best, best_count = votes.most_common(1)[0]
    if diag:
        diag.passed("GWorld", "signature_vote",
                    f"addr=+0x{best - module_base:X} ({best_count} votes)")
        diag.set_confidence("GWorld", min(1.0, best_count / 3),
                            f"{best_count} signature votes")
    return best

def _validate_world_slot_structural(
    handle: int,
    slot_addr: int,
    gnames_ptr: int = 0,
    ue_version: str = "4.27",
    case_preserving: bool = False,
) -> bool:
    ptr = read_uint64(handle, slot_addr)
    if not _likely_runtime_object_ptr(ptr):
        return False

    class_ptr = read_uint64(handle, ptr + UOBJECT_CLASS)
    if _plausible_heap_ptr(class_ptr):
        class_name_idx = read_uint32(handle, class_ptr + UOBJECT_NAME)
        if class_name_idx and gnames_ptr:
            cp_modes = _case_preserving_modes(case_preserving)
            for cp_mode in cp_modes:
                try:
                    class_name = read_fname(
                        handle, gnames_ptr, class_name_idx, ue_version, cp_mode
                    )
                    if class_name:
                        if _looks_like_world_class(class_name):
                            return True
                        return False
                except Exception:
                    continue

    if not _plausible_heap_ptr(class_ptr):
        return False
    persistent_level = read_uint64(handle, ptr + 0x30)
    if not _plausible_heap_ptr(persistent_level):
        return False
    level_class = read_uint64(handle, persistent_level + UOBJECT_CLASS)
    if not _plausible_heap_ptr(level_class):
        return False
    name_idx = read_uint32(handle, ptr + UOBJECT_NAME)
    if not name_idx:
        return False
    logger.info(
        "GWorld structural-only validation passed for slot +0x%X "
        "(FName resolution failed but structural shape matches UWorld)",
        slot_addr,
    )
    return True

def _find_gworld_near_slot(
    handle: int,
    anchor_slot: int,
    module_base: int,
    module_size: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    deadline: float = 0.0,
    diag=None,
) -> int:
    module_end = module_base + module_size if module_size else 0
    skip_addrs = {anchor_slot}
    cp_modes = _case_preserving_modes(case_preserving)

    def _batched_world_scan(
        sec_data: bytes,
        sec_start: int,
        exclude_range: tuple = None,
    ) -> int:
        slot_candidates: List[tuple] = []
        for off in range(0, len(sec_data) - 7, 8):
            slot_addr = sec_start + off
            if slot_addr in skip_addrs:
                continue
            if exclude_range and exclude_range[0] <= slot_addr < exclude_range[1]:
                continue
            val = struct.unpack_from("<Q", sec_data, off)[0]
            if _likely_runtime_object_ptr(val):
                slot_candidates.append((slot_addr, val))
        if not slot_candidates:
            return 0

        class_reqs = [(obj_ptr + UOBJECT_CLASS, 8) for _, obj_ptr in slot_candidates]
        class_results = scatter_read_multiple(handle, class_reqs)
        class_ptrs: List[int] = []
        for raw in class_results:
            if len(raw) >= 8:
                class_ptrs.append(struct.unpack_from("<Q", raw)[0])
            else:
                class_ptrs.append(0)

        unique_classes = list({p for p in class_ptrs if _plausible_heap_ptr(p)})
        class_name_map: Dict[int, str] = {}
        if unique_classes:
            name_reqs = [(cptr + UOBJECT_NAME, 4) for cptr in unique_classes]
            name_results = scatter_read_multiple(handle, name_reqs)
            for cptr, raw in zip(unique_classes, name_results):
                if _deadline_reached(deadline):
                    break
                if len(raw) < 4:
                    continue
                name_idx = struct.unpack_from("<I", raw)[0]
                for cp_mode in cp_modes:
                    try:
                        name = read_fname(
                            handle, gnames_ptr, name_idx, ue_version, cp_mode
                        )
                        if name:
                            class_name_map[cptr] = name
                            break
                    except Exception:
                        continue

        for (slot_addr, obj_ptr), class_ptr in zip(slot_candidates, class_ptrs):
            if _looks_like_world_class(class_name_map.get(class_ptr, "")):
                return slot_addr

        for (slot_addr, obj_ptr), class_ptr in zip(slot_candidates, class_ptrs):
            if class_ptr in class_name_map:
                continue
            if not _plausible_heap_ptr(class_ptr):
                continue
            persistent_level = read_uint64(handle, obj_ptr + 0x30)
            if not _plausible_heap_ptr(persistent_level):
                continue
            level_class = read_uint64(handle, persistent_level + UOBJECT_CLASS)
            if not _plausible_heap_ptr(level_class):
                continue
            name_idx = read_uint32(handle, obj_ptr + UOBJECT_NAME)
            if not name_idx:
                continue
            logger.info(
                "GWorld structural-only validation passed for slot +0x%X "
                "(FName resolution failed but structural shape matches UWorld)",
                slot_addr,
            )
            return slot_addr

        return 0

    _TIGHT_RADIUS = 0x800
    scan_start = max(module_base, anchor_slot - _TIGHT_RADIUS)
    scan_end = min(module_end, anchor_slot + _TIGHT_RADIUS) if module_end else anchor_slot + _TIGHT_RADIUS
    region_size = scan_end - scan_start

    if region_size > 0 and not _deadline_reached(deadline):
        snap_mark_local = snapshot_mark()
        try:
            region_data = read_bytes(handle, scan_start, region_size)
            if region_data and len(region_data) >= 8:
                result = _batched_world_scan(region_data, scan_start)
                if result:
                    if diag:
                        diag.info(
                            f"GWorld at +0x{result - module_base:X} "
                            f"({result - anchor_slot:+d} bytes from GEngine)",
                            "GWorld",
                        )
                    return result
        finally:
            snapshot_restore_mark(snap_mark_local)

    if not _deadline_reached(deadline):
        data_ranges = get_pe_rdata_data_scan_ranges(handle, module_base)
        if data_ranges:
            snap_mark_local = snapshot_mark()
            try:
                snapshot_memory_ranges(handle, data_ranges, tolerant=True)
                for sec_start, sec_end in data_ranges:
                    if _deadline_reached(deadline):
                        break
                    sec_data = read_bytes(handle, sec_start, sec_end - sec_start)
                    if not sec_data or len(sec_data) < 8:
                        continue
                    result = _batched_world_scan(
                        sec_data, sec_start,
                        exclude_range=(scan_start, scan_end),
                    )
                    if result:
                        if diag:
                            diag.info(
                                f"GWorld at +0x{result - module_base:X} "
                                f"(found in .data full scan)",
                                "GWorld",
                            )
                        return result
            finally:
                snapshot_restore_mark(snap_mark_local)

    return 0

def find_gworld(
    handle: int,
    module_base: int,
    module_size: int,
    ue_version: str = "4.27",
    override_rva: Optional[int] = None,
    diag=None,
    gobjects_ptr: int = 0,
    gnames_ptr: int = 0,
    case_preserving: bool = False,
    item_size: int = 24,
    timeout_seconds: float = 0.0,
) -> int:
    if override_rva is not None:
        if diag:
            diag.info(
                f"Using cached offset +0x{override_rva:X} from OffsetsInfo.json",
                "GWorld",
            )
        return module_base + override_rva

    deadline = 0.0
    timeout_value = 0.0
    if timeout_seconds:
        try:
            timeout_value = float(timeout_seconds)
        except (TypeError, ValueError):
            timeout_value = 0.0
        if timeout_value > 0:
            deadline = time.monotonic() + timeout_value

    text_ranges = get_pe_text_scan_ranges(handle, module_base)
    module_end = module_base + module_size if module_size > 0 else 0
    votes: Counter = Counter()
    snap_mark = snapshot_mark()
    timed_out = False
    structural_attempted = False
    data_scan_deadline = deadline
    structural_deadline = deadline

    if deadline and timeout_value > 0:
        now = time.monotonic()
        data_window = min(30.0, max(8.0, timeout_value * 0.25))
        data_scan_deadline = min(deadline, now + data_window)
        if data_scan_deadline <= now:
            data_scan_deadline = min(deadline, now + 2.0)

        sig_window = min(40.0, max(15.0, timeout_value * 0.30))
        sig_deadline = min(deadline, now + data_window + sig_window)
        if sig_deadline <= now:
            sig_deadline = min(deadline, now + 2.0)

        structural_deadline = deadline
    else:
        sig_deadline = deadline

    if gnames_ptr and not _deadline_reached(data_scan_deadline):
        if diag:
            diag.info(
                "Attempting GWorld discovery via .data section scan (reliable for large games)...",
                "GWorld",
            )
        try:
            cp_modes = _case_preserving_modes(case_preserving)
            for cp_mode in cp_modes:
                if _deadline_reached(data_scan_deadline):
                    break
                if cp_mode != case_preserving and diag:
                    mode_label = "auto" if cp_mode is None else str(bool(cp_mode))
                    diag.info(
                        f"Retrying .data scan with case_preserving={mode_label}",
                        "GWorld",
                    )
                data_world = _find_gworld_via_data_section(
                    handle,
                    module_base,
                    module_size,
                    gnames_ptr,
                    ue_version,
                    cp_mode,
                    data_scan_deadline,
                )
                if not data_world:
                    continue
                if validate_gworld(
                    handle,
                    data_world,
                    module_base=module_base,
                    module_size=module_size,
                    gnames_ptr=gnames_ptr,
                    ue_version=ue_version,
                    case_preserving=cp_mode,
                    deadline=data_scan_deadline,
                ):
                    if diag:
                        diag.passed(
                            "GWorld",
                            "data_section_scan",
                            f"addr=+0x{data_world - module_base:X} (UWorld class found in .data)",
                        )
                        diag.set_confidence(
                            "GWorld", 0.9, "UWorld class found in module .data section"
                        )
                    return data_world
        except Exception as exc:
            logger.warning("Data section GWorld scan failed with %s: %s", type(exc).__name__, exc)
            if diag:
                diag.warn(f"Data section scan raised {type(exc).__name__}: {exc}", "GWorld")

    try:
        if text_ranges:
            snapshot_memory_ranges(handle, text_ranges, tolerant=True)

        for sig in sorted(GWORLD_SIGS, key=lambda s: s.priority):
            if _deadline_reached(sig_deadline):
                timed_out = True
                break
            if text_ranges:
                hits = []
                for sec_start, sec_end in text_ranges:
                    if _deadline_reached(sig_deadline):
                        timed_out = True
                        break
                    hits.extend(
                        scan_pattern(
                            handle,
                            sec_start,
                            sec_end - sec_start,
                            sig.pattern,
                            max_results=20,
                        )
                    )
                if timed_out:
                    break
            else:
                hits = scan_pattern(
                    handle,
                    module_base,
                    module_size,
                    sig.pattern,
                    max_results=20,
                )

            resolved = []
            for hit in hits:
                if _deadline_reached(sig_deadline):
                    timed_out = True
                    break
                try:
                    target = resolve_rip(
                        handle, hit, sig.disp_offset, sig.instruction_size
                    )
                except Exception:
                    continue
                if target is None:
                    continue
                if module_size > 0:
                    if not (module_base <= target < module_end):
                        continue
                elif target < module_base:
                    continue
                votes[target] += 1
                resolved.append(target)

            if diag:
                diag.tried(
                    "GWorld",
                    sig.name,
                    f"{len(hits)} hit(s), {len(resolved)} resolved",
                )
            if _deadline_reached(sig_deadline):
                timed_out = True
                break
    finally:
        snapshot_restore_mark(snap_mark)

    sig_winner = 0
    if votes:
        for candidate_addr, candidate_count in votes.most_common():
            if _deadline_reached(deadline):
                break
            if not gnames_ptr or validate_gworld(
                handle,
                candidate_addr,
                module_base=module_base,
                module_size=module_size,
                gnames_ptr=gnames_ptr,
                ue_version=ue_version,
                case_preserving=case_preserving,
                deadline=deadline,
            ):
                if diag:
                    diag.passed(
                        "GWorld",
                        "signature_vote",
                        f"addr=+0x{candidate_addr - module_base:X} ({candidate_count} votes)",
                    )
                    diag.set_confidence(
                        "GWorld",
                        min(1.0, candidate_count / 3),
                        f"{candidate_count} signature votes",
                    )
                return candidate_addr

        best, best_count = votes.most_common(1)[0]
        sig_winner = best
        if diag:
            voted_addrs = ", ".join(
                f"+0x{addr - module_base:X}({cnt})"
                for addr, cnt in votes.most_common()
            )
            diag.info(
                f"All {len(votes)} voted address(es) failed validation [{voted_addrs}]; "
                f"scanning .data for GWorld via GEngine anchor...",
                "GWorld",
            )

    if sig_winner and not _deadline_reached(deadline):
        nearby = _find_gworld_near_slot(
            handle, sig_winner, module_base, module_size,
            gnames_ptr, ue_version, case_preserving, deadline,
            diag=diag,
        )
        if nearby:
            if diag:
                diag.passed(
                    "GWorld",
                    "gengine_proximity",
                    f"Found GWorld at +0x{nearby - module_base:X} "
                    f"(GEngine at +0x{sig_winner - module_base:X})",
                )
                diag.set_confidence(
                    "GWorld", 0.85,
                    "GWorld found via .data scan anchored from GEngine signature hit",
                )
            return nearby

    if gobjects_ptr and gnames_ptr and not _deadline_reached(structural_deadline):
        structural_attempted = True
        if diag:
            diag.info(
                "Attempting structural GWorld recovery via validated GObjects walk...",
                "GWorld",
            )
        try:
            cp_modes = _case_preserving_modes(case_preserving)
            for cp_mode in cp_modes:
                if _deadline_reached(structural_deadline):
                    break
                if cp_mode != case_preserving and diag:
                    mode_label = "auto" if cp_mode is None else str(bool(cp_mode))
                    diag.info(
                        f"Retrying structural fallback with case_preserving={mode_label}",
                        "GWorld",
                    )
                structural = _find_gworld_via_gobjects(
                    handle,
                    module_base,
                    module_size,
                    gobjects_ptr,
                    gnames_ptr,
                    ue_version,
                    cp_mode,
                    item_size,
                    diag=diag,
                    deadline=structural_deadline,
                )
                if structural:
                    return structural
        except Exception as exc:
            logger.warning("Structural GWorld search failed with %s: %s", type(exc).__name__, exc)
            if diag:
                diag.warn(f"Structural search raised {type(exc).__name__}: {exc}", "GWorld")

    if diag:
        if timed_out:
            timeout_msg = f" after {int(timeout_value)}s" if timeout_seconds else ""
            diag.warn(f"GWorld search timed out{timeout_msg}; continuing without GWorld", "GWorld")
        diag.failed(
            "GWorld",
            "all_methods",
            f"0 validated candidates across {len(GWORLD_SIGS)} patterns, data scan, "
            f"proximity scan, and structural fallback",
        )
        diag.set_confidence("GWorld", 0.0, "no validated GWorld candidate found")
    return 0

def read_gworld_ptr(
    handle: int,
    gworld_addr: int,
    module_base: int = 0,
    module_size: int = 0,
    gnames_ptr: int = 0,
    ue_version: str = "4.27",
    case_preserving: bool = False,
    deadline: float = 0.0,
) -> int:
    uworld = read_uint64(handle, gworld_addr)
    if not _plausible_heap_ptr(uworld):
        if gnames_ptr:
            direct_class = _get_uobject_class_name(
                handle, gworld_addr, gnames_ptr, ue_version, case_preserving
            )
            if _looks_like_world_class(direct_class):
                return gworld_addr
        return 0
    if gnames_ptr and module_base:
        uworld = resolve_uworld_from_module(
            handle, uworld, gworld_addr, module_base, module_size,
            gnames_ptr, ue_version, case_preserving, deadline
        )
    return uworld

def _get_uobject_class_name(
    handle: int,
    obj_ptr: int,
    gnames_ptr: int,
    ue_version: str = "4.27",
    case_preserving: bool = False,
) -> str:
    if not _plausible_heap_ptr(obj_ptr):
        return ""
    class_ptr = read_uint64(handle, obj_ptr + UOBJECT_CLASS)
    if not _plausible_heap_ptr(class_ptr):
        return ""
    class_name_idx = read_uint32(handle, class_ptr + UOBJECT_NAME)
    return read_fname(handle, gnames_ptr, class_name_idx, ue_version, case_preserving)

def resolve_uworld_from_module(
    handle: int,
    candidate: int,
    gworld_slot_va: int,
    module_base: int,
    module_size: int,
    gnames_ptr: int,
    ue_version: str = "4.27",
    case_preserving: bool = False,
    deadline: float = 0.0,
) -> int:
    class_name = _get_uobject_class_name(
        handle, candidate, gnames_ptr, ue_version, case_preserving
    )

    if not class_name:
        return candidate

    if "World" in class_name:
        return candidate

    if "Engine" not in class_name:
        logger.warning(
            "GWorld candidate class is '%s' (not World or Engine), "
            "returning as-is",
            class_name,
        )
        return candidate

    logger.info(
        "GWorld points to %s at 0x%X, scanning module globals for UWorld...",
        class_name,
        candidate,
    )

    gworld_rva = gworld_slot_va - module_base
    scan_start = max(0, gworld_rva - 0x20000)
    scan_end = min(module_size, gworld_rva + 0x20000)

    scanned_slots = 0
    for rva in range(scan_start, scan_end, 8):
        if _deadline_reached(deadline):
            logger.debug(
                "resolve_uworld_from_module: deadline reached while scanning globals near RVA 0x%X",
                gworld_rva,
            )
            break
        scanned_slots += 1
        if scanned_slots > 4096:
            logger.debug(
                "resolve_uworld_from_module: hit scan cap (4096 slots) near RVA 0x%X",
                gworld_rva,
            )
            break
        if module_base + rva == gworld_slot_va:
            continue
        ptr = read_uint64(handle, module_base + rva)
        if not _likely_runtime_object_ptr(ptr):
            continue

        inner_class_name = _get_uobject_class_name(
            handle, ptr, gnames_ptr, ue_version, case_preserving
        )
        if inner_class_name == "World":
            logger.info(
                "Found UWorld at module+0x%X -> 0x%X", rva, ptr
            )
            return ptr

    logger.warning(
        "GWorld points to %s but could not find UWorld in module globals "
        "near RVA 0x%X, returning original candidate",
        class_name,
        gworld_rva,
    )
    return candidate

def _validate_uworld_structural(handle: int, uworld_ptr: int) -> bool:
    if not _plausible_heap_ptr(uworld_ptr):
        return False
    persistent_level = read_uint64(handle, uworld_ptr + 0x30)
    if not _plausible_heap_ptr(persistent_level):
        return False
    return True

def validate_gworld(
    handle: int,
    gworld_addr: int,
    module_base: int = 0,
    module_size: int = 0,
    gnames_ptr: int = 0,
    ue_version: str = "4.27",
    case_preserving: bool = False,
    deadline: float = 0.0,
) -> bool:
    uworld = read_uint64(handle, gworld_addr)

    if not _plausible_heap_ptr(uworld):
        if gnames_ptr:
            direct_class = _get_uobject_class_name(
                handle, gworld_addr, gnames_ptr, ue_version, case_preserving
            )
            if _looks_like_world_class(direct_class):
                return _validate_uworld_structural(handle, gworld_addr)
        return False

    class_ptr = read_uint64(handle, uworld + UOBJECT_CLASS)
    if not _plausible_heap_ptr(class_ptr):
        return False

    class_name_idx = read_uint32(handle, class_ptr + UOBJECT_NAME)
    class_name = read_fname(handle, gnames_ptr, class_name_idx, ue_version, case_preserving)

    if not class_name and gnames_ptr:
        try:
            alt_case = not case_preserving
            class_name = read_fname(handle, gnames_ptr, class_name_idx, ue_version, alt_case)
        except Exception:
            pass
    if not class_name and gnames_ptr:
        try:
            class_name = read_fname(handle, gnames_ptr, class_name_idx, ue_version, None)
        except Exception:
            pass

    if class_name and not _looks_like_world_class(class_name):
        logger.debug(
            "validate_gworld: slot 0x%X -> class '%s' (not World), rejecting",
            gworld_addr, class_name,
        )
        return False

    if _looks_like_world_class(class_name):
        if not _validate_uworld_structural(handle, uworld):
            logger.debug(
                "validate_gworld: slot 0x%X -> World class OK but PersistentLevel "
                "not readable (may be paged out) — accepting anyway",
                gworld_addr,
            )
        return True

    logger.debug(
        "validate_gworld: slot 0x%X -> FName resolution failed (class_name_idx=%d), "
        "trying structural fallback",
        gworld_addr, class_name_idx,
    )
    if _validate_uworld_structural(handle, uworld):
        logger.info(
            "validate_gworld: slot 0x%X -> ACCEPTED via structural fallback "
            "(PersistentLevel at +0x30 is valid, FName unavailable)",
            gworld_addr,
        )
        return True

    return False

def validate_gworld_rva(
    handle: int,
    module_base: int,
    rva: int,
    gnames_ptr: int,
    ue_version: str = "4.27",
    case_preserving: bool = False,
    module_size: int = 0,
) -> bool:
    if not rva or not gnames_ptr:
        return False

    return validate_gworld(
        handle,
        module_base + rva,
        module_base=module_base,
        module_size=module_size,
        gnames_ptr=gnames_ptr,
        ue_version=ue_version,
        case_preserving=case_preserving,
    )

def get_world_name(
    handle: int,
    gworld_addr: int,
    module_base: int = 0,
    module_size: int = 0,
    gnames_ptr: int = 0,
    ue_version: str = "4.27",
    case_preserving: bool = False,
) -> str:
    uworld = read_gworld_ptr(handle, gworld_addr, module_base, module_size, gnames_ptr, ue_version, case_preserving)
    if not uworld:
        return ""

    name_idx = read_uint32(handle, uworld + UOBJECT_NAME)
    return read_fname(handle, gnames_ptr, name_idx, ue_version, case_preserving)

def get_world_class_name(
    handle: int,
    gworld_addr: int,
    module_base: int = 0,
    module_size: int = 0,
    gnames_ptr: int = 0,
    ue_version: str = "4.27",
    case_preserving: bool = False,
) -> str:
    uworld = read_gworld_ptr(handle, gworld_addr, module_base, module_size, gnames_ptr, ue_version, case_preserving)
    if not uworld:
        return ""

    class_ptr = read_uint64(handle, uworld + UOBJECT_CLASS)
    if not class_ptr:
        return ""

    class_name_idx = read_uint32(handle, class_ptr + UOBJECT_NAME)
    return read_fname(handle, gnames_ptr, class_name_idx, ue_version, case_preserving)

def get_world_info(
    handle: int,
    gworld_addr: int,
    module_base: int = 0,
    module_size: int = 0,
    gnames_ptr: int = 0,
    ue_version: str = "4.27",
    case_preserving: bool = False,
) -> Optional[dict]:
    uworld = read_gworld_ptr(handle, gworld_addr, module_base, module_size, gnames_ptr, ue_version, case_preserving)
    if not uworld:
        return None

    name_idx = read_uint32(handle, uworld + UOBJECT_NAME)
    name = read_fname(handle, gnames_ptr, name_idx, ue_version, case_preserving)

    class_ptr = read_uint64(handle, uworld + UOBJECT_CLASS)
    class_name = ""
    if class_ptr:
        cls_name_idx = read_uint32(handle, class_ptr + UOBJECT_NAME)
        class_name = read_fname(handle, gnames_ptr, cls_name_idx, ue_version, case_preserving)

    outer_ptr = read_uint64(handle, uworld + UOBJECT_OUTER)
    outer_name = ""
    if outer_ptr:
        outer_name_idx = read_uint32(handle, outer_ptr + UOBJECT_NAME)
        outer_name = read_fname(handle, gnames_ptr, outer_name_idx, ue_version, case_preserving)

    return {
        "address": uworld,
        "name": name,
        "class_name": class_name,
        "outer_name": outer_name,
    }

def _looks_like_engine_class(class_name: str) -> bool:
    return class_name in ("GameEngine", "UnrealEdEngine", "Engine") or class_name.endswith("Engine")

def find_gengine(
    handle: int,
    module_base: int,
    module_size: int,
    gnames_ptr: int,
    ue_version: str = "4.27",
    case_preserving: bool = False,
) -> int:
    if not gnames_ptr:
        return 0

    data_ranges = get_pe_rdata_data_scan_ranges(handle, module_base)
    if not data_ranges:
        return 0

    _prefetch_fname_pool(handle, gnames_ptr)

    snap_mark = snapshot_mark()
    try:
        snapshot_memory_ranges(handle, data_ranges, tolerant=True)

        for sec_start, sec_end in data_ranges:
            sec_data = read_bytes(handle, sec_start, sec_end - sec_start)
            if not sec_data or len(sec_data) < 8:
                continue

            slots_vals: List[tuple] = []
            for off in range(0, len(sec_data) - 7, 8):
                val = struct.unpack_from("<Q", sec_data, off)[0]
                if _likely_runtime_object_ptr(val):
                    slots_vals.append((sec_start + off, val))
            if not slots_vals:
                continue

            _BATCH = 5000
            all_class_ptrs: List[int] = []
            for i in range(0, len(slots_vals), _BATCH):
                batch = slots_vals[i : i + _BATCH]
                reqs = [(val + UOBJECT_CLASS, 8) for _, val in batch]
                results = scatter_read_multiple(handle, reqs)
                for raw in results:
                    if len(raw) >= 8:
                        all_class_ptrs.append(struct.unpack_from("<Q", raw)[0])
                    else:
                        all_class_ptrs.append(0)

            if len(all_class_ptrs) != len(slots_vals):
                continue

            unique_classes = list({p for p in all_class_ptrs if _plausible_heap_ptr(p)})
            class_name_map: Dict[int, str] = {}
            if unique_classes:
                name_reqs = [(cptr + UOBJECT_NAME, 4) for cptr in unique_classes]
                name_results = scatter_read_multiple(handle, name_reqs)
                for cptr, raw in zip(unique_classes, name_results):
                    if len(raw) >= 4:
                        name_idx = struct.unpack_from("<I", raw)[0]
                        try:
                            class_name_map[cptr] = read_fname(
                                handle, gnames_ptr, name_idx, ue_version, case_preserving
                            )
                        except Exception:
                            pass

            for (slot_va, _obj_ptr), class_ptr in zip(slots_vals, all_class_ptrs):
                if _looks_like_engine_class(class_name_map.get(class_ptr, "")):
                    return slot_va - module_base
    finally:
        snapshot_restore_mark(snap_mark)

    return 0
