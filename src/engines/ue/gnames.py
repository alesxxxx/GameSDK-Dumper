
from typing import Callable, Dict, List, Optional, Tuple
from collections import Counter, OrderedDict
import logging
import time as _time

logger = logging.getLogger(__name__)

from src.core.memory import (
    read_bytes,
    read_uint64,
    read_uint32,
    read_uint16,
    read_int32,
)
from src.core.pe_parser import get_pe_rdata_data_scan_ranges
from src.core.scanner import scan_pattern, resolve_rip
from src.engines.ue.signatures import GNAMES_SIGS
from src.engines.ue.offsets_override import load_game_offsets_override

_FNAME_CACHE_MAX = 120_000
_fname_cache: OrderedDict = OrderedDict()
_gnames_resolution_meta: Dict[str, object] = {}
_MODERN_FNAMEPOOL_TOKENS = {
    "None",
    "ByteProperty",
    "IntProperty",
    "BoolProperty",
    "FloatProperty",
    "DoubleProperty",
    "NameProperty",
    "StrProperty",
    "TextProperty",
    "ObjectProperty",
    "ClassProperty",
    "StructProperty",
    "ArrayProperty",
    "MapProperty",
    "SetProperty",
}

GNAMES_LAYOUT_CHUNKED_INDIRECT = -1
_gnames_entry_str_offset: Dict[int, int] = {}
_gnames_chunked_table_off: Dict[int, int] = {}

def get_last_gnames_resolution_meta() -> Dict[str, object]:
    return dict(_gnames_resolution_meta)

def _set_gnames_resolution_meta(
    *,
    address: int,
    legacy: bool,
    method: str,
    case_preserving: Optional[bool] = None,
) -> None:
    _gnames_resolution_meta.clear()
    _gnames_resolution_meta.update(
        {
            "address": address,
            "legacy": legacy,
            "method": method,
            "case_preserving": case_preserving,
        }
    )

def _plausible_heap_ptr64(value: int) -> bool:
    return 0x1000000 < value < 0x7FFFFFFFFFFF

def _plausible_heap_ptr64_strict(value: int) -> bool:
    if value <= 0x1000000 or value >= 0x7FFFFFFFFFFF:
        return False
    if (value >> 48) != 0:
        return False
    return True

def _plausible_uobject_chain_ptr64(p: int) -> bool:
    return 0x10000 < p < 0x7FFFFFFFFFFF

def _read_fname_chunked_indirect(
    handle: int,
    gnames_ptr: int,
    index: int,
    table_ptr_offset: Optional[int] = None,
) -> str:
    off = (
        table_ptr_offset
        if table_ptr_offset is not None
        else _gnames_chunked_table_off.get(gnames_ptr, 0)
    )
    chunks_base = read_uint64(handle, gnames_ptr + off)
    if not chunks_base:
        return ""

    chunk_idx = index >> 14
    within_idx = index & 0x3FFF

    chunk_ptr = read_uint64(handle, chunks_base + chunk_idx * 8)
    if not chunk_ptr:
        return ""

    entry_ptr = read_uint64(handle, chunk_ptr + within_idx * 8)
    if not entry_ptr:
        return ""

    for stroff in (0x10, 0x0C, 0x08):
        raw = read_bytes(handle, entry_ptr + stroff, 1024)
        if not raw:
            continue
        nul = raw.find(b"\x00")
        if nul >= 0:
            raw = raw[:nul]
        if not raw:
            continue
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            continue
        if not _is_valid_fname(text):
            continue
        return text
    return ""

def clear_fname_cache() -> None:
    global \
        _fnames_fully_cached, \
        _full_cache_fallback_attempts, \
        _full_cache_fallback_budget
    _fname_cache.clear()
    _full_fname_cache.clear()
    _full_cache_miss_indices.clear()
    _fname_pool_limits.clear()
    _block_ptr_cache.clear()
    _full_cache_fallback_attempts = 0
    _full_cache_fallback_budget = 4096
    _fnames_fully_cached = False

_FULL_FNAME_CACHE_MAX = 8_000_000
_full_fname_cache: OrderedDict = OrderedDict()
_fnames_fully_cached: bool = False
_full_cache_miss_indices: Dict[Tuple[int, int, Optional[bool]], bool] = {}
_full_cache_fallback_attempts: int = 0
_full_cache_fallback_budget: int = 4096
_fname_pool_limits: Dict[Tuple[int, bool], Tuple[int, int]] = {}
_block_ptr_cache: Dict[Tuple[int, int], int] = {}

def _is_index_plausible_for_pool(
    gnames_ptr: int,
    index: int,
    case_preserving: Optional[bool],
) -> bool:
    if index <= 0:
        return index == 0

    cp_modes: List[bool]
    if case_preserving is None:
        cp_modes = [False, True]
    else:
        cp_modes = [bool(case_preserving)]

    for cp_mode in cp_modes:
        limits = _fname_pool_limits.get((gnames_ptr, cp_mode))
        if not limits:
            continue
        current_block, current_cursor = limits
        block_index = (index >> 16) & 0xFFFF
        entry_offset = index & 0xFFFF

        if block_index > (current_block + 1):
            return False

        if block_index >= current_block:
            stride = 4 if cp_mode else 2
            max_entry_offset = max(0, (current_cursor + (stride - 1)) // stride)
            if entry_offset > (max_entry_offset + 128):
                return False
        return True

    return True

def cache_all_fnames(
    handle: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    legacy: bool = False,
    progress_callback: Optional[Callable[[int, int], None]] = None,
    max_snapshot_blocks: int = 1024,
    max_snapshot_seconds: float = 30.0,
) -> None:
    global \
        _fnames_fully_cached, \
        _full_cache_fallback_attempts, \
        _full_cache_fallback_budget
    _full_fname_cache.clear()
    _full_cache_miss_indices.clear()
    _full_cache_fallback_attempts = 0
    _full_cache_fallback_budget = 4096

    if legacy:
        _fnames_fully_cached = False
        _fname_pool_limits.pop((gnames_ptr, bool(case_preserving)), None)
        return

    from src.core.memory import read_bytes, USE_DRIVER

    _current_block = read_uint32(handle, gnames_ptr + 0x08)
    _current_cursor = read_uint32(handle, gnames_ptr + 0x0C)

    if not _current_block and _current_cursor == 0:
        _fnames_fully_cached = False
        _fname_pool_limits.pop((gnames_ptr, bool(case_preserving)), None)
        return

    if _current_block > 8192:
        _current_block = 8192
    _fname_pool_limits[(gnames_ptr, bool(case_preserving))] = (
        int(_current_block),
        int(_current_cursor),
    )

    _block_ptrs_raw = read_bytes(handle, gnames_ptr + 0x10, (_current_block + 1) * 8)
    if not _block_ptrs_raw or len(_block_ptrs_raw) < (_current_block + 1) * 8:
        _fnames_fully_cached = False
        return

    import struct

    _block_ptrs = list(struct.unpack_from(f"<{_current_block + 1}Q", _block_ptrs_raw))
    for bi, bp in enumerate(_block_ptrs):
        _block_ptr_cache[(gnames_ptr, bi)] = bp
    total_blocks = len(_block_ptrs)
    snapshot_blocks = total_blocks
    if max_snapshot_blocks and max_snapshot_blocks > 0:
        snapshot_blocks = min(snapshot_blocks, int(max_snapshot_blocks))
    if snapshot_blocks <= 0:
        _fnames_fully_cached = False
        return

    HEADER_SIZE = 6 if case_preserving else 2
    ALIGN = 4 if case_preserving else 2
    STRIDE = 4 if case_preserving else 2

    if USE_DRIVER:
        from src.core.driver import read_memory_kernel
        from src.core.memory import TARGET_PID

        _read_func = lambda ptr, sz: read_memory_kernel(TARGET_PID, ptr, sz)
    else:
        _read_func = lambda ptr, sz: read_bytes(handle, ptr, sz)

    if snapshot_blocks < total_blocks:
        logger.warning(
            "FNamePool snapshot capped: %d/%d blocks (max_snapshot_blocks=%d)",
            snapshot_blocks,
            total_blocks,
            max_snapshot_blocks,
        )
    logger.info(
        "Snapshotting %d FNamePool blocks (pool has %d blocks)...",
        snapshot_blocks,
        total_blocks,
    )

    def _emit_progress(current: int, total: int) -> None:
        if not progress_callback:
            return
        try:
            progress_callback(current, total)
        except Exception:
            pass

    total_names = 0
    t0 = _time.monotonic()
    last_progress_emit = t0
    processed_blocks = 0
    timed_out = False
    _emit_progress(0, snapshot_blocks)

    for block_idx, bptr in enumerate(_block_ptrs[:snapshot_blocks]):
        progress_idx = block_idx + 1
        if (
            max_snapshot_seconds
            and max_snapshot_seconds > 0
            and (_time.monotonic() - t0) >= float(max_snapshot_seconds)
        ):
            timed_out = True
            break

        processed_blocks = progress_idx
        if not bptr or bptr < 0x10000:
            now = _time.monotonic()
            if (
                progress_idx == snapshot_blocks
                or (progress_idx & 0x1F) == 0
                or (now - last_progress_emit) >= 0.25
            ):
                _emit_progress(progress_idx, snapshot_blocks)
                last_progress_emit = now
            continue

        block_size_bytes = 256 * 1024 if case_preserving else 128 * 1024
        bsize = _current_cursor + 256 if block_idx == _current_block else block_size_bytes
        bdata = _read_func(bptr, bsize)
        if not bdata:
            now = _time.monotonic()
            if (
                progress_idx == snapshot_blocks
                or (progress_idx & 0x1F) == 0
                or (now - last_progress_emit) >= 0.25
            ):
                _emit_progress(progress_idx, snapshot_blocks)
                last_progress_emit = now
            continue

        cursor = 0
        bdata_len = len(bdata)
        _KERNEL_CHUNK = 65488

        while cursor + HEADER_SIZE <= bdata_len:
            if case_preserving:
                header_word = struct.unpack_from("<H", bdata, cursor + 4)[0]
                name_len = header_word >> 1
            else:
                header_word = struct.unpack_from("<H", bdata, cursor)[0]
                name_len = header_word >> 6

            if name_len == 0:
                next_chunk_start = ((cursor // _KERNEL_CHUNK) + 1) * _KERNEL_CHUNK
                if next_chunk_start + HEADER_SIZE <= bdata_len:
                    cursor = next_chunk_start
                    continue
                break

            if name_len > 1024:
                cursor += ALIGN
                continue

            if cursor + HEADER_SIZE + name_len <= bdata_len:
                raw_str = bdata[cursor + HEADER_SIZE : cursor + HEADER_SIZE + name_len]
                try:
                    text = raw_str.decode("utf-8", errors="ignore").split("\x00")[0]
                    if len(text) > 0:
                        entry_offset = cursor // STRIDE
                        comp_idx = (block_idx << 16) | entry_offset
                        _full_fname_cache[comp_idx] = text
                        total_names += 1
                except Exception:
                    pass

            entry_total = HEADER_SIZE + name_len
            entry_total = (entry_total + ALIGN - 1) & ~(ALIGN - 1)
            cursor += entry_total

        now = _time.monotonic()
        if (
            progress_idx == snapshot_blocks
            or (progress_idx & 0x1F) == 0
            or (now - last_progress_emit) >= 0.25
        ):
            _emit_progress(progress_idx, snapshot_blocks)
            last_progress_emit = now

    _emit_progress(processed_blocks, snapshot_blocks)

    while len(_full_fname_cache) > _FULL_FNAME_CACHE_MAX:
        _full_fname_cache.popitem(last=False)

    elapsed = _time.monotonic() - t0
    if timed_out:
        logger.warning(
            "FNamePool snapshot timed out at block %d/%d after %.1fs; using partial cache",
            processed_blocks,
            snapshot_blocks,
            elapsed,
        )

    if total_names >= 128:
        _fnames_fully_cached = True
        _full_cache_fallback_budget = max(4096, min(100_000, total_names // 2))
        if processed_blocks < total_blocks:
            _full_cache_fallback_budget = max(_full_cache_fallback_budget, 200_000)
        logger.info(
            "Successfully cached %d FNames from %d/%d blocks in %.2fs",
            total_names,
            processed_blocks,
            total_blocks,
            elapsed,
        )
    else:
        _fnames_fully_cached = False
        logger.warning(
            "FNamePool snapshot too small (%d names from %d/%d blocks) at 0x%X; keeping live read fallback enabled",
            total_names,
            processed_blocks,
            total_blocks,
            gnames_ptr,
        )

def _is_valid_ue_identifier_gnames_scan(text: str) -> bool:
    if len(text) < 2 or len(text) > 64:
        return False
    try:
        text.encode("ascii")
    except UnicodeEncodeError:
        return False
    return all(32 <= ord(c) <= 126 for c in text)

def _try_tname_entry_string_scan(
    handle: int,
    gnames_candidate: int,
    index: int,
    debug_once: Optional[dict] = None,
) -> Tuple[str, int]:
    data = read_uint64(handle, gnames_candidate + 0x0)
    if not data:
        return "", -1

    entry_ptr = read_uint64(handle, data + index * 8)
    if not entry_ptr:
        return "", -1

    for stroff in (0x10, 0x08, 0x0C, 0x14):
        raw = read_bytes(handle, entry_ptr + stroff, 1024)
        if not raw:
            continue

        nul = raw.find(b"\x00")
        if nul >= 0:
            raw = raw[:nul]
        if not raw:
            continue

        try:
            text = raw.decode("ascii", errors="strict")
        except UnicodeDecodeError:
            continue

        if not _is_valid_ue_identifier_gnames_scan(text):
            continue

        if debug_once is not None and not debug_once.get("printed"):
            logger.debug(f"FNameEntry string hit at offset 0x{stroff:X}: {text!r}")
            debug_once["printed"] = True

        return text, stroff

    return "", -1

_NONE_ENTRY_PATTERN = b"None\x00"
_NONE_SCAN_MAX_HITS = 400

def _section_align8(addr: int, sec_start: int) -> int:
    a = max(addr, sec_start)
    if a % 8:
        a += 8 - (a % 8)
    return a

def _collect_gnames_anchor_strings(
    handle: int,
    ranges: List[Tuple[int, int]],
) -> List[str]:
    from src.core.debug import dbg
    from src.core.memory import prefetch_memory_pages, scatter_read_multiple
    import time as _time

    _t0 = _time.monotonic()

    heap_ptrs: List[int] = []
    max_candidates = 50_000
    for start, end in ranges:
        addr = _section_align8(start, start)
        while addr < end:
            heap_ptr = read_uint64(handle, addr)
            if _plausible_heap_ptr64_strict(heap_ptr):
                heap_ptrs.append(heap_ptr)
                if len(heap_ptrs) >= max_candidates:
                    break
            addr += 8
        if len(heap_ptrs) >= max_candidates:
            break

    dbg(
        "GNames anchor: %d plausible heap ptrs collected in %.1fs",
        len(heap_ptrs),
        _time.monotonic() - _t0,
    )

    if not heap_ptrs:
        return []

    seen: set = set()
    out: List[str] = []
    BATCH_SIZE = 500
    total_probed = 0
    for batch_start in range(0, len(heap_ptrs), BATCH_SIZE):
        batch = heap_ptrs[batch_start : batch_start + BATCH_SIZE]
        requests = [(ptr + 0x10, 32) for ptr in batch]
        results = scatter_read_multiple(handle, requests)
        total_probed += len(batch)

        for raw in results:
            if not raw or len(raw) < 2:
                continue
            nul = raw.find(b"\x00")
            if nul <= 0:
                continue
            try:
                text = raw[:nul].decode("ascii", errors="strict")
            except UnicodeDecodeError:
                continue
            if not _is_valid_ue_identifier_gnames_scan(text):
                continue
            if text not in seen:
                seen.add(text)
                out.append(text)
                if len(out) >= 20:
                    dbg(
                        "GNames anchor: found 20 anchors in %d probes (%.1fs)",
                        total_probed,
                        _time.monotonic() - _t0,
                    )
                    return out

    dbg(
        "GNames anchor: done, %d anchors found in %d probes (%.1fs)",
        len(out),
        total_probed,
        _time.monotonic() - _t0,
    )
    return out

def _module_find_pattern(
    handle: int,
    module_base: int,
    module_size: int,
    pattern: bytes,
) -> List[int]:
    hits: List[int] = []
    if module_size <= 0 or not pattern:
        return hits
    overlap = len(pattern) - 1
    pos = 0
    chunk = 4 * 1024 * 1024
    last_bucket = -1
    while pos < module_size:
        bucket = pos // (2 * 1024 * 1024)
        if bucket != last_bucket:
            last_bucket = bucket
            logger.debug(
                f"pattern scan: {pos // (1024 * 1024)}MB/"
                f"{module_size // (1024 * 1024)}MB"
            )
        n = min(chunk, module_size - pos)
        buf = read_bytes(handle, module_base + pos, n)
        if not buf:
            pos += max(1, n - overlap)
            continue
        i = 0
        while True:
            j = buf.find(pattern, i)
            if j < 0:
                break
            hits.append(module_base + pos + j)
            i = j + 1
        pos += max(1, n - overlap)
    return hits

def _read_fnameentry_string_at(handle: int, entry_ptr: int, stroff: int) -> str:
    if not entry_ptr:
        return ""
    raw = read_bytes(handle, entry_ptr + stroff, 1024)
    if not raw:
        return ""
    nul = raw.find(b"\x00")
    if nul >= 0:
        raw = raw[:nul]
    if not raw:
        return ""
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return ""
    if not _is_valid_fname(text):
        return ""
    return text

def _read_fnameentry_string_at_10(handle: int, entry_ptr: int) -> str:
    return _read_fnameentry_string_at(handle, entry_ptr, 0x10)

def _read_ue_identifier_gnames_scan_at(
    handle: int,
    entry_ptr: int,
    stroff: int = 0x10,
) -> str:
    if not entry_ptr:
        return ""
    raw = read_bytes(handle, entry_ptr + stroff, 1024)
    if not raw:
        return ""
    nul = raw.find(b"\x00")
    if nul <= 0:
        return ""
    try:
        text = raw[:nul].decode("ascii", errors="strict")
    except UnicodeDecodeError:
        return ""
    if not _is_valid_ue_identifier_gnames_scan(text):
        return ""
    return text

def _format_p3_raw8_dump(raw: bytes) -> str:
    if not raw:
        return "<empty>"
    if len(raw) < 8:
        return f"len={len(raw)} {raw.hex()}"
    chunk = raw[:8]
    hx = chunk.hex()
    nul = chunk.find(b"\x00")
    end = nul if nul >= 0 else 8
    asc = chunk[:end].decode("ascii", errors="replace").strip()
    return f"{hx} ({asc!r})"

def _fnamepool_token_score(names: List[str]) -> int:
    return sum(1 for name in names if name in _MODERN_FNAMEPOOL_TOKENS)

def _find_modern_gnames_without_gobjects(
    handle: int,
    ranges: List[Tuple[int, int]],
    ue_version: str,
) -> Tuple[int, Optional[bool], int]:
    import struct as _struct

    best_addr = 0
    best_cp: Optional[bool] = None
    best_score = -1
    deadline = _time.monotonic() + 15.0
    candidates_checked = 0

    for start, end in ranges:
        if _time.monotonic() > deadline:
            break
        data = read_bytes(handle, start, end - start)
        if len(data) < 0x18:
            continue

        max_rel = len(data) - 0x18
        for rel in range(0, max_rel + 1, 8):
            if (candidates_checked & 0x1FF) == 0 and _time.monotonic() > deadline:
                break
            candidates_checked += 1

            current_block = _struct.unpack_from("<I", data, rel + 0x08)[0]
            current_cursor = _struct.unpack_from("<I", data, rel + 0x0C)[0]
            block0 = _struct.unpack_from("<Q", data, rel + 0x10)[0]
            if not _plausible_heap_ptr64(block0):
                continue
            if current_block > 8192 or current_cursor > 0x40000:
                continue
            if current_block == 0 and current_cursor == 0:
                continue

            candidate = start + rel
            is_valid, cp = validate_gnames(handle, candidate, ue_version)
            if not is_valid or cp is None:
                continue

            names = _walk_block_sequential(handle, block0, cp, max_entries=12)
            if len(names) < 5 or names[0] != "None":
                continue

            score = _fnamepool_token_score(names) * 8 + len(set(names))
            if score > best_score:
                best_addr = candidate
                best_cp = cp
                best_score = score

    return best_addr, best_cp, best_score

def _find_gnames_without_gobjects(
    handle: int,
    module_base: int,
    module_size: int,
    ue_version: str,
) -> Tuple[int, bool, str, Optional[bool]]:
    ranges = get_pe_rdata_data_scan_ranges(handle, module_base)
    if not ranges:
        return 0, False, "none", None

    from src.core.memory import (
        snapshot_mark,
        snapshot_memory_ranges,
        snapshot_restore_mark,
    )

    snap_mark = snapshot_mark()
    try:
        snapshot_memory_ranges(handle, ranges, tolerant=True)

        modern_addr, modern_cp, modern_score = _find_modern_gnames_without_gobjects(
            handle,
            ranges,
            ue_version,
        )
        if modern_addr and modern_score >= 2:
            return modern_addr, False, "names_first_modern", modern_cp

        legacy_addr = _find_gnames_from_gobjects_inner(
            handle, module_base, module_size, ranges
        )
        if legacy_addr:
            method = (
                "names_first_legacy_chunked"
                if _gnames_entry_str_offset.get(legacy_addr)
                == GNAMES_LAYOUT_CHUNKED_INDIRECT
                else "names_first_legacy_flat"
            )
            return legacy_addr, True, method, None
    finally:
        snapshot_restore_mark(snap_mark)

    return 0, False, "none", None

def find_gnames_from_gobjects(
    handle: int,
    gobjects_ptr: int,
    base: int,
    _size: int,
    item_size: int = 24,
) -> int:
    _ = (gobjects_ptr, item_size)

    ranges = get_pe_rdata_data_scan_ranges(handle, base)
    logger.debug(f"scan ranges: {ranges}")
    if not ranges:
        logger.debug("no scan ranges found, aborting")
        return 0

    from src.core.memory import (
        snapshot_mark,
        snapshot_memory_ranges,
        snapshot_restore_mark,
    )

    snap_mark = snapshot_mark()
    try:
        stats = snapshot_memory_ranges(handle, ranges, tolerant=True)
        for stat in stats:
            logger.debug(
                f"snapshotting section 0x{stat['start']:X}..0x{stat['end']:X} "
                f"({stat['size'] // 1024} KB, {stat['nonzero_pct']}% non-zero)"
            )
        return _find_gnames_from_gobjects_inner(handle, base, _size, ranges)
    finally:
        snapshot_restore_mark(snap_mark)

def _find_gnames_from_gobjects_inner(handle, base, _size, ranges):
    from src.core.debug import dbg
    from src.core.memory import prefetch_memory_pages, scatter_read_multiple
    import time as _time
    import struct as _struct

    _total_start = _time.monotonic()
    PHASE2_TIMEOUT = 45.0
    PHASE3_TIMEOUT = 45.0
    TOTAL_TIMEOUT = 120.0

    def _phase_timed_out(phase_start: float, phase_timeout: float) -> bool:
        now = _time.monotonic()
        return (
            (now - phase_start) > phase_timeout
            or (now - _total_start) > TOTAL_TIMEOUT
        )

    def _page_align(addr: int) -> int:
        return addr & ~0xFFF

    def _pages_for_span(addr: int, size: int) -> List[int]:
        if not addr or size <= 0:
            return []
        start = _page_align(addr)
        end = _page_align(addr + size - 1)
        if start == end:
            return [start]
        return [start, end]

    def _read_phase3_entry_text(
        entry_ptr: int,
        stroff: int,
        *,
        max_size: int,
        ascii_only: bool,
        validator,
    ) -> str:
        if not entry_ptr:
            return ""
        raw = read_bytes(handle, entry_ptr + stroff, max_size)
        if not raw:
            return ""
        nul = raw.find(b"\x00")
        if nul <= 0:
            return ""
        encoding = "ascii" if ascii_only else "utf-8"
        try:
            text = raw[:nul].decode(encoding, errors="strict")
        except UnicodeDecodeError:
            return ""
        if not validator(text):
            return ""
        return text

    anchor_strings = _collect_gnames_anchor_strings(handle, ranges)
    anchor_set = set(anchor_strings)
    dbg(
        "GNames brute: anchor strings collected: %d (%.1fs)",
        len(anchor_strings),
        _time.monotonic() - _total_start,
    )
    logger.debug(f"GNames string-anchor collected {len(anchor_strings)} identifiers")

    if len(anchor_set) >= 3:
        _t2 = _time.monotonic()
        _phase2_start = _time.monotonic()
        candidates: List[Tuple[int, int]] = []
        for start, end in ranges:
            addr = _section_align8(start, start)
            while addr < end:
                data_ptr = read_uint64(handle, addr)
                if _plausible_heap_ptr64(data_ptr):
                    candidates.append((addr, data_ptr))
                addr += 8

        dbg(
            "GNames brute Phase 2: %d plausible heap ptrs from %d KB sections (%.1fs)",
            len(candidates),
            sum((e - s) for s, e in ranges) // 1024,
            _time.monotonic() - _t2,
        )

        BATCH = 500
        none_candidates: List[Tuple[int, int]] = []
        total_batched = 0
        for bi in range(0, len(candidates), BATCH):
            if _phase_timed_out(_phase2_start, PHASE2_TIMEOUT):
                dbg(
                    "GNames brute Phase 2: TIMEOUT after %.1fs total, %d candidates checked",
                    _time.monotonic() - _total_start,
                    total_batched,
                )
                break
            batch = candidates[bi : bi + BATCH]
            requests = [(data_ptr, 8) for _, data_ptr in batch]
            results = scatter_read_multiple(handle, requests)
            total_batched += len(batch)

            entry_ptrs = []
            entry_indices = []
            for j, raw in enumerate(results):
                if raw and len(raw) >= 8:
                    eptr = _struct.unpack_from("<Q", raw)[0]
                    if _plausible_heap_ptr64(eptr):
                        entry_ptrs.append(eptr)
                        entry_indices.append(j)

            if not entry_ptrs:
                continue

            str_requests = [(eptr + 0x10, 32) for eptr in entry_ptrs]
            str_results = scatter_read_multiple(handle, str_requests)

            for k, raw in enumerate(str_results):
                if not raw or len(raw) < 5:
                    continue
                nul = raw.find(b"\x00")
                if nul <= 0:
                    continue
                try:
                    text = raw[:nul].decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    continue
                if text == "None":
                    j = entry_indices[k]
                    module_addr, data_ptr = batch[j]
                    none_candidates.append((module_addr, data_ptr))

        dbg(
            "GNames brute Phase 2: %d 'None' candidates found from %d total (%.1fs)",
            len(none_candidates),
            total_batched,
            _time.monotonic() - _total_start,
        )

        if none_candidates:
            VALIDATE_INDICES = tuple(range(1, 17))
            entry_ptr_requests = []
            owners = []
            for addr, data_ptr in none_candidates:
                for idx in VALIDATE_INDICES:
                    entry_ptr_requests.append((data_ptr + idx * 8, 8))
                    owners.append((addr, idx))

            entry_ptr_results = scatter_read_multiple(handle, entry_ptr_requests)
            string_requests = []
            string_owners = []
            for (addr, idx), raw in zip(owners, entry_ptr_results):
                if not raw or len(raw) < 8:
                    continue
                entry_ptr = _struct.unpack_from("<Q", raw)[0]
                if not _plausible_heap_ptr64(entry_ptr):
                    continue
                string_requests.append((entry_ptr + 0x10, 32))
                string_owners.append((addr, idx))

            found_by_addr: Dict[int, set] = {}
            for (addr, _idx), raw in zip(
                string_owners, scatter_read_multiple(handle, string_requests)
            ):
                if not raw or len(raw) < 2:
                    continue
                nul = raw.find(b"\x00")
                if nul <= 0:
                    continue
                try:
                    text = raw[:nul].decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    continue
                if text in anchor_set:
                    found_by_addr.setdefault(addr, set()).add(text)

            for addr, _data_ptr in none_candidates:
                if _phase_timed_out(_phase2_start, PHASE2_TIMEOUT):
                    dbg("GNames brute Phase 2 validation: TIMEOUT")
                    return 0
                found_labels = found_by_addr.get(addr, set())
                if len(found_labels) >= 3:
                    _gnames_entry_str_offset[addr] = 0x10
                    dbg(
                        "GNames brute Phase 2 ACCEPTED 0x%X (total time %.1fs)",
                        addr,
                        _time.monotonic() - _total_start,
                    )
                    logger.debug(f"GNames string-anchor ACCEPTED 0x{addr:X}")
                    return addr

        for addr, _data_ptr in none_candidates:
            if _phase_timed_out(_phase2_start, PHASE2_TIMEOUT):
                dbg("GNames brute Phase 2 validation: TIMEOUT")
                return 0
            found_labels: set = set()
            for i in range(1, 51):
                s = _read_tname_entry_array_str(handle, addr, i)
                if s and s in anchor_set:
                    found_labels.add(s)
                if len(found_labels) >= 3:
                    break
            if len(found_labels) >= 3:
                _gnames_entry_str_offset[addr] = 0x10
                dbg(
                    "GNames brute Phase 2 ACCEPTED 0x%X (total time %.1fs)",
                    addr,
                    _time.monotonic() - _total_start,
                )
                logger.debug(f"GNames string-anchor ACCEPTED 0x{addr:X}")
                return addr

        dbg(
            "GNames brute Phase 2 done: %d total candidates, %d None matches, no accept (%.1fs)",
            len(candidates),
            len(none_candidates),
            _time.monotonic() - _total_start,
        )

    dbg("GNames brute: Phase 3 (.rdata -> heap reverse map)...")
    logger.debug("GNames string-anchor failed, Phase 3 (.rdata → heap reverse map)...")
    if _size <= 0:
        return 0

    _phase3_start = _time.monotonic()
    _p3_heap_ptr_max = 0x0000700000000000
    rev: Dict[int, List[int]] = {}
    max_rev_entries = 100_000
    for start, end in ranges:
        if _phase_timed_out(_phase3_start, PHASE3_TIMEOUT):
            dbg("GNames brute Phase 3 build map: TIMEOUT")
            return 0
        a = _section_align8(start, start)
        while a < end:
            v = read_uint64(handle, a)
            if _plausible_heap_ptr64_strict(v) and v < _p3_heap_ptr_max:
                rev.setdefault(v, []).append(a)
                if len(rev) >= max_rev_entries:
                    break
            a += 8
        if len(rev) >= max_rev_entries:
            break

    logger.debug(f"Phase 3 reverse dict built: {len(rev)} heap pointers (filtered)")

    phase3_candidates = list(rev.keys())
    phase3_first_none_reported = False
    p3_raw_dbg_printed = 0
    PHASE3_BATCH = 512
    for batch_start in range(0, len(phase3_candidates), PHASE3_BATCH):
        if _phase_timed_out(_phase3_start, PHASE3_TIMEOUT):
            dbg("GNames brute Phase 3 search: TIMEOUT")
            return 0

        batch = phase3_candidates[batch_start : batch_start + PHASE3_BATCH]
        array_pages = set()
        for array_base_candidate in batch:
            array_pages.update(_pages_for_span(array_base_candidate, 24))
        if array_pages:
            prefetch_memory_pages(handle, list(array_pages), tolerant=True)

        stage3 = []
        entry_pages = set()
        for array_base_candidate in batch:
            e0 = read_uint64(handle, array_base_candidate)
            if not _plausible_heap_ptr64(e0) or e0 >= _p3_heap_ptr_max:
                continue
            e1 = read_uint64(handle, array_base_candidate + 8)
            e2 = read_uint64(handle, array_base_candidate + 16)
            if not (_plausible_heap_ptr64(e1) and _plausible_heap_ptr64(e2)):
                continue
            stage3.append((array_base_candidate, e0, e1, e2))
            for entry_ptr in (e0, e1, e2):
                for off, size in ((0x08, 8), (0x0C, 8), (0x10, 32)):
                    entry_pages.update(_pages_for_span(entry_ptr + off, size))

        if entry_pages:
            logger.debug(
                f"Phase 3 batch prefetch: {len(array_pages)} array pages, "
                f"{len(entry_pages)} entry pages for {len(stage3)} candidates"
            )
            prefetch_memory_pages(handle, list(entry_pages), tolerant=True)

        for array_base_candidate, e0, e1, e2 in stage3:
            if p3_raw_dbg_printed < 10:
                r08 = read_bytes(handle, e0 + 0x08, 8)
                r0c = read_bytes(handle, e0 + 0x0C, 8)
                r10 = read_bytes(handle, e0 + 0x10, 8)
                logger.debug(
                    f"P3 cand 0x{array_base_candidate:X} â†’ e0=0x{e0:X} "
                    f"raw@e0+0x08={_format_p3_raw8_dump(r08)} "
                    f"raw@e0+0x0C={_format_p3_raw8_dump(r0c)} "
                    f"raw@e0+0x10={_format_p3_raw8_dump(r10)}"
                )
                p3_raw_dbg_printed += 1

            stroff: Optional[int] = None
            for off in (0x08, 0x0C, 0x10):
                s0 = _read_phase3_entry_text(
                    e0,
                    off,
                    max_size=32,
                    ascii_only=False,
                    validator=_is_valid_fname,
                )
                if s0 == "None":
                    stroff = off
                    break
            if stroff is None:
                continue
            if not phase3_first_none_reported:
                logger.debug(
                    f"Phase 3 first None match: array_base=0x{array_base_candidate:X} "
                    f"stroff=0x{stroff:X} e0=0x{e0:X}"
                )
                phase3_first_none_reported = True

            b1 = _read_phase3_entry_text(
                e1,
                stroff,
                max_size=32,
                ascii_only=True,
                validator=_is_valid_ue_identifier_gnames_scan,
            )
            b2 = _read_phase3_entry_text(
                e2,
                stroff,
                max_size=32,
                ascii_only=True,
                validator=_is_valid_ue_identifier_gnames_scan,
            )
            if not (b1 and b2):
                continue
            for t in rev[array_base_candidate]:
                _gnames_entry_str_offset[t] = stroff
                logger.debug(
                    f"Phase 3 ACCEPTED 0x{t:X} via array_base=0x{array_base_candidate:X}"
                )
                return t

    return 0

    phase3_first_none_reported = False
    p3_raw_dbg_printed = 0
    for array_base_candidate in rev.keys():
        if _time.monotonic() - _phase_start > PHASE_TIMEOUT:
            dbg("GNames brute Phase 3 search: TIMEOUT")
            return 0

        e0 = read_uint64(handle, array_base_candidate)
        if not _plausible_heap_ptr64(e0):
            continue
        if e0 >= _p3_heap_ptr_max:
            continue
        if p3_raw_dbg_printed < 10:
            r08 = read_bytes(handle, e0 + 0x08, 8)
            r0c = read_bytes(handle, e0 + 0x0C, 8)
            r10 = read_bytes(handle, e0 + 0x10, 8)
            logger.debug(
                f"P3 cand 0x{array_base_candidate:X} → e0=0x{e0:X} "
                f"raw@e0+0x08={_format_p3_raw8_dump(r08)} "
                f"raw@e0+0x0C={_format_p3_raw8_dump(r0c)} "
                f"raw@e0+0x10={_format_p3_raw8_dump(r10)}"
            )
            p3_raw_dbg_printed += 1
        stroff: Optional[int] = None
        for off in (0x08, 0x0C, 0x10):
            s0 = _read_fnameentry_string_at(handle, e0, off)
            if s0 == "None":
                stroff = off
                break
        if stroff is None:
            continue
        if not phase3_first_none_reported:
            logger.debug(
                f"Phase 3 first None match: array_base=0x{array_base_candidate:X} "
                f"stroff=0x{stroff:X} e0=0x{e0:X}"
            )
            phase3_first_none_reported = True
        e1 = read_uint64(handle, array_base_candidate + 8)
        e2 = read_uint64(handle, array_base_candidate + 16)
        if not (_plausible_heap_ptr64(e1) and _plausible_heap_ptr64(e2)):
            continue
        b1 = _read_ue_identifier_gnames_scan_at(handle, e1, stroff)
        b2 = _read_ue_identifier_gnames_scan_at(handle, e2, stroff)
        if not (b1 and b2):
            continue
        for t in rev[array_base_candidate]:
            _gnames_entry_str_offset[t] = stroff
            logger.debug(
                f"Phase 3 ACCEPTED 0x{t:X} via array_base=0x{array_base_candidate:X}"
            )
            return t

    return 0

def _run_gnames_names_first_fallback(
    handle: int,
    module_base: int,
    module_size: int,
    ue_version: str,
    *,
    diag=None,
    confidence_reason: str,
) -> Tuple[int, bool]:
    from src.core.debug import dbg

    fb, fb_legacy, fb_method, fb_cp = _find_gnames_without_gobjects(
        handle,
        module_base,
        module_size,
        ue_version,
    )
    if not fb:
        dbg("find_gnames: names-first fallback also failed")
        return 0, False

    dbg(
        "find_gnames: names-first fallback found GNames at 0x%X (+0x%X)",
        fb,
        fb - module_base,
    )
    _set_gnames_resolution_meta(
        address=fb,
        legacy=fb_legacy,
        method=fb_method,
        case_preserving=fb_cp,
    )
    if diag:
        diag.passed(
            "GNames",
            "names_first_fallback",
            f"{fb_method} at +0x{fb - module_base:X}",
        )
        diag.set_confidence(
            "GNames",
            0.75 if not fb_legacy else 0.65,
            confidence_reason,
        )
    return fb, fb_legacy

def _validate_gnames_candidate(
    handle: int,
    candidate: int,
    module_base: int,
    module_size: int,
    ue_version: str,
    is_legacy_hint: bool,
) -> Optional[Tuple[int, bool, Optional[bool], str]]:
    from src.core.debug import dbg

    best = candidate
    dbg("find_gnames: validating candidate 0x%X...", best)
    val0 = read_uint64(handle, best)
    if module_base <= val0 < module_base + module_size:
        for member_off in range(0x08, 0x80, 0x08):
            nested_candidate = read_uint64(handle, best + member_off)
            if not _plausible_heap_ptr64(nested_candidate):
                continue
            objects = read_uint64(handle, nested_candidate)
            if not _plausible_heap_ptr64(objects):
                continue
            chunk0 = read_uint64(handle, objects)
            if not _plausible_heap_ptr64(chunk0):
                continue
            entry0 = read_uint64(handle, chunk0)
            if not _plausible_heap_ptr64(entry0):
                continue
            raw = read_bytes(handle, entry0 + 0x08, 8)
            if raw and raw[:5] == b"None\x00":
                logger.debug(
                    f"GNames singleton unwrap: best=0x{best:X} -> candidate=0x{nested_candidate:X} at +0x{member_off:X}"
                )
                best = nested_candidate
                _gnames_entry_str_offset[best] = 0x08
                break

    leg0 = _read_tname_entry_array_str(handle, best, 0)
    mod0 = _read_fname_modern(handle, best, 0, None)

    v0 = read_uint64(handle, best + 0x00)
    v1 = read_uint64(handle, best + 0x08)
    v2 = read_uint64(handle, best + 0x10)
    v3 = read_uint64(handle, best + 0x18)
    v4 = read_uint64(handle, best + 0x20)
    logger.debug(
        f"AOB GNames candidate 0x{best:X} raw: +0x00={v0:016X} +0x08={v1:016X} "
        f"+0x10={v2:016X} +0x18={v3:016X} +0x20={v4:016X}"
    )

    mod_hi = module_base + module_size
    for label, arr_base in (("v0", v0), ("v1", v1)):
        if not (module_base <= arr_base < mod_hi):
            continue
        entry0 = read_uint64(handle, arr_base)
        s08 = _read_fnameentry_string_at(handle, entry0, 0x08)
        s10 = _read_fnameentry_string_at(handle, entry0, 0x10)
        logger.debug(
            f"module-internal array probe: {label}=0x{arr_base:X} entry0=0x{entry0:X} "
            f"str08={s08!r} str10={s10!r}"
        )
        if not (0x10000 < entry0 < 0x7FFFFFFFFFFF):
            continue
        stroff_flat: Optional[int] = None
        for off in (0x08, 0x10, 0x0C):
            if _read_fnameentry_string_at(handle, entry0, off) == "None":
                stroff_flat = off
                break
        if stroff_flat is not None:
            _gnames_entry_str_offset[best] = stroff_flat
            return best, True, None, "signature_probe_legacy_flat"

    for table_off, chunks_base in ((0, v0), (8, v1)):
        if not _plausible_heap_ptr64(chunks_base):
            continue
        for idx in (0, 1, 2, 3):
            chunk_idx = idx >> 14
            within_idx = idx & 0x3FFF
            chunk_ptr = read_uint64(handle, chunks_base + chunk_idx * 8)
            entry_ptr = (
                read_uint64(handle, chunk_ptr + within_idx * 8) if chunk_ptr else 0
            )
            for stroff in (0x10, 0x0C, 0x08):
                raw = read_bytes(handle, entry_ptr + stroff, 32) if entry_ptr else b""
                txt = (
                    raw.split(b"\x00")[0].decode("utf-8", errors="replace")
                    if raw
                    else ""
                )
                logger.debug(
                    f"chunked probe table+0x{table_off:X} idx={idx} chunk_ptr={hex(chunk_ptr)} "
                    f"entry_ptr={hex(entry_ptr)} stroff=0x{stroff:X} â†’ {repr(txt)}"
                )

    if _plausible_heap_ptr64(v0) or _plausible_heap_ptr64(v1):
        for table_off in (0, 8):
            if not read_uint64(handle, best + table_off):
                continue
            c0 = _read_fname_chunked_indirect(handle, best, 0, table_off)
            c1 = _read_fname_chunked_indirect(handle, best, 1, table_off)
            if c0 == "None" and c1 and _is_valid_fname(c1):
                _gnames_entry_str_offset[best] = GNAMES_LAYOUT_CHUNKED_INDIRECT
                _gnames_chunked_table_off[best] = table_off
                logger.debug(
                    f"GNames chunked indirect ACCEPTED table_ptr+0x{table_off:X}"
                )
                return best, True, None, "signature_probe_legacy_chunked"

    if leg0 == "" and mod0 == "":
        dbg(
            "find_gnames: candidate 0x%X rejected by layout probe (leg0='' mod0='')",
            best,
        )
        return None

    if leg0 == "None" and mod0 != "None":
        legacy_names = True
    elif mod0 == "None" and leg0 != "None":
        legacy_names = False
    else:
        legacy_names = is_legacy_hint

    valid_gnames, detected_cp = validate_gnames(handle, best, ue_version)
    if not valid_gnames:
        dbg("find_gnames: candidate 0x%X failed sequential validation", best)
        return None

    return (
        best,
        legacy_names,
        None if legacy_names else detected_cp,
        "signature_probe_modern" if not legacy_names else "signature_probe_legacy",
    )

def _shadowed_find_gnames_impl(
    handle: int,
    module_base: int,
    module_size: int,
    ue_version: str = "4.27",
    gobjects_hint: int = 0,
    gobjects_item_size: int = 24,
    process_name: Optional[str] = None,
    override_rva: Optional[int] = None,
    diag=None,
) -> Tuple[int, bool]:
    _gnames_resolution_meta.clear()
    override = load_game_offsets_override(process_name)
    if override is not None:
        ogn, _ogo, _ogw, _stride, legacy = override
        gnames_abs = module_base + ogn
        if legacy:
            logger.debug(f"GNames raw layout at 0x{gnames_abs:X}:")
            for _i in range(6):
                _v = read_uint64(handle, gnames_abs + _i * 8)
                logger.debug(f"  +0x{_i * 8:02X}: 0x{_v:016X}")

            objects_ptr = read_uint64(handle, gnames_abs)
            logger.debug(f"Objects (chunk table) = 0x{objects_ptr:X}")

            chunk0 = read_uint64(handle, objects_ptr) if objects_ptr else 0
            logger.debug(f"chunk0 ptr = 0x{chunk0:X}")

            if chunk0:
                for _ei in range(4):
                    _eptr = read_uint64(handle, chunk0 + _ei * 8)
                    logger.debug(f"chunk0[{_ei}] (FNameEntry*) = 0x{_eptr:X}")
                    if _eptr:
                        _raw = read_bytes(handle, _eptr, 32)
                        logger.debug(f"  bytes: {_raw.hex() if _raw else '<fail>'}")
                        for _off in (0x00, 0x04, 0x08, 0x0C, 0x10):
                            _s = read_bytes(handle, _eptr + _off, 16)
                            if _s:
                                _text = _s.split(b"\x00")[0]
                                try:
                                    logger.debug(
                                        f"  +0x{_off:02X}: {_text.decode('ascii')!r}"
                                    )
                                except Exception:
                                    logger.debug(f"  +0x{_off:02X}: {_s[:8].hex()}")

            _detected = False
            for table_off in (0, 8):
                c0 = _read_fname_chunked_indirect(handle, gnames_abs, 0, table_off)
                c1 = _read_fname_chunked_indirect(handle, gnames_abs, 1, table_off)
                logger.debug(
                    f"chunked probe table+0x{table_off:X}: idx0={c0!r} idx1={c1!r}"
                )
                if c0 == "None" and c1 and _is_valid_fname(c1):
                    _gnames_entry_str_offset[gnames_abs] = (
                        GNAMES_LAYOUT_CHUNKED_INDIRECT
                    )
                    _gnames_chunked_table_off[gnames_abs] = table_off
                    logger.debug(
                        f"GNames override: CHUNKED INDIRECT accepted "
                        f"(table_off=0x{table_off:X})"
                    )
                    _detected = True
                    break

            if not _detected:
                data_ptr = read_uint64(handle, gnames_abs)
                entry0 = read_uint64(handle, data_ptr) if data_ptr else 0
                found_stroff = None
                if entry0:
                    for probe_off in (0x08, 0x0C, 0x10):
                        s = _read_fnameentry_string_at(handle, entry0, probe_off)
                        if s == "None":
                            found_stroff = probe_off
                            break
                if found_stroff is not None:
                    _gnames_entry_str_offset[gnames_abs] = found_stroff
                    logger.debug(
                        f"GNames override: flat TArray stroff=0x{found_stroff:X}"
                    )
                else:
                    _gnames_entry_str_offset[gnames_abs] = 0x10
                    logger.debug(
                        f"GNames override: no layout detected "
                        f"(data_ptr=0x{data_ptr:X} entry0=0x{entry0:X}), "
                        f"defaulting stroff=0x10"
                    )
        logger.debug(
            f"GNames from OffsetsInfo.json: +0x{ogn:X} legacy={legacy} "
            f"(skipping AOB/fallback)"
        )
        _set_gnames_resolution_meta(
            address=gnames_abs,
            legacy=legacy,
            method="offsets_override",
            case_preserving=None,
        )
        return gnames_abs, legacy

    from src.core.debug import dbg
    import time as _time

    _t0 = _time.monotonic()

    major_minor = _parse_version(ue_version)
    is_legacy = major_minor is not None and major_minor < (4, 23)
    is_pre_419 = major_minor is not None and major_minor < (4, 19)
    dbg(
        "find_gnames: version=%s legacy=%s pre419=%s", ue_version, is_legacy, is_pre_419
    )

    if override_rva is not None:
        best = module_base + override_rva
        logger.debug(f"Skipping AOB scan, using override_rva GNames at 0x{best:X}")
    else:
        from src.core.memory import USE_DRIVER as _USE_DRV

        _bulk_ctx = None
        if _USE_DRV:
            from src.core.driver import bulk_read_mode as _brm

            _bulk_ctx = _brm()
            _bulk_ctx.__enter__()
            dbg("find_gnames: bulk_read_mode ENABLED")

        from src.core.memory import read_bytes as _read_bytes_mem
        import struct as _struct
        from src.core.pe_parser import get_pe_text_scan_ranges as _get_text_ranges

        _text_ranges = _get_text_ranges(handle, module_base)
        if not _text_ranges:
            _text_ranges = [(module_base, module_base + module_size)]

        _text_total = sum(end - start for start, end in _text_ranges)
        dbg(
            "find_gnames: reading .text section 0x%X + %d MB for AOB cache...",
            _text_ranges[0][0] if _text_ranges else module_base,
            _text_total // (1024 * 1024),
        )
        _t_read = _time.monotonic()
        _text_sections = []
        if _USE_DRV:
            from src.core.driver import read_memory_kernel_tolerant as _rmk
            from src.core.memory import TARGET_PID as _TPID

            for _start, _end in _text_ranges:
                _data = _rmk(_TPID, _start, _end - _start)
                if _data:
                    _text_sections.append((_start, _data))
        else:
            for _start, _end in _text_ranges:
                _data = _read_bytes_mem(handle, _start, _end - _start)
                if _data:
                    _text_sections.append((_start, _data))

        module_data = b"".join(data for _, data in _text_sections)
        _gnames_text_base = _text_sections[0][0] if _text_sections else module_base
        dbg(
            "find_gnames: .text read done in %.1fs, got %d bytes",
            _time.monotonic() - _t_read,
            len(module_data) if module_data else 0,
        )

        votes: Counter = Counter()

        if module_data and len(module_data) > 0x1000:
            from src.core.scanner import _parse_pattern, _build_prefix, _match_full

            for sig in sorted(GNAMES_SIGS, key=lambda s: s.priority):
                is_423_plus = "4.23+" in sig.ue_versions or "5.x" in sig.ue_versions
                is_419_422 = "4.19-4.22" in sig.ue_versions
                is_413_418 = "4.13-4.18" in sig.ue_versions

                if major_minor is not None:
                    if not is_legacy and not is_423_plus:
                        continue
                    if is_legacy and not is_pre_419 and not is_419_422:
                        continue
                    if is_pre_419 and not is_413_418:
                        continue

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
                        hits.append(_gnames_text_base + pos)
                    i = pos + 1

                resolved_count = 0
                for hit in hits:
                    local_off = hit - _gnames_text_base
                    disp_off = local_off + sig.disp_offset
                    if disp_off + 4 <= len(module_data):
                        disp = _struct.unpack_from("<i", module_data, disp_off)[0]
                        target = hit + sig.instruction_size + disp
                        if target > module_base:
                            votes[target] += 1
                            resolved_count += 1

                if diag:
                    diag.tried(
                        "GNames",
                        sig.name,
                        f"{len(hits)} hit(s), {resolved_count} resolved",
                    )
        else:
            dbg("find_gnames: module cache failed, falling back to per-sig IPC scan")
            for sig in sorted(GNAMES_SIGS, key=lambda s: s.priority):
                is_423_plus = "4.23+" in sig.ue_versions or "5.x" in sig.ue_versions
                is_419_422 = "4.19-4.22" in sig.ue_versions
                is_413_418 = "4.13-4.18" in sig.ue_versions

                if major_minor is not None:
                    if not is_legacy and not is_423_plus:
                        continue
                    if is_legacy and not is_pre_419 and not is_419_422:
                        continue
                    if is_pre_419 and not is_413_418:
                        continue

                hits = scan_pattern(
                    handle, module_base, module_size, sig.pattern, max_results=20
                )
                resolved_count = 0
                for hit in hits:
                    target = resolve_rip(
                        handle, hit, sig.disp_offset, sig.instruction_size
                    )
                    if target and target > module_base:
                        votes[target] += 1
                        resolved_count += 1
                if diag:
                    diag.tried(
                        "GNames",
                        sig.name,
                        f"{len(hits)} hit(s), {resolved_count} resolved",
                    )

        module_data = None

        if _bulk_ctx is not None:
            _bulk_ctx.__exit__(None, None, None)
            _bulk_ctx = None

        _t1 = _time.monotonic()
        dbg(
            "find_gnames: AOB scan done in %.1fs, %d unique candidates",
            _t1 - _t0,
            len(votes),
        )

        if not votes:
            if diag:
                diag.failed(
                    "GNames",
                    "AOB signatures",
                    f"0 valid hits across all patterns for version {ue_version}",
                )
                diag.set_confidence("GNames", 0.0, "no signatures matched")

            dbg("find_gnames: AOB=0 hits, trying names-first fallback")
            fb, fb_legacy, fb_method, fb_cp = _find_gnames_without_gobjects(
                handle,
                module_base,
                module_size,
                ue_version,
            )
            if fb:
                dbg(
                    "find_gnames: names-first fallback found GNames at 0x%X (+0x%X)",
                    fb,
                    fb - module_base,
                )
                _set_gnames_resolution_meta(
                    address=fb,
                    legacy=fb_legacy,
                    method=fb_method,
                    case_preserving=fb_cp,
                )
                if diag:
                    diag.passed(
                        "GNames",
                        "names_first_fallback",
                        f"{fb_method} at +0x{fb - module_base:X}",
                    )
                    diag.set_confidence(
                        "GNames",
                        0.75 if not fb_legacy else 0.65,
                        f"{fb_method.replace('_', ' ')} succeeded after signature miss",
                    )
                return fb, fb_legacy
            dbg("find_gnames: names-first fallback also failed")

            return 0, False

        best = votes.most_common(1)[0][0]
        dbg("find_gnames: best AOB candidate = 0x%X (+0x%X)", best, best - module_base)

    dbg("find_gnames: validating candidate 0x%X...", best)
    val0 = read_uint64(handle, best)
    if module_base <= val0 < module_base + module_size:
        for member_off in range(0x08, 0x80, 0x08):
            candidate = read_uint64(handle, best + member_off)
            if not _plausible_heap_ptr64(candidate):
                continue
            objects = read_uint64(handle, candidate)
            if not _plausible_heap_ptr64(objects):
                continue
            chunk0 = read_uint64(handle, objects)
            if not _plausible_heap_ptr64(chunk0):
                continue
            entry0 = read_uint64(handle, chunk0)
            if not _plausible_heap_ptr64(entry0):
                continue
            raw = read_bytes(handle, entry0 + 0x08, 8)
            if raw and raw[:5] == b"None\x00":
                logger.debug(
                    f"GNames singleton unwrap: best=0x{best:X} -> candidate=0x{candidate:X} at +0x{member_off:X}"
                )
                best = candidate
                _gnames_entry_str_offset[best] = 0x08
                break

    try:
        leg0 = _read_tname_entry_array_str(handle, best, 0)
    except Exception as e:
        logger.debug(f"exception during legacy probe index 0: {e!r}")
        raise
    try:
        mod0 = _read_fname_modern(handle, best, 0, None)
    except Exception as e:
        logger.debug(f"exception during modern probe index 0: {e!r}")
        raise

    v0 = read_uint64(handle, best + 0x00)
    v1 = read_uint64(handle, best + 0x08)
    v2 = read_uint64(handle, best + 0x10)
    v3 = read_uint64(handle, best + 0x18)
    v4 = read_uint64(handle, best + 0x20)
    logger.debug(
        f"AOB GNames candidate 0x{best:X} raw: +0x00={v0:016X} +0x08={v1:016X} "
        f"+0x10={v2:016X} +0x18={v3:016X} +0x20={v4:016X}"
    )

    mod_hi = module_base + module_size
    for label, arr_base in (("v0", v0), ("v1", v1)):
        if not (module_base <= arr_base < mod_hi):
            continue
        entry0 = read_uint64(handle, arr_base + 0 * 8)
        s08 = _read_fnameentry_string_at(handle, entry0, 0x08)
        s10 = _read_fnameentry_string_at(handle, entry0, 0x10)
        logger.debug(
            f"module-internal array probe: {label}=0x{arr_base:X} entry0=0x{entry0:X} "
            f"str08={s08!r} str10={s10!r}"
        )
        if not (0x10000 < entry0 < 0x7FFFFFFFFFFF):
            continue
        stroff_flat: Optional[int] = None
        for off in (0x08, 0x10, 0x0C):
            s = _read_fnameentry_string_at(handle, entry0, off)
            if s == "None":
                stroff_flat = off
                break
        if stroff_flat is not None:
            _gnames_entry_str_offset[best] = stroff_flat
            _set_gnames_resolution_meta(
                address=best,
                legacy=True,
                method="signature_probe_legacy_flat",
                case_preserving=None,
            )
            return best, True

    for table_off, chunks_base in ((0, v0), (8, v1)):
        if not _plausible_heap_ptr64(chunks_base):
            continue
        for idx in (0, 1, 2, 3):
            chunk_idx = idx >> 14
            within_idx = idx & 0x3FFF
            chunk_ptr = read_uint64(handle, chunks_base + chunk_idx * 8)
            entry_ptr = (
                read_uint64(handle, chunk_ptr + within_idx * 8) if chunk_ptr else 0
            )
            for stroff in (0x10, 0x0C, 0x08):
                raw = read_bytes(handle, entry_ptr + stroff, 32) if entry_ptr else b""
                txt = (
                    raw.split(b"\x00")[0].decode("utf-8", errors="replace")
                    if raw
                    else ""
                )
                logger.debug(
                    f"chunked probe table+0x{table_off:X} idx={idx} chunk_ptr={hex(chunk_ptr)} "
                    f"entry_ptr={hex(entry_ptr)} stroff=0x{stroff:X} → {repr(txt)}"
                )

    if _plausible_heap_ptr64(v0) or _plausible_heap_ptr64(v1):
        for table_off in (0, 8):
            if not read_uint64(handle, best + table_off):
                continue
            c0 = _read_fname_chunked_indirect(handle, best, 0, table_off)
            c1 = _read_fname_chunked_indirect(handle, best, 1, table_off)
            if c0 == "None" and c1 and _is_valid_fname(c1):
                _gnames_entry_str_offset[best] = GNAMES_LAYOUT_CHUNKED_INDIRECT
                _gnames_chunked_table_off[best] = table_off
                logger.debug(
                    f"GNames chunked indirect ACCEPTED table_ptr+0x{table_off:X}"
                )
                _set_gnames_resolution_meta(
                    address=best,
                    legacy=True,
                    method="signature_probe_legacy_chunked",
                    case_preserving=None,
                )
                return best, True

    if leg0 == "" and mod0 == "":
        dbg("find_gnames: leg0='' mod0='' - falling back to names-first recovery")
        fb, fb_legacy, fb_method, fb_cp = _find_gnames_without_gobjects(
            handle,
            module_base,
            module_size,
            ue_version,
        )
        if fb:
            _set_gnames_resolution_meta(
                address=fb,
                legacy=fb_legacy,
                method=fb_method,
                case_preserving=fb_cp,
            )
            if diag:
                diag.passed(
                    "GNames",
                    "names_first_fallback",
                    f"{fb_method} at +0x{fb - module_base:X}",
                )
                diag.set_confidence(
                    "GNames",
                    0.75 if not fb_legacy else 0.65,
                    f"{fb_method.replace('_', ' ')} recovered names after layout probe mismatch",
                )
            return fb, fb_legacy
        return 0, False

    if leg0 == "None" and mod0 != "None":
        legacy_names = True
    elif mod0 == "None" and leg0 != "None":
        legacy_names = False
    else:
        legacy_names = is_legacy

    logger.debug("legacy probe index 0:", repr(leg0))
    logger.debug("modern probe index 0:", repr(mod0))
    logger.debug("is_legacy:", legacy_names)

    if legacy_names:
        for idx in (1, 2):
            try:
                v = _read_tname_entry_array_str(handle, best, idx)
            except Exception as e:
                logger.debug(f"exception during legacy probe index {idx}: {e!r}")
                raise
            logger.debug(f"legacy probe index {idx}:", repr(v))
    else:
        for idx in (1, 2):
            try:
                v = _read_fname_modern(handle, best, idx, None)
            except Exception as e:
                logger.debug(f"exception during modern probe index {idx}: {e!r}")
                raise
            logger.debug(f"modern probe index {idx}:", repr(v))

    valid_gnames, _detected_cp = validate_gnames(handle, best, ue_version)
    if not valid_gnames:
        dbg("find_gnames: candidate 0x%X failed sequential validation", best)
        if diag:
            diag.failed(
                "GNames",
                "validate_gnames",
                f"candidate +0x{best - module_base:X} did not survive sequential block validation",
            )
        fb, fb_legacy, fb_method, fb_cp = _find_gnames_without_gobjects(
            handle,
            module_base,
            module_size,
            ue_version,
        )
        if fb:
            _set_gnames_resolution_meta(
                address=fb,
                legacy=fb_legacy,
                method=fb_method,
                case_preserving=fb_cp,
            )
            if diag:
                diag.passed(
                    "GNames",
                    "names_first_fallback",
                    f"{fb_method} at +0x{fb - module_base:X}",
                )
                diag.set_confidence(
                    "GNames",
                    0.75 if not fb_legacy else 0.65,
                    f"{fb_method.replace('_', ' ')} recovered names after validation failure",
                )
            return fb, fb_legacy
        return 0, False

    if diag:
        layout = "legacy TNameEntryArray" if legacy_names else "modern FNamePool"
        diag.passed(
            "GNames", "layout_detection", f"{layout} at +0x{best - module_base:X}"
        )
        diag.set_confidence(
            "GNames",
            0.8 if (leg0 == "None" or mod0 == "None") else 0.5,
            f"{layout}, index 0 = {leg0!r} / {mod0!r}",
        )

    _set_gnames_resolution_meta(
        address=best,
        legacy=legacy_names,
        method="signature_probe_modern"
        if not legacy_names
        else "signature_probe_legacy",
        case_preserving=None if legacy_names else _detected_cp,
    )
    return best, legacy_names

def find_gnames(
    handle: int,
    module_base: int,
    module_size: int,
    ue_version: str = "4.27",
    gobjects_hint: int = 0,
    gobjects_item_size: int = 24,
    process_name: Optional[str] = None,
    override_rva: Optional[int] = None,
    diag=None,
    allow_slow_fallback: bool = True,
) -> Tuple[int, bool]:
    _ = (gobjects_hint, gobjects_item_size)
    _gnames_resolution_meta.clear()
    override = load_game_offsets_override(process_name)
    if override is not None:
        ogn, _ogo, _ogw, _stride, legacy = override
        gnames_abs = module_base + ogn
        if legacy:
            logger.debug(f"GNames raw layout at 0x{gnames_abs:X}:")
            for _i in range(6):
                _v = read_uint64(handle, gnames_abs + _i * 8)
                logger.debug(f"  +0x{_i * 8:02X}: 0x{_v:016X}")

            objects_ptr = read_uint64(handle, gnames_abs)
            logger.debug(f"Objects (chunk table) = 0x{objects_ptr:X}")
            chunk0 = read_uint64(handle, objects_ptr) if objects_ptr else 0
            logger.debug(f"chunk0 ptr = 0x{chunk0:X}")

            if chunk0:
                for _ei in range(4):
                    _eptr = read_uint64(handle, chunk0 + _ei * 8)
                    logger.debug(f"chunk0[{_ei}] (FNameEntry*) = 0x{_eptr:X}")
                    if not _eptr:
                        continue
                    _raw = read_bytes(handle, _eptr, 32)
                    logger.debug(f"  bytes: {_raw.hex() if _raw else '<fail>'}")
                    for _off in (0x00, 0x04, 0x08, 0x0C, 0x10):
                        _s = read_bytes(handle, _eptr + _off, 16)
                        if not _s:
                            continue
                        _text = _s.split(b"\x00")[0]
                        try:
                            logger.debug(f"  +0x{_off:02X}: {_text.decode('ascii')!r}")
                        except Exception:
                            logger.debug(f"  +0x{_off:02X}: {_s[:8].hex()}")

            detected = False
            for table_off in (0, 8):
                c0 = _read_fname_chunked_indirect(handle, gnames_abs, 0, table_off)
                c1 = _read_fname_chunked_indirect(handle, gnames_abs, 1, table_off)
                logger.debug(
                    f"chunked probe table+0x{table_off:X}: idx0={c0!r} idx1={c1!r}"
                )
                if c0 == "None" and c1 and _is_valid_fname(c1):
                    _gnames_entry_str_offset[gnames_abs] = GNAMES_LAYOUT_CHUNKED_INDIRECT
                    _gnames_chunked_table_off[gnames_abs] = table_off
                    logger.debug(
                        f"GNames override: CHUNKED INDIRECT accepted (table_off=0x{table_off:X})"
                    )
                    detected = True
                    break

            if not detected:
                data_ptr = read_uint64(handle, gnames_abs)
                entry0 = read_uint64(handle, data_ptr) if data_ptr else 0
                found_stroff = None
                if entry0:
                    for probe_off in (0x08, 0x0C, 0x10):
                        if _read_fnameentry_string_at(handle, entry0, probe_off) == "None":
                            found_stroff = probe_off
                            break
                _gnames_entry_str_offset[gnames_abs] = (
                    found_stroff if found_stroff is not None else 0x10
                )
        logger.debug(
            f"GNames from OffsetsInfo.json: +0x{ogn:X} legacy={legacy} (skipping AOB/fallback)"
        )
        _set_gnames_resolution_meta(
            address=gnames_abs,
            legacy=legacy,
            method="offsets_override",
            case_preserving=None,
        )
        return gnames_abs, legacy

    from src.core.debug import dbg
    import time as _time

    _t0 = _time.monotonic()
    major_minor = _parse_version(ue_version)
    is_legacy = major_minor is not None and major_minor < (4, 23)
    is_pre_419 = major_minor is not None and major_minor < (4, 19)
    dbg(
        "find_gnames: version=%s legacy=%s pre419=%s", ue_version, is_legacy, is_pre_419
    )

    candidate_votes: List[Tuple[int, int]]
    if override_rva is not None:
        best = module_base + override_rva
        logger.debug(f"Skipping AOB scan, using override_rva GNames at 0x{best:X}")
        candidate_votes = [(best, 0)]
    else:
        from src.core.memory import USE_DRIVER as _USE_DRV

        _bulk_ctx = None
        if _USE_DRV:
            from src.core.driver import bulk_read_mode as _brm

            _bulk_ctx = _brm()
            _bulk_ctx.__enter__()
            dbg("find_gnames: bulk_read_mode ENABLED")

        from src.core.memory import read_bytes as _read_bytes_mem
        import struct as _struct
        from src.core.pe_parser import get_pe_text_scan_ranges as _get_text_ranges

        _text_ranges = _get_text_ranges(handle, module_base)
        if not _text_ranges:
            _text_ranges = [(module_base, module_base + module_size)]

        _text_total = sum(end - start for start, end in _text_ranges)
        dbg(
            "find_gnames: reading .text section 0x%X + %d MB for AOB cache...",
            _text_ranges[0][0] if _text_ranges else module_base,
            _text_total // (1024 * 1024),
        )
        _t_read = _time.monotonic()
        _text_sections = []
        if _USE_DRV:
            from src.core.driver import read_memory_kernel_tolerant as _rmk
            from src.core.memory import TARGET_PID as _TPID

            for _start, _end in _text_ranges:
                _data = _rmk(_TPID, _start, _end - _start)
                if _data:
                    _text_sections.append((_start, _data))
        else:
            for _start, _end in _text_ranges:
                _data = _read_bytes_mem(handle, _start, _end - _start)
                if _data:
                    _text_sections.append((_start, _data))

        module_data = b"".join(data for _, data in _text_sections)
        _gnames_text_base = _text_sections[0][0] if _text_sections else module_base
        dbg(
            "find_gnames: .text read done in %.1fs, got %d bytes",
            _time.monotonic() - _t_read,
            len(module_data) if module_data else 0,
        )

        votes: Counter = Counter()
        if module_data and len(module_data) > 0x1000:
            from src.core.scanner import _parse_pattern, _build_prefix, _match_full

            for sig in sorted(GNAMES_SIGS, key=lambda s: s.priority):
                is_423_plus = "4.23+" in sig.ue_versions or "5.x" in sig.ue_versions
                is_419_422 = "4.19-4.22" in sig.ue_versions
                is_413_418 = "4.13-4.18" in sig.ue_versions

                if major_minor is not None:
                    if not is_legacy and not is_423_plus:
                        continue
                    if is_legacy and not is_pre_419 and not is_419_422:
                        continue
                    if is_pre_419 and not is_413_418:
                        continue

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
                        hits.append(_gnames_text_base + pos)
                    i = pos + 1

                resolved_count = 0
                for hit in hits:
                    local_off = hit - _gnames_text_base
                    disp_off = local_off + sig.disp_offset
                    if disp_off + 4 <= len(module_data):
                        disp = _struct.unpack_from("<i", module_data, disp_off)[0]
                        target = hit + sig.instruction_size + disp
                        if target > module_base:
                            votes[target] += 1
                            resolved_count += 1

                if diag:
                    diag.tried(
                        "GNames",
                        sig.name,
                        f"{len(hits)} hit(s), {resolved_count} resolved",
                    )
        else:
            dbg("find_gnames: module cache failed, falling back to per-sig IPC scan")
            for sig in sorted(GNAMES_SIGS, key=lambda s: s.priority):
                is_423_plus = "4.23+" in sig.ue_versions or "5.x" in sig.ue_versions
                is_419_422 = "4.19-4.22" in sig.ue_versions
                is_413_418 = "4.13-4.18" in sig.ue_versions

                if major_minor is not None:
                    if not is_legacy and not is_423_plus:
                        continue
                    if is_legacy and not is_pre_419 and not is_419_422:
                        continue
                    if is_pre_419 and not is_413_418:
                        continue

                hits = scan_pattern(
                    handle, module_base, module_size, sig.pattern, max_results=20
                )
                resolved_count = 0
                for hit in hits:
                    target = resolve_rip(
                        handle, hit, sig.disp_offset, sig.instruction_size
                    )
                    if target and target > module_base:
                        votes[target] += 1
                        resolved_count += 1
                if diag:
                    diag.tried(
                        "GNames",
                        sig.name,
                        f"{len(hits)} hit(s), {resolved_count} resolved",
                    )

        module_data = None
        if _bulk_ctx is not None:
            _bulk_ctx.__exit__(None, None, None)

        dbg(
            "find_gnames: AOB scan done in %.1fs, %d unique candidates",
            _time.monotonic() - _t0,
            len(votes),
        )
        if not votes:
            if diag:
                diag.failed(
                    "GNames",
                    "AOB signatures",
                    f"0 valid hits across all patterns for version {ue_version}",
                )
                diag.set_confidence("GNames", 0.0, "no signatures matched")
            if not allow_slow_fallback:
                dbg("find_gnames: AOB=0 hits, slow fallback disabled for this caller")
                _gnames_resolution_meta.update(
                    {
                        "method": "signature_probe",
                        "failure_kind": "signature_miss",
                        "slow_fallback_skipped": True,
                    }
                )
                if diag:
                    diag.tried(
                        "GNames",
                        "names_first_fallback",
                        "Skipped slow fallback for time-bounded GObjects recovery",
                    )
                return 0, False
            dbg("find_gnames: AOB=0 hits, trying names-first fallback")
            return _run_gnames_names_first_fallback(
                handle,
                module_base,
                module_size,
                ue_version,
                diag=diag,
                confidence_reason="names first fallback succeeded after signature miss",
            )

        candidate_votes = votes.most_common()
        best = candidate_votes[0][0]
        dbg("find_gnames: best AOB candidate = 0x%X (+0x%X)", best, best - module_base)

    for candidate_addr, vote_count in candidate_votes:
        accepted = _validate_gnames_candidate(
            handle,
            candidate_addr,
            module_base,
            module_size,
            ue_version,
            is_legacy,
        )
        if accepted is None:
            if diag and override_rva is None:
                diag.tried(
                    "GNames",
                    "candidate_validation",
                    f"candidate +0x{candidate_addr - module_base:X} rejected after {vote_count} vote(s)",
                )
            continue

        resolved_addr, legacy_names, detected_cp, method = accepted
        if diag:
            layout = "legacy TNameEntryArray" if legacy_names else "modern FNamePool"
            diag.passed(
                "GNames",
                "layout_detection",
                f"{layout} at +0x{resolved_addr - module_base:X}",
            )
            diag.set_confidence(
                "GNames",
                0.85 if override_rva is not None else min(0.9, 0.6 + 0.1 * vote_count),
                f"{layout}, validated after {vote_count} vote(s)",
            )

        _set_gnames_resolution_meta(
            address=resolved_addr,
            legacy=legacy_names,
            method=method,
            case_preserving=detected_cp,
        )
        return resolved_addr, legacy_names

    if diag:
        diag.failed(
            "GNames",
            "candidate_validation",
            f"{len(candidate_votes)} AOB candidate(s) rejected by layout/validation checks",
        )
    if not allow_slow_fallback:
        dbg("find_gnames: AOB candidates rejected, slow fallback disabled for this caller")
        _gnames_resolution_meta.update(
            {
                "method": "signature_probe",
                "failure_kind": "candidate_validation_rejected",
                "slow_fallback_skipped": True,
                "candidate_count": len(candidate_votes),
            }
        )
        if diag:
            diag.tried(
                "GNames",
                "names_first_fallback",
                "Skipped slow fallback for time-bounded GObjects recovery",
            )
        return 0, False
    dbg("find_gnames: all AOB candidates rejected, trying names-first fallback")
    return _run_gnames_names_first_fallback(
        handle,
        module_base,
        module_size,
        ue_version,
        diag=diag,
        confidence_reason="names first fallback recovered names after AOB candidate rejection",
    )

def read_fname(
    handle: int,
    gnames_ptr: int,
    index: int,
    ue_version: str = "4.27",
    case_preserving: Optional[bool] = None,
    legacy: bool = False,
) -> str:
    global _full_cache_fallback_attempts

    if (
        not legacy
        and index
        and not _is_index_plausible_for_pool(gnames_ptr, index, case_preserving)
    ):
        return ""

    if not legacy and _fnames_fully_cached:
        if index == 0:
            return "None"
        res = _full_fname_cache.get(index)
        if res is not None:
            _full_fname_cache.move_to_end(index)
            return res
        miss_key = (gnames_ptr, index, case_preserving)
        if _full_cache_miss_indices.get(miss_key):
            return ""
        if _full_cache_fallback_attempts >= _full_cache_fallback_budget:
            _full_cache_miss_indices[miss_key] = True
            return ""
        _full_cache_fallback_attempts += 1
        result = _read_fname_uncached(
            handle, gnames_ptr, index, ue_version, case_preserving
        )
        if result:
            _full_fname_cache[index] = result
            while len(_full_fname_cache) > _FULL_FNAME_CACHE_MAX:
                _full_fname_cache.popitem(last=False)
        else:
            _full_cache_miss_indices[miss_key] = True
        return result

    key = (gnames_ptr, index, legacy, case_preserving)
    cached = _fname_cache.get(key)
    if cached is not None:
        _fname_cache.move_to_end(key)
        return cached

    if legacy:
        result = read_fname_legacy(handle, gnames_ptr, index)
    else:
        result = _read_fname_uncached(
            handle, gnames_ptr, index, ue_version, case_preserving
        )

    if len(_fname_cache) >= _FNAME_CACHE_MAX:
        _fname_cache.popitem(last=False)
    _fname_cache[key] = result
    return result

def read_fname_legacy(handle: int, gnames_ptr: int, index: int) -> str:
    if index == 0:
        return "None"
    if _gnames_entry_str_offset.get(gnames_ptr) == GNAMES_LAYOUT_CHUNKED_INDIRECT:
        return _read_fname_chunked_indirect(handle, gnames_ptr, index)
    return _read_tname_entry_array_str(handle, gnames_ptr, index)

def _read_tname_entry_array_str(handle: int, gnames_ptr: int, index: int) -> str:
    m = _gnames_entry_str_offset.get(gnames_ptr)
    if m == GNAMES_LAYOUT_CHUNKED_INDIRECT:
        return _read_fname_chunked_indirect(handle, gnames_ptr, index)
    stroff = 0x10 if m is None else m

    data = read_uint64(handle, gnames_ptr + 0x0)
    if not data:
        return ""

    entry_ptr = read_uint64(handle, data + index * 8)
    if not entry_ptr:
        return ""

    raw = read_bytes(handle, entry_ptr + stroff, 1024)
    if not raw:
        return ""

    nul = raw.find(b"\x00")
    if nul >= 0:
        raw = raw[:nul]
    if not raw:
        return ""

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return ""

    if not _is_valid_fname(text):
        return ""

    return text

def _read_fname_uncached(
    handle: int,
    gnames_ptr: int,
    index: int,
    ue_version: str,
    case_preserving: Optional[bool],
) -> str:
    if index == 0:
        return "None"

    return _read_fname_modern(handle, gnames_ptr, index, case_preserving)

def _read_fname_modern(
    handle: int,
    gnames_ptr: int,
    index: int,
    case_preserving: Optional[bool],
) -> str:
    block_index = (index >> 16) & 0xFFFF
    entry_offset = index & 0xFFFF

    bp_key = (gnames_ptr, block_index)
    block_ptr = _block_ptr_cache.get(bp_key)
    if block_ptr is None:
        block_ptr = read_uint64(handle, gnames_ptr + 8 * (block_index + 2))
        _block_ptr_cache[bp_key] = block_ptr
    if not block_ptr:
        return ""

    if case_preserving is None:
        result = _try_read_entry(handle, block_ptr, entry_offset, False)
        if result:
            return result
        result = _try_read_entry(handle, block_ptr, entry_offset, True)
        if result:
            return result
        return ""

    return _try_read_entry(handle, block_ptr, entry_offset, case_preserving) or ""

def _try_read_entry(
    handle: int,
    block_ptr: int,
    entry_offset: int,
    case_preserving: bool,
) -> str:
    import struct as _struct

    if case_preserving:
        byte_pos = block_ptr + 4 * entry_offset
        header_off = 4
        body_off = 6
    else:
        byte_pos = block_ptr + 2 * entry_offset
        header_off = 0
        body_off = 2

    raw_combined = read_bytes(handle, byte_pos, body_off + 1024)
    if not raw_combined or len(raw_combined) < body_off + 2:
        return ""

    header_word = _struct.unpack_from("<H", raw_combined, header_off)[0]
    if header_word == 0:
        return ""
    name_length = (header_word >> 1) if case_preserving else (header_word >> 6)
    if name_length <= 0 or name_length > 1024:
        return ""

    if len(raw_combined) < body_off + name_length:
        return ""
    raw = raw_combined[body_off : body_off + name_length]

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return ""

    if not _is_valid_fname(text):
        return ""

    return text

def _read_fname_legacy_static_indirect(handle: int, gnames_ptr: int, index: int) -> str:
    return _read_fname_chunked_indirect(handle, gnames_ptr, index)

def validate_gnames(
    handle: int,
    gnames_ptr: int,
    ue_version: str = "4.27",
) -> Tuple[bool, Optional[bool]]:
    major_minor = _parse_version(ue_version)
    is_legacy = major_minor is not None and major_minor < (4, 23)

    if is_legacy:
        if gnames_ptr in _gnames_entry_str_offset:
            if _read_tname_entry_array_str(handle, gnames_ptr, 0) != "None":
                return False, None
            if (
                sum(
                    1
                    for j in range(1, 6)
                    if _read_tname_entry_array_str(handle, gnames_ptr, j)
                )
                < 2
            ):
                return False, None
            return True, None
        valid_count = 0
        for probe_idx in range(5):
            n = _read_tname_entry_array_str(handle, gnames_ptr, probe_idx)
            if n and _is_valid_fname(n):
                valid_count += 1
        if valid_count >= 2:
            return True, None
        return False, None

    block_ptr = read_uint64(handle, gnames_ptr + 8 * (0 + 2))
    if not block_ptr:
        return False, None

    for cp in (False, True):
        names = _walk_block_sequential(handle, block_ptr, cp, max_entries=20)
        if len(names) >= 5 and names[0] == "None":
            return True, cp

    return False, None

def _walk_block_sequential(
    handle: int,
    block_ptr: int,
    case_preserving: bool,
    max_entries: int = 20,
) -> List[str]:
    names = []
    cursor = 0
    HEADER_SIZE = 6 if case_preserving else 2
    ALIGN = 4 if case_preserving else 2

    for _ in range(max_entries):
        addr = block_ptr + cursor

        if case_preserving:
            header_word = read_uint16(handle, addr + 4)
            if header_word == 0:
                break
            name_length = header_word >> 1
        else:
            header_word = read_uint16(handle, addr)
            if header_word == 0:
                break
            name_length = header_word >> 6

        if name_length <= 0 or name_length > 1024:
            break

        raw = read_bytes(handle, addr + HEADER_SIZE, name_length)
        if not raw or len(raw) < name_length:
            break

        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            break

        if not _is_valid_fname(text):
            break

        names.append(text)

        entry_total = HEADER_SIZE + name_length
        entry_total = (entry_total + ALIGN - 1) & ~(ALIGN - 1)
        cursor += entry_total

    return names

def probe_case_preserving(
    handle: int,
    gnames_ptr: int,
) -> Optional[bool]:
    _, cp = validate_gnames(handle, gnames_ptr)
    return cp

def _is_valid_fname(text: str) -> bool:
    if not text or len(text) > 1024:
        return False
    valid = sum(1 for c in text if c.isalnum() or c in "_-/.: <>")
    return valid / len(text) >= 0.7

def _parse_version(ver_str: str) -> Optional[Tuple[int, int]]:
    try:
        parts = ver_str.split(".")
        return (int(parts[0]), int(parts[1]))
    except (ValueError, IndexError):
        return None
