
import struct
import warnings
from typing import List, Optional

from src.core.memory import read_bytes
from src.core.debug import dbg

def _parse_pattern(pattern: str):
    tokens = pattern.strip().split()
    pat_bytes = []
    mask = []
    for t in tokens:
        if t in ("??", "?"):
            pat_bytes.append(0)
            mask.append(False)
        else:
            pat_bytes.append(int(t, 16))
            mask.append(True)
    return pat_bytes, mask

def _build_prefix(pat_bytes, mask):
    prefix = []
    for b, m in zip(pat_bytes, mask):
        if not m:
            break
        prefix.append(b)
    if not prefix:
        prefix.append(pat_bytes[0])
    return bytes(prefix)

def _match_full(chunk, offset, pat_bytes, mask, pat_len):
    for j in range(pat_len):
        if mask[j] and chunk[offset + j] != pat_bytes[j]:
            return False
    return True

def scan_pattern(
    handle: int,
    module_base: int,
    module_size: int,
    pattern: str,
    max_results: int = 50,
) -> List[int]:
    try:
        from src.core.memory import _snapshot_regions, get_active_native_backend

        native = get_active_native_backend()
        if native is not None and not _snapshot_regions:
            return native.scan_pattern(handle, module_base, module_size, pattern, max_results)
    except Exception as exc:
        dbg("scan_pattern: native backend failed, falling back to Python scan: %s", exc)

    pat_bytes, mask = _parse_pattern(pattern)
    pat_len = len(pat_bytes)
    if pat_len == 0:
        return []

    prefix = _build_prefix(pat_bytes, mask)
    results = []

    from src.core.memory import USE_DRIVER as _USE_DRIVER, TARGET_PID as _TARGET_PID
    from src.core.memory import _snapshot_regions

    CHUNK_SIZE = 0x80000 if _USE_DRIVER else 0x100000
    OVERLAP = pat_len - 1

    _driver_chunk_size = 0
    _read_result_meta = None
    _use_driver_ex = _USE_DRIVER and not _snapshot_regions
    if _use_driver_ex:
        from src.core.driver import read_memory_kernel_ex, COMM_DATA_MAXSIZE
        _driver_chunk_size = COMM_DATA_MAXSIZE

    offset = 0
    chunks_read = 0
    total_attempts = 0
    total_fails = 0
    consecutive_fails = 0
    skip_window = 1
    skipped_matches = 0
    dbg("scan_pattern: scanning 0x%X + 0x%X (%d KB chunks, pattern=%s)",
        module_base, module_size, CHUNK_SIZE // 1024, pattern[:40])
    while offset < module_size and len(results) < max_results:
        read_size = min(CHUNK_SIZE, module_size - offset)

        if _use_driver_ex:
            _read_result_meta = read_memory_kernel_ex(
                _TARGET_PID, module_base + offset, read_size, tolerant=True,
            )
            chunk = _read_result_meta.data
        else:
            chunk = read_bytes(handle, module_base + offset, read_size)
            _read_result_meta = None

        total_attempts += 1
        if not chunk or len(chunk) < pat_len:
            total_fails += 1
            consecutive_fails += 1

            if consecutive_fails >= 3:
                skip_window = min(skip_window * 2, 32)
                skip_bytes = read_size * skip_window
                dbg("scan_pattern: %d consecutive fails at 0x%X, skipping %d chunks ahead",
                    consecutive_fails, module_base + offset, skip_window)
                offset += skip_bytes
            else:
                offset += read_size

            if total_attempts >= 10 and total_fails > total_attempts * 4 // 5:
                dbg("scan_pattern: aborting — %d/%d chunks failed (%.0f%%)",
                    total_fails, total_attempts, total_fails * 100.0 / total_attempts)
                break
            continue

        consecutive_fails = 0
        skip_window = 1
        actual_read = len(chunk)

        search_end = actual_read - pat_len + 1
        i = 0
        while i < search_end:
            pos = chunk.find(prefix, i, actual_read)
            if pos == -1:
                break
            if pos < search_end and _match_full(chunk, pos, pat_bytes, mask, pat_len):
                if (
                    _read_result_meta is not None
                    and _read_result_meta.failed_chunks
                    and _driver_chunk_size > 0
                    and not _read_result_meta.offset_is_valid(pos, _driver_chunk_size)
                ):
                    skipped_matches += 1
                    i = pos + 1
                    continue
                addr = module_base + offset + pos
                results.append(addr)
                if len(results) >= max_results:
                    break
            i = pos + 1

        effective_overlap = min(OVERLAP, actual_read - 1)
        offset += actual_read - effective_overlap
        chunks_read += 1

    if skipped_matches:
        dbg("scan_pattern: rejected %d match(es) in zero-filled failed regions", skipped_matches)
    dbg("scan_pattern: done (%d results, %d chunks read)", len(results), chunks_read)
    return results

def resolve_rip(
    handle: int,
    match_address: int,
    disp_offset: int = 3,
    instruction_size: int = 7,
) -> int:
    try:
        from src.core.memory import _snapshot_regions, get_active_native_backend

        native = get_active_native_backend()
        if native is not None and not _snapshot_regions:
            target = native.resolve_rip(handle, match_address, disp_offset, instruction_size)
            if target:
                return target
    except Exception as exc:
        dbg("resolve_rip: native backend failed, falling back to Python read: %s", exc)

    disp_bytes = read_bytes(handle, match_address + disp_offset, 4)
    if len(disp_bytes) < 4:
        return 0

    disp = struct.unpack_from("<i", disp_bytes)[0]
    target = match_address + instruction_size + disp
    return target

def resolve_rip_auto(
    handle: int,
    match_address: int,
) -> int:
    warnings.warn(
        "resolve_rip_auto is deprecated; use resolve_rip with explicit "
        "disp_offset and instruction_size instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    header = read_bytes(handle, match_address, 4)
    if len(header) < 4:
        return 0

    b0, b1, b2, b3 = header[0], header[1], header[2], header[3]

    if b0 in (0x48, 0x4C):
        return resolve_rip(handle, match_address, disp_offset=3, instruction_size=7)

    if b0 in (0x8B, 0x89, 0x8D, 0x3B, 0x39):
        if b1 in (0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D):
            return resolve_rip(handle, match_address, disp_offset=2, instruction_size=6)

    if b0 == 0xF3 and b1 == 0x0F and b2 in (0x10, 0x11) and b3 == 0x05:
        return resolve_rip(handle, match_address, disp_offset=4, instruction_size=8)

    if b0 == 0xFF and b1 == 0x25:
        return resolve_rip(handle, match_address, disp_offset=2, instruction_size=6)

    return 0
