
import ctypes
import ctypes.wintypes as wt
import logging
import os
import struct
from contextlib import nullcontext
from dataclasses import dataclass, field
from typing import Iterator, Optional, Tuple, List

logger = logging.getLogger(__name__)

USE_DRIVER = False
TARGET_PID = 0
MEMORY_BACKEND = (os.environ.get("GSDK_MEMORY_BACKEND") or "win32").strip().lower()
_native_handles = set()
_native_backend_warning_shown = False

def set_driver_mode(enabled: bool, pid: int = 0):
    global USE_DRIVER, TARGET_PID
    USE_DRIVER = enabled
    TARGET_PID = pid

def set_memory_backend(name: str) -> None:
    global MEMORY_BACKEND, _native_backend_warning_shown
    normalized = (name or "win32").strip().lower()
    if normalized not in {"win32", "native", "auto"}:
        raise ValueError("memory backend must be one of: win32, native, auto")
    MEMORY_BACKEND = normalized
    _native_backend_warning_shown = False

def get_memory_backend() -> str:
    return MEMORY_BACKEND

def _get_native_backend():
    from src.core.native_backend import get_native_backend

    return get_native_backend()

def _active_native_backend():
    global _native_backend_warning_shown
    if USE_DRIVER or MEMORY_BACKEND == "win32":
        return None
    try:
        backend = _get_native_backend()
    except Exception as exc:
        if MEMORY_BACKEND == "native" and not _native_backend_warning_shown:
            logger.warning("Native memory backend unavailable: %s", exc)
            _native_backend_warning_shown = True
        return None

    if getattr(backend, "available", False):
        return backend

    if MEMORY_BACKEND == "native" and not _native_backend_warning_shown:
        logger.warning(
            "Native memory backend requested but unavailable: %s",
            getattr(backend, "load_error", "unknown error"),
        )
        _native_backend_warning_shown = True
    return None

def get_active_native_backend():
    return _active_native_backend()

def get_memory_backend_status() -> dict:
    backend = None
    if MEMORY_BACKEND != "win32":
        try:
            backend = _get_native_backend()
        except Exception:
            backend = None
    return {
        "requested": MEMORY_BACKEND,
        "active": bool(_active_native_backend()),
        "available": bool(getattr(backend, "available", False)) if backend else False,
        "path": getattr(backend, "path", "") if backend else "",
        "error": getattr(backend, "load_error", "") if backend else "",
    }

_snapshot_regions: list = []
_snapshot_pages: dict = {}
_SNAPSHOT_PAGE_SIZE = 0x1000
_MAX_COALESCED_GAP = 0x80
_MAX_COALESCED_SPAN_SIZE = 0x4000

@dataclass(frozen=True)
class CoalescedReadPart:
    request_index: int
    address: int
    size: int
    span_offset: int

@dataclass(frozen=True)
class CoalescedSpan:
    start: int
    size: int
    parts: Tuple[CoalescedReadPart, ...]

@dataclass
class BatchReadPlan:
    mode: str
    request_count: int
    snapshot_hits: int = 0
    spans: List[CoalescedSpan] = field(default_factory=list)
    scatter_requests: List[Tuple[int, int, int]] = field(default_factory=list)

_read_telemetry = {
    "planner_calls": 0,
    "planned_requests": 0,
    "snapshot_hits": 0,
    "snapshot_bytes": 0,
    "merged_spans": 0,
    "coalesced_requests": 0,
    "coalesced_bytes": 0,
    "scatter_dispatches": 0,
    "scatter_requests": 0,
}

def reset_read_telemetry() -> None:
    for key in list(_read_telemetry.keys()):
        _read_telemetry[key] = 0
    try:
        from src.core.driver import reset_command_metrics

        reset_command_metrics()
    except Exception:
        pass

def get_read_telemetry() -> dict:
    stats = dict(_read_telemetry)
    cmd_metrics = {}
    health = {}
    scatter_max_entries = 0
    try:
        from src.core.driver import (
            SCATTER_MAX_ENTRIES,
            check_driver_health,
            get_command_metrics,
        )

        scatter_max_entries = SCATTER_MAX_ENTRIES
        cmd_metrics = get_command_metrics()
        health = check_driver_health() if USE_DRIVER else {}
    except Exception:
        cmd_metrics = {}

    commands_by_operation = dict(cmd_metrics.get("commands_by_operation", {}))
    batch_metrics = dict(health.get("batch_metrics", {}))
    scatter_batches = commands_by_operation.get("scatter_read", 0) or stats["scatter_dispatches"]
    strict_reads = commands_by_operation.get("read", 0)
    tolerant_reads = commands_by_operation.get("read_tolerant", 0)
    capacity = max(scatter_batches * max(scatter_max_entries, 1), 1)
    planned_requests = max(stats["planned_requests"], 1)
    translation_lookups = batch_metrics.get("translation_cache_lookups", 0)
    translation_hits = batch_metrics.get("translation_cache_hits", 0)

    stats.update(
        {
            "kernel_command_count": cmd_metrics.get("total_commands", 0),
            "kernel_commands_by_operation": commands_by_operation,
            "kernel_bytes_read": cmd_metrics.get("total_bytes", 0),
            "strict_reads": strict_reads,
            "tolerant_reads": tolerant_reads,
            "scatter_batches": scatter_batches,
            "batch_fill_pct": (stats["scatter_requests"] * 100.0) / capacity,
            "collapse_rate_pct": (stats["coalesced_requests"] * 100.0) / planned_requests,
            "translation_cache_hits": translation_hits,
            "translation_cache_lookups": translation_lookups,
            "translation_cache_hit_pct": (
                (translation_hits * 100.0) / translation_lookups if translation_lookups else 0.0
            ),
        }
    )
    return stats

def _note_snapshot_hit(size: int) -> None:
    _read_telemetry["snapshot_hits"] += 1
    _read_telemetry["snapshot_bytes"] += max(0, size)

def _build_batch_read_plan(
    requests: List[Tuple[int, int, int]],
    *,
    max_span_size: int,
) -> BatchReadPlan:
    page_buckets = {}
    scatter_requests: List[Tuple[int, int, int]] = []

    for request_index, address, size in requests:
        if size <= 0:
            scatter_requests.append((request_index, address, size))
            continue
        start_page = address & ~(_SNAPSHOT_PAGE_SIZE - 1)
        end_page = (address + size - 1) & ~(_SNAPSHOT_PAGE_SIZE - 1)
        if start_page != end_page:
            scatter_requests.append((request_index, address, size))
            continue
        page_buckets.setdefault(start_page, []).append((request_index, address, size))

    spans: List[CoalescedSpan] = []

    def _flush_group(group: List[Tuple[int, int, int]]) -> None:
        if len(group) < 2:
            scatter_requests.extend(group)
            return
        start = group[0][1]
        end = max(addr + size for _, addr, size in group)
        span_size = end - start
        requested_size = sum(size for _, _, size in group)
        if span_size > max_span_size:
            scatter_requests.extend(group)
            return
        if span_size > max(requested_size * 2, requested_size + _MAX_COALESCED_GAP):
            scatter_requests.extend(group)
            return
        spans.append(
            CoalescedSpan(
                start=start,
                size=span_size,
                parts=tuple(
                    CoalescedReadPart(
                        request_index=request_index,
                        address=addr,
                        size=size,
                        span_offset=addr - start,
                    )
                    for request_index, addr, size in group
                ),
            )
        )

    for bucket in page_buckets.values():
        bucket.sort(key=lambda item: item[1])
        group = [bucket[0]]
        group_end = bucket[0][1] + bucket[0][2]
        for item in bucket[1:]:
            _, address, size = item
            new_end = max(group_end, address + size)
            span_size = new_end - group[0][1]
            if address - group_end <= _MAX_COALESCED_GAP and span_size <= max_span_size:
                group.append(item)
                group_end = new_end
                continue
            _flush_group(group)
            group = [item]
            group_end = address + size
        _flush_group(group)

    if spans and scatter_requests:
        mode = "mixed"
    elif spans:
        mode = "coalesced"
    else:
        mode = "scatter"
    return BatchReadPlan(mode=mode, request_count=len(requests), spans=spans, scatter_requests=scatter_requests)

_SNAPSHOT_BUDGET_BYTES = 512 * 1024 * 1024

def _snapshot_total_bytes() -> int:
    return sum(len(d) for _, _, d in _snapshot_regions)

def add_memory_snapshot(base: int, data: bytes) -> None:
    if _snapshot_total_bytes() + len(data) > _SNAPSHOT_BUDGET_BYTES:
        logger.warning(
            "add_memory_snapshot: snapshot budget exhausted (%d MB), "
            "skipping %d byte region at 0x%X",
            _SNAPSHOT_BUDGET_BYTES // (1024 * 1024), len(data), base,
        )
        return
    end = base + len(data)
    _snapshot_regions.append((base, end, data))
    page = base & ~(_SNAPSHOT_PAGE_SIZE - 1)
    while page < end:
        _snapshot_pages[page] = (base, end, data)
        page += _SNAPSHOT_PAGE_SIZE

def clear_memory_snapshots() -> None:
    _snapshot_regions.clear()
    _snapshot_pages.clear()

def snapshot_mark() -> int:
    return len(_snapshot_regions)

def snapshot_restore_mark(mark: int) -> None:
    if mark >= len(_snapshot_regions):
        return
    for base, end, data in _snapshot_regions[mark:]:
        page = base & ~(_SNAPSHOT_PAGE_SIZE - 1)
        while page < end:
            if page in _snapshot_pages:
                region = _snapshot_pages[page]
                if region[0] == base and region[1] == end:
                    del _snapshot_pages[page]
            page += _SNAPSHOT_PAGE_SIZE
    del _snapshot_regions[mark:]

def _merge_snapshot_ranges(ranges: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    merged: List[Tuple[int, int]] = []
    for start, end in sorted((s, e) for s, e in ranges if e > s):
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return merged

def snapshot_memory_ranges(
    handle: int,
    ranges: List[Tuple[int, int]],
    *,
    tolerant: bool = False,
) -> List[dict]:
    if not ranges:
        return []

    stats: List[dict] = []
    merged = _merge_snapshot_ranges(ranges)
    driver_reader = None
    ctx = nullcontext()
    pid = TARGET_PID
    driver_tolerant = False
    driver_chunk_size = 0

    if USE_DRIVER:
        from src.core.driver import (
            bulk_read_mode,
            COMM_DATA_MAXSIZE,
            read_memory_kernel_ex,
            supports_tolerant_bulk_read,
        )

        driver_reader = read_memory_kernel_ex
        driver_tolerant = bool(tolerant and supports_tolerant_bulk_read())
        driver_chunk_size = COMM_DATA_MAXSIZE
        ctx = bulk_read_mode()

    with ctx:
        for start, end in merged:
            size = end - start
            if size <= 0:
                continue
            if driver_reader is not None:
                result = driver_reader(pid, start, size, tolerant=driver_tolerant)
                data = result.data
                actual = result.actual_byte_count(size, driver_chunk_size)
            else:
                data = read_bytes(handle, start, size)
                actual = len(data)
            if actual == 0:
                continue
            if actual < size:
                data = data + (b"\x00" * (size - actual))

            add_memory_snapshot(start, data)

            sample = data[: min(len(data), 4096)]
            sample_nonzero = sum(1 for i in range(0, len(sample), 8) if sample[i:i + 8] != (b"\x00" * 8))
            sample_total = max(1, (len(sample) + 7) // 8)
            stats.append(
                {
                    "start": start,
                    "end": end,
                    "size": size,
                    "actual": actual,
                    "filled_pct": actual * 100 // max(size, 1),
                    "nonzero_pct": sample_nonzero * 100 // sample_total,
                    "tolerant": bool(driver_tolerant and driver_reader is not None and actual == size),
                }
            )

    return stats

def prefetch_memory_pages(
    handle: int,
    pages: List[int],
    *,
    page_size: int = _SNAPSHOT_PAGE_SIZE,
    tolerant: bool = False,
) -> List[dict]:
    ranges = [(page, page + page_size) for page in sorted(set(pages)) if page]
    return snapshot_memory_ranges(handle, ranges, tolerant=tolerant)

def _snapshot_read(addr: int, size: int):
    if not _snapshot_pages:
        return None
    page = addr & ~(_SNAPSHOT_PAGE_SIZE - 1)
    region = _snapshot_pages.get(page)
    if region is not None:
        base, end, data = region
        if base <= addr and addr + size <= end:
            offset = addr - base
            _note_snapshot_hit(size)
            return data[offset:offset + size]
    end_page = (addr + size - 1) & ~(_SNAPSHOT_PAGE_SIZE - 1)
    if end_page != page:
        region = _snapshot_pages.get(end_page)
        if region is not None:
            base, end, data = region
            if base <= addr and addr + size <= end:
                offset = addr - base
                _note_snapshot_hit(size)
                return data[offset:offset + size]
    return None

def scatter_read_multiple(handle: int, requests: List[Tuple[int, int]]) -> List[bytes]:
    if not requests:
        return []

    results: List[Optional[bytes]] = [None] * len(requests)
    uncached: List[Tuple[int, int, int]] = []
    snapshot_hits = 0

    for i, (addr, sz) in enumerate(requests):
        cached = _snapshot_read(addr, sz) if _snapshot_regions else None
        if cached is not None:
            results[i] = cached
            snapshot_hits += 1
        else:
            uncached.append((i, addr, sz))

    if not uncached:
        return [r if r is not None else b"" for r in results]

    _read_telemetry["planner_calls"] += 1
    _read_telemetry["planned_requests"] += len(uncached)

    max_span_size = _MAX_COALESCED_SPAN_SIZE
    if USE_DRIVER:
        try:
            from src.core.driver import COMM_DATA_MAXSIZE

            max_span_size = min(max_span_size, COMM_DATA_MAXSIZE)
        except Exception:
            pass

    plan = _build_batch_read_plan(uncached, max_span_size=max_span_size)
    plan.snapshot_hits = snapshot_hits

    if plan.spans:
        if USE_DRIVER:
            from src.core.driver import read_memory_kernel_tolerant

            reader = lambda address, size: read_memory_kernel_tolerant(TARGET_PID, address, size)
        else:
            reader = lambda address, size: read_bytes(handle, address, size)

        for span in plan.spans:
            blob = reader(span.start, span.size)
            if len(blob) < span.size:
                blob = blob.ljust(span.size, b"\x00")
            for part in span.parts:
                piece = blob[part.span_offset : part.span_offset + part.size]
                if len(piece) < part.size:
                    piece = piece.ljust(part.size, b"\x00")
                results[part.request_index] = piece
            _read_telemetry["merged_spans"] += 1
            _read_telemetry["coalesced_requests"] += len(span.parts)
            _read_telemetry["coalesced_bytes"] += span.size

    if plan.scatter_requests:
        uncached_requests = [(addr, sz) for _, addr, sz in plan.scatter_requests]
        if USE_DRIVER:
            from src.core.driver import scatter_read

            uncached_results = scatter_read(TARGET_PID, uncached_requests)
            _read_telemetry["scatter_dispatches"] += 1
            _read_telemetry["scatter_requests"] += len(uncached_requests)
        else:
            native = _active_native_backend()
            if native is not None:
                try:
                    uncached_results = native.scatter_read(handle, uncached_requests)
                    _read_telemetry["scatter_dispatches"] += 1
                    _read_telemetry["scatter_requests"] += len(uncached_requests)
                except Exception as exc:
                    logger.debug("native scatter_read failed: %s", exc)
                    uncached_results = [read_bytes(handle, a, s) for a, s in uncached_requests]
            else:
                uncached_results = [read_bytes(handle, a, s) for a, s in uncached_requests]
        for j, (orig_idx, _, _) in enumerate(plan.scatter_requests):
            results[orig_idx] = uncached_results[j] if j < len(uncached_results) else b""

    return [r if r is not None else b"" for r in results]

PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_ALL_ACCESS = 0x1FFFFF

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

MAX_MODULE_NAME32 = 255
MAX_PATH = 260

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_char * MAX_PATH),
    ]

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("th32ModuleID", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("GlsSnapCount", wt.DWORD),
        ("ProccntUsage", wt.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wt.DWORD),
        ("hModule", ctypes.c_void_p),
        ("szModule", ctypes.c_char * (MAX_MODULE_NAME32 + 1)),
        ("szExePath", ctypes.c_char * MAX_PATH),
    ]

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)

def get_running_processes() -> List[Tuple[int, str]]:
    snapshot = _k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        return []

    processes = []
    pe32 = PROCESSENTRY32()
    pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)

    system_procs = {
        "system",
        "registry",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "winlogon.exe",
        "svchost.exe",
        "fontdrvhost.exe",
        "dwm.exe",
        "spoolsv.exe",
        "taskhostw.exe",
        "explorer.exe",
        "sihost.exe",
        "conhost.exe",
        "runtimebroker.exe",
        "searchui.exe",
        "shellexperiencehost.exe",
        "applicationframehost.exe",
        "startmenuexperiencehost.exe",
        "systemsettings.exe",
        "ctfmon.exe",
        "wlanext.exe",
        "dasHost.exe",
        "dllhost.exe",
        "searchindexer.exe",
        "wmiprvse.exe",
        "igfxcuiservice.exe",
        "nvvsvc.exe",
        "nvxdsync.exe",
        "audiodg.exe",
        "msmpeng.exe",
        "wudfhost.exe",
        "securityhealthservice.exe",
        "cmd.exe",
        "powershell.exe",
        "backgroundtaskhost.exe",
        "lockapp.exe",
        "smartscreen.exe",
        "dashost.exe",
        "[system process]",
        "usocoreworker.exe",
        "ctfmon.exe",
        "winlogon.exe",
    }

    try:
        if _k32.Process32First(snapshot, ctypes.byref(pe32)):
            while True:
                name = pe32.szExeFile.decode("utf-8", errors="ignore")
                pid = pe32.th32ProcessID

                if pid > 4 and name.lower() not in system_procs:
                    processes.append((pid, name))

                if not _k32.Process32Next(snapshot, ctypes.byref(pe32)):
                    break
    finally:
        _k32.CloseHandle(snapshot)

    return sorted(processes, key=lambda x: x[1].lower())

def get_pid_by_name(process_name: str) -> int:
    snap = _k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        return 0

    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

    pid = 0
    target = process_name.lower().encode("utf-8")

    try:
        if _k32.Process32First(snap, ctypes.byref(entry)):
            while True:
                name = entry.szExeFile.split(b"\x00")[0].lower()
                if name == target:
                    pid = entry.th32ProcessID
                    break
                if not _k32.Process32Next(snap, ctypes.byref(entry)):
                    break
    finally:
        _k32.CloseHandle(snap)

    return pid

def get_module_info(pid: int, module_name: str) -> Tuple[int, int]:
    native = _active_native_backend()
    if native is not None:
        try:
            base, size = native.get_module_info(pid, module_name)
            if base:
                return base, size
        except Exception as exc:
            logger.debug("native get_module_info failed for %s: %s", module_name, exc)

    snap = _k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == INVALID_HANDLE_VALUE:
        return 0, 0

    entry = MODULEENTRY32()
    entry.dwSize = ctypes.sizeof(MODULEENTRY32)

    target = module_name.lower().encode("utf-8")
    base = 0
    size = 0

    try:
        if _k32.Module32First(snap, ctypes.byref(entry)):
            while True:
                name = entry.szModule.split(b"\x00")[0].lower()
                if name == target:
                    base = entry.modBaseAddr or 0
                    size = entry.modBaseSize
                    break
                if not _k32.Module32Next(snap, ctypes.byref(entry)):
                    break
    finally:
        _k32.CloseHandle(snap)

    if not base:
        return 0, 0

    if not size:
        try:
            _hproc = 0
            if not USE_DRIVER:
                _hproc = _k32.OpenProcess(
                    PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
                )
            try:
                raw = read_bytes(_hproc, base, 0x400)
                if raw and len(raw) >= 0x100:
                    e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
                    if (
                        e_lfanew
                        and e_lfanew + 0x58 < len(raw)
                        and raw[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"
                    ):
                        soi = struct.unpack_from("<I", raw, e_lfanew + 0x50)[0]
                        if 0x100000 < soi < 0x20000000:
                            size = soi
                            logger.debug(
                                f"get_module_info: modBaseSize=0 for {module_name!r}, "
                                f"recovered SizeOfImage=0x{size:X} ({size // (1024 * 1024)} MB)"
                            )
            finally:
                if _hproc:
                    _k32.CloseHandle(_hproc)
        except Exception as _e:
            logger.debug(f"get_module_info: PE size fallback failed: {_e}")

        if not size:
            size = 200 * 1024 * 1024
            logger.warning(
                f"get_module_info: could not determine size for {module_name!r} "
                f"— defaulting to 200 MB scan window"
            )

    return base, size

def get_module_base(pid: int, module_name: str) -> int:
    base, _ = get_module_info(pid, module_name)
    return base

def get_module_size(pid: int, module_name: str) -> int:
    _, size = get_module_info(pid, module_name)
    return size

def enumerate_modules(pid: int) -> List[Tuple[str, int, int, str]]:
    native = _active_native_backend()
    if native is not None:
        try:
            modules = native.enumerate_modules(pid)
            if modules:
                return modules
        except Exception as exc:
            logger.debug("native enumerate_modules failed: %s", exc)

    snap = _k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == INVALID_HANDLE_VALUE:
        return []

    entry = MODULEENTRY32()
    entry.dwSize = ctypes.sizeof(MODULEENTRY32)

    modules = []
    try:
        if _k32.Module32First(snap, ctypes.byref(entry)):
            while True:
                name = entry.szModule.split(b"\x00")[0].decode("utf-8", errors="ignore")
                path = entry.szExePath.split(b"\x00")[0].decode(
                    "utf-8", errors="ignore"
                )
                base = entry.modBaseAddr or 0
                size = entry.modBaseSize
                modules.append((name, base, size, path))
                if not _k32.Module32Next(snap, ctypes.byref(entry)):
                    break
    finally:
        _k32.CloseHandle(snap)

    return modules

def attach(
    pid: int, access: int = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
) -> Optional[int]:
    if USE_DRIVER:
        logger.debug(f"Driver mode enabled: circumventing OpenProcess for PID {pid}")
        global TARGET_PID
        TARGET_PID = pid
        return 0xDEADBEEF

    native = _active_native_backend()
    if native is not None:
        handle = native.attach(pid, access)
        if handle:
            _native_handles.add(handle)
            return handle

    handle = _k32.OpenProcess(access, False, pid)
    if not handle:
        return None
    return handle

def detach(handle: int) -> None:
    if handle == 0xDEADBEEF:
        from src.core.driver import invalidate_cr3_cache
        invalidate_cr3_cache(TARGET_PID)
        return
    if handle in _native_handles:
        _native_handles.discard(handle)
        native = _active_native_backend()
        if native is not None:
            native.detach(handle)
            return
    if handle:
        _k32.CloseHandle(handle)

from contextlib import contextmanager

@contextmanager
def process_handle(pid: int, access: int = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION):
    h = attach(pid, access)
    if h is None:
        raise OSError(f"Failed to open process {pid}")
    try:
        yield h
    finally:
        detach(h)

MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

class MEMORY_BASIC_INFORMATION(ctypes.Structure):

    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("PartitionId", wt.WORD),
        ("Reserved", wt.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
        ("Unused", wt.DWORD),
    ]

def _region_is_readable(protect: int) -> bool:
    if protect == 0 or (protect & PAGE_GUARD):
        return False
    if (protect & 0xFF) == PAGE_NOACCESS:
        return False
    return True

def iter_readable_regions(handle: int) -> Iterator[Tuple[int, int]]:
    if USE_DRIVER:
        from src.core.driver import iter_readable_regions_kernel

        yield from iter_readable_regions_kernel(TARGET_PID)
        return

    native = _active_native_backend()
    if native is not None:
        try:
            yield from native.iter_readable_regions(handle)
            return
        except Exception as exc:
            logger.debug("native iter_readable_regions failed: %s", exc)

    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    max_user = 0x7FFFFFFFFFFF
    vq = _k32.VirtualQueryEx
    vq.argtypes = [
        wt.HANDLE,
        ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION),
        ctypes.c_size_t,
    ]
    vq.restype = ctypes.c_size_t

    while addr <= max_user:
        if (
            vq(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
            == 0
        ):
            break
        base = mbi.BaseAddress or 0
        size = int(mbi.RegionSize)
        if size <= 0:
            break
        if mbi.State == MEM_COMMIT and _region_is_readable(mbi.Protect):
            yield (base, size)
        naddr = base + size
        if naddr <= addr:
            break
        addr = naddr

IS_32BIT = False
POINTER_SIZE = 8

def set_architecture(is_32bit: bool):
    global IS_32BIT, POINTER_SIZE
    IS_32BIT = is_32bit
    POINTER_SIZE = 4 if is_32bit else 8

_READ_BYTES_MAX = 256 * 1024 * 1024

def read_bytes(handle: int, address: int, size: int) -> bytes:
    if size <= 0:
        return b""
    if size > _READ_BYTES_MAX:
        logger.warning(
            "read_bytes: rejecting oversized request of %d bytes at 0x%X "
            "(max %d)", size, address, _READ_BYTES_MAX,
        )
        return b""

    if _snapshot_regions:
        cached = _snapshot_read(address, size)
        if cached is not None:
            return cached

    if USE_DRIVER:
        from src.core.driver import read_memory_kernel_tolerant

        return read_memory_kernel_tolerant(TARGET_PID, address, size)

    native = _active_native_backend()
    if native is not None:
        try:
            return native.read_bytes(handle, address, size)
        except Exception as exc:
            logger.debug("native read_bytes failed at 0x%X size=%d: %s", address, size, exc)

    buf = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    ok = _k32.ReadProcessMemory(
        handle,
        ctypes.c_void_p(address),
        buf,
        size,
        ctypes.byref(bytes_read),
    )
    if not ok or bytes_read.value == 0:
        return b""
    return buf.raw[: bytes_read.value]

def get_pe_fingerprint(handle: int, module_base: int) -> dict:
    native = _active_native_backend()
    if native is not None:
        try:
            return native.pe_fingerprint(handle, module_base)
        except Exception as exc:
            logger.debug("native pe_fingerprint failed at 0x%X: %s", module_base, exc)

    raw = read_bytes(handle, module_base, 0x400)
    if len(raw) < 0x100 or raw[:2] != b"MZ":
        return {}
    try:
        e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
        if e_lfanew + 0x58 >= len(raw) or raw[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return {}
        machine = struct.unpack_from("<H", raw, e_lfanew + 4)[0]
        sections = struct.unpack_from("<H", raw, e_lfanew + 6)[0]
        timestamp = struct.unpack_from("<I", raw, e_lfanew + 8)[0]
        opt = e_lfanew + 24
        entry_point = struct.unpack_from("<I", raw, opt + 0x10)[0]
        size_of_image = struct.unpack_from("<I", raw, opt + 0x38)[0]
        checksum = struct.unpack_from("<I", raw, opt + 0x40)[0]
        header_hash = 14695981039346656037
        for byte in raw:
            header_hash ^= byte
            header_hash = (header_hash * 1099511628211) & 0xFFFFFFFFFFFFFFFF
        header_hash ^= (timestamp << 32) & 0xFFFFFFFFFFFFFFFF
        header_hash ^= size_of_image
        return {
            "machine": machine,
            "number_of_sections": sections,
            "timestamp": timestamp,
            "size_of_image": size_of_image,
            "checksum": checksum,
            "entry_point_rva": entry_point,
            "header_fingerprint": f"{header_hash:016x}",
        }
    except Exception:
        return {}

def read_pointer(handle: int, address: int) -> int:
    return read_uint32(handle, address) if IS_32BIT else read_uint64(handle, address)

def read_uint64(handle: int, address: int) -> int:
    data = read_bytes(handle, address, 8)
    if len(data) < 8:
        return 0
    return struct.unpack_from("<Q", data)[0]

def read_uint32(handle: int, address: int) -> int:
    data = read_bytes(handle, address, 4)
    if len(data) < 4:
        return 0
    return struct.unpack_from("<I", data)[0]

def read_int32(handle: int, address: int) -> int:
    data = read_bytes(handle, address, 4)
    if len(data) < 4:
        return 0
    return struct.unpack_from("<i", data)[0]

def read_uint16(handle: int, address: int) -> int:
    data = read_bytes(handle, address, 2)
    if len(data) < 2:
        return 0
    return struct.unpack_from("<H", data)[0]

def read_float(handle: int, address: int) -> float:
    data = read_bytes(handle, address, 4)
    if len(data) < 4:
        return 0.0
    return struct.unpack_from("<f", data)[0]

def read_double(handle: int, address: int) -> float:
    data = read_bytes(handle, address, 8)
    if len(data) < 8:
        return 0.0
    return struct.unpack_from("<d", data)[0]

def read_string(handle: int, address: int, max_len: int = 256) -> str:
    data = read_bytes(handle, address, max_len)
    if not data:
        return ""
    idx = data.find(b"\x00")
    if idx >= 0:
        data = data[:idx]
    return data.decode("utf-8", errors="replace")

def write_bytes(handle: int, address: int, data: bytes) -> bool:
    if USE_DRIVER:
        from src.core.driver import write_memory_kernel

        return write_memory_kernel(TARGET_PID, address, data)

    written = ctypes.c_size_t(0)
    ok = _k32.WriteProcessMemory(
        handle,
        ctypes.c_void_p(address),
        data,
        len(data),
        ctypes.byref(written),
    )
    return bool(ok) and written.value == len(data)

def write_uint32(handle: int, address: int, value: int) -> bool:
    return write_bytes(handle, address, struct.pack("<I", value))

def write_float(handle: int, address: int, value: float) -> bool:
    return write_bytes(handle, address, struct.pack("<f", value))
