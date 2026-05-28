
import ctypes
import ctypes.wintypes as wt
import random
import struct
import threading
import time
import logging
from contextlib import contextmanager
from typing import Iterator, List, Optional, Tuple, Any, Dict
from dataclasses import dataclass, field

from src.core.debug import dbg

logger = logging.getLogger(__name__)

@dataclass
class StructReadDef:
    address: int
    size: int
    struct_type: Any = None
    buffer_offset: int = 0

@dataclass
class KernelReadResult:
    data: bytes
    total_chunks: int = 0
    failed_chunks: frozenset = field(default_factory=frozenset)

    @property
    def success_rate(self) -> float:
        if self.total_chunks == 0:
            return 1.0
        return (self.total_chunks - len(self.failed_chunks)) / self.total_chunks

    def is_chunk_valid(self, chunk_index: int) -> bool:
        return chunk_index not in self.failed_chunks

    def offset_is_valid(self, offset: int, chunk_size: int) -> bool:
        if chunk_size <= 0:
            return True
        return self.is_chunk_valid(offset // chunk_size)

    def failed_byte_count(self, requested_size: int, chunk_size: int) -> int:
        requested_size = max(0, int(requested_size or 0))
        chunk_size = max(1, int(chunk_size or 1))
        if requested_size == 0 or not self.failed_chunks:
            return 0
        total = 0
        for chunk_index in self.failed_chunks:
            chunk_offset = int(chunk_index) * chunk_size
            if chunk_offset >= requested_size:
                continue
            total += min(chunk_size, requested_size - chunk_offset)
        return total

    def actual_byte_count(self, requested_size: int, chunk_size: int) -> int:
        requested_size = max(0, int(requested_size or 0))
        return max(0, requested_size - self.failed_byte_count(requested_size, chunk_size))

@dataclass
class DriverCommandMetrics:
    total_commands: int = 0
    total_bytes: int = 0
    failed_commands: int = 0
    retries: int = 0
    commands_by_operation: Dict[str, int] = field(default_factory=dict)
    bytes_by_operation: Dict[str, int] = field(default_factory=dict)

COMMAND_MAGIC = 0xD3C2B1A0
COMMAND_READ = 1
COMMAND_WRITE = 2
COMMAND_GETBASE = 3
COMMAND_FINDCR3 = 4
COMMAND_SCATTER_READ = 5
COMMAND_HEALTH_CHECK = 6
COMMAND_READ_TOLERANT = 7

HEALTH_CHECK_MAGIC = 0xE7F6A5B4

CMD_STATUS_WAITING = 0
CMD_STATUS_COMPLETE = 1
CMD_STATUS_ERROR = 2

_COMM_SECTION_PREFIX = "Global\\{wdf-"
_COMM_SECTION_LEGACY = "Global\\{a8f5c2b1-d3e7-49a6-8c01-7f2b3e4d5a6c}"
COMM_PAGE_SIZE = 65536

COMM_HEADER_SIZE = 48
COMM_DATA_MAXSIZE = COMM_PAGE_SIZE - COMM_HEADER_SIZE

_CMD_STRUCT = struct.Struct("<IIII QQQ II")

_SCATTER_ENTRY = struct.Struct("<QI")
SCATTER_ENTRY_SIZE = _SCATTER_ENTRY.size
SCATTER_MAX_ENTRIES = COMM_DATA_MAXSIZE // SCATTER_ENTRY_SIZE

_COMMAND_NAMES = {
    COMMAND_READ: "read",
    COMMAND_WRITE: "write",
    COMMAND_GETBASE: "getbase",
    COMMAND_FINDCR3: "findcr3",
    COMMAND_SCATTER_READ: "scatter_read",
    COMMAND_HEALTH_CHECK: "health_check",
    COMMAND_READ_TOLERANT: "read_tolerant",
}

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.OpenFileMappingW.restype = wt.HANDLE
_k32.OpenFileMappingW.argtypes = [wt.DWORD, wt.BOOL, wt.LPCWSTR]
_k32.MapViewOfFile.restype = ctypes.c_void_p
_k32.MapViewOfFile.argtypes = [wt.HANDLE, wt.DWORD, wt.DWORD, wt.DWORD, ctypes.c_size_t]
_k32.UnmapViewOfFile.restype = wt.BOOL
_k32.CloseHandle.restype = wt.BOOL
_k32.OpenProcess.restype = wt.HANDLE
_k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]

FILE_MAP_ALL_ACCESS = 0xF001F
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

_g_mapping: int = 0
_g_view: int = 0
_health_cache: Optional[dict] = None
_command_metrics = DriverCommandMetrics()
_ipc_lock = threading.Lock()
_last_read_result = threading.local()

_cr3_cache: dict = {}
_CR3_CACHE_TTL = 30.0

_JITTER_ENABLED = True
_JITTER_MIN_US = 50
_JITTER_MAX_US = 500

_BULK_MODE = False

class FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wt.DWORD),
        ("dwHighDateTime", wt.DWORD),
    ]

_k32.GetProcessTimes.restype = wt.BOOL
_k32.GetProcessTimes.argtypes = [
    wt.HANDLE,
    ctypes.POINTER(FILETIME),
    ctypes.POINTER(FILETIME),
    ctypes.POINTER(FILETIME),
    ctypes.POINTER(FILETIME),
]

def _store_last_read_result(result: KernelReadResult) -> KernelReadResult:
    _last_read_result.value = result
    return result

def get_last_kernel_read_result() -> Optional[KernelReadResult]:
    return getattr(_last_read_result, "value", None)

def _filetime_to_int(value: FILETIME) -> int:
    return (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)

def _get_process_identity(pid: int) -> int:
    if pid <= 0:
        return 0
    handle = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return 0
    try:
        created = FILETIME()
        exited = FILETIME()
        kernel = FILETIME()
        user = FILETIME()
        if not _k32.GetProcessTimes(
            handle,
            ctypes.byref(created),
            ctypes.byref(exited),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            return 0
        return _filetime_to_int(created)
    finally:
        _k32.CloseHandle(handle)

def _discover_section_name() -> str | None:
    import ctypes.wintypes as _wt

    _ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

    class UNICODE_STRING(ctypes.Structure):
        _fields_ = [
            ("Length", ctypes.c_ushort),
            ("MaximumLength", ctypes.c_ushort),
            ("Buffer", ctypes.c_wchar_p),
        ]

    class OBJECT_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("Length", ctypes.c_ulong),
            ("RootDirectory", ctypes.c_void_p),
            ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
            ("Attributes", ctypes.c_ulong),
            ("SecurityDescriptor", ctypes.c_void_p),
            ("SecurityQualityOfService", ctypes.c_void_p),
        ]

    class OBJECT_DIRECTORY_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("Name", UNICODE_STRING),
            ("TypeName", UNICODE_STRING),
        ]

    OBJ_CASE_INSENSITIVE = 0x40

    try:
        dir_name_str = "\\BaseNamedObjects\\Global"
        dir_name = UNICODE_STRING()
        dir_name.Length = len(dir_name_str) * 2
        dir_name.MaximumLength = (len(dir_name_str) + 1) * 2
        dir_name.Buffer = dir_name_str

        obj_attr = OBJECT_ATTRIBUTES()
        obj_attr.Length = ctypes.sizeof(OBJECT_ATTRIBUTES)
        obj_attr.RootDirectory = None
        obj_attr.ObjectName = ctypes.pointer(dir_name)
        obj_attr.Attributes = OBJ_CASE_INSENSITIVE
        obj_attr.SecurityDescriptor = None
        obj_attr.SecurityQualityOfService = None

        dir_handle = ctypes.c_void_p()
        status = _ntdll.NtOpenDirectoryObject(
            ctypes.byref(dir_handle),
            0x01,
            ctypes.byref(obj_attr),
        )
        if status != 0:
            dbg("_discover_section_name: NtOpenDirectoryObject failed: 0x%08X", status)
            return None

        buf_size = 65536
        buf = ctypes.create_string_buffer(buf_size)
        context = ctypes.c_ulong(0)
        return_length = ctypes.c_ulong(0)

        found_name = None
        first_call = True
        iteration = 0
        total_entries = 0
        total_sections = 0
        sample_sections = []

        while True:
            iteration += 1
            status = _ntdll.NtQueryDirectoryObject(
                dir_handle,
                buf,
                buf_size,
                False,
                first_call,
                ctypes.byref(context),
                ctypes.byref(return_length),
            )
            first_call = False
            status_u32 = status & 0xFFFFFFFF
            dbg(
                "_discover_section_name: NtQueryDirectoryObject iter=%d status=0x%08X return_length=%d",
                iteration, status_u32, return_length.value,
            )

            STATUS_SUCCESS = 0x00000000
            STATUS_MORE_ENTRIES = 0x00000105

            if status_u32 & 0x80000000:
                break
            if status_u32 not in (STATUS_SUCCESS, STATUS_MORE_ENTRIES):
                break
            if return_length.value == 0:
                break

            offset = 0
            entry_size = ctypes.sizeof(OBJECT_DIRECTORY_INFORMATION)
            while offset + entry_size <= return_length.value:
                entry = ctypes.cast(
                    ctypes.byref(buf, offset),
                    ctypes.POINTER(OBJECT_DIRECTORY_INFORMATION)
                ).contents

                if entry.Name.Length == 0:
                    break

                total_entries += 1
                name = entry.Name.Buffer
                type_name = entry.TypeName.Buffer

                if type_name == "Section":
                    total_sections += 1
                    if name and len(sample_sections) < 20:
                        sample_sections.append(name)

                if (name and type_name and
                    type_name == "Section" and
                    name.startswith("{wdf-")):
                    found_name = f"Global\\{name}"
                    dbg("_discover_section_name: Found section: %s", found_name)
                    break

                offset += entry_size

            if found_name:
                break

        dbg(
            "_discover_section_name: enumerated %d entries, %d sections, found=%s",
            total_entries, total_sections, found_name,
        )
        if not found_name and sample_sections:
            dbg(
                "_discover_section_name: sample section names: %s",
                ", ".join(sample_sections),
            )

        _ntdll.NtClose(dir_handle)
        return found_name

    except Exception as e:
        dbg("_discover_section_name: Exception: %s", e)
        return None

def init_driver() -> bool:
    global _g_mapping, _g_view, _health_cache

    section_name = _discover_section_name()
    if section_name:
        dbg("init_driver: discovered section '%s'", section_name)
    else:
        section_name = _COMM_SECTION_LEGACY
        dbg("init_driver: using legacy section '%s'", section_name)

    mapping = _k32.OpenFileMappingW(FILE_MAP_ALL_ACCESS, False, section_name)
    if not mapping:
        err = ctypes.get_last_error()
        dbg("init_driver: OpenFileMappingW FAILED (0x%08X)", err)
        logger.error(
            f"[Driver] OpenFileMappingW failed (0x{err:08X}). "
            "Is wdfsvc64.sys loaded?"
        )
        return False

    view = _k32.MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, COMM_PAGE_SIZE)
    if not view:
        err = ctypes.get_last_error()
        dbg("init_driver: MapViewOfFile FAILED (0x%08X)", err)
        logger.error(f"[Driver] MapViewOfFile failed (0x{err:08X}).")
        _k32.CloseHandle(mapping)
        return False

    _k32.CloseHandle(mapping)
    _g_mapping = 0
    _g_view = view
    _health_cache = None
    reset_command_metrics()
    dbg("init_driver: SUCCESS — view mapped at 0x%X", view)
    logger.info(
        "[Driver] Connected — shared section mapped at 0x{:X}".format(view)
    )
    return True

def check_driver_health() -> dict:
    global _health_cache

    result = {
        "alive": False,
        "version": "unknown",
        "capabilities": {},
        "dtb_offset": 0,
        "dtb_validated": False,
        "batch_metrics": {
            "scatter_batches": 0,
            "merged_reads": 0,
            "translation_cache_hits": 0,
            "translation_cache_lookups": 0,
        },
    }

    if not _g_view:
        return result

    if _health_cache is not None:
        return dict(_health_cache)

    if _send_command(0, 0, 0, COMMAND_HEALTH_CHECK, timeout_ms=2000, retries=1):
        raw = ctypes.string_at(_g_view + COMM_HEADER_SIZE, 48)
        if len(raw) >= 24:
            echo_magic = struct.unpack_from("<Q", raw, 0)[0]
            version_raw = struct.unpack_from("<I", raw, 8)[0]
            caps_raw = struct.unpack_from("<I", raw, 12)[0]
            dtb_off = struct.unpack_from("<I", raw, 16)[0]
            dtb_valid = struct.unpack_from("<I", raw, 20)[0]
            if len(raw) >= 40:
                result["batch_metrics"] = {
                    "scatter_batches": struct.unpack_from("<I", raw, 24)[0],
                    "merged_reads": struct.unpack_from("<I", raw, 28)[0],
                    "translation_cache_hits": struct.unpack_from("<I", raw, 32)[0],
                    "translation_cache_lookups": struct.unpack_from("<I", raw, 36)[0],
                }

            if echo_magic == HEALTH_CHECK_MAGIC:
                result["alive"] = True
                major = (version_raw >> 16) & 0xFFFF
                minor = version_raw & 0xFFFF
                result["version"] = f"{major}.{minor}"
                result["capabilities"] = {
                    "physical_read": bool(caps_raw & 0x01),
                    "dtb_validated": bool(caps_raw & 0x04),
                    "tolerant_bulk_read": bool(caps_raw & 0x08),
                }
                result["dtb_offset"] = dtb_off
                result["dtb_validated"] = bool(dtb_valid)

    _health_cache = dict(result)
    return result

def supports_tolerant_bulk_read() -> bool:
    return bool(check_driver_health()["capabilities"].get("tolerant_bulk_read"))

def _command_name(instruction: int) -> str:
    return _COMMAND_NAMES.get(instruction, f"command_{instruction}")

def reset_command_metrics() -> None:
    global _command_metrics
    _command_metrics = DriverCommandMetrics()

def get_command_metrics() -> dict:
    return {
        "total_commands": _command_metrics.total_commands,
        "total_bytes": _command_metrics.total_bytes,
        "failed_commands": _command_metrics.failed_commands,
        "retries": _command_metrics.retries,
        "commands_by_operation": dict(_command_metrics.commands_by_operation),
        "bytes_by_operation": dict(_command_metrics.bytes_by_operation),
    }

def _record_command_dispatch(instruction: int, size: int) -> None:
    op = _command_name(instruction)
    _command_metrics.total_commands += 1
    _command_metrics.total_bytes += max(0, size)
    _command_metrics.commands_by_operation[op] = (
        _command_metrics.commands_by_operation.get(op, 0) + 1
    )
    _command_metrics.bytes_by_operation[op] = (
        _command_metrics.bytes_by_operation.get(op, 0) + max(0, size)
    )

def _record_command_failure() -> None:
    _command_metrics.failed_commands += 1

def check_system_prerequisites() -> list:
    results = []

    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if is_admin:
            results.append(("ok", "Running as Administrator"))
        else:
            results.append(("fail", "NOT running as Administrator — right-click and 'Run as admin'"))
    except Exception:
        results.append(("warn", "Could not check admin status"))

    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"
        )
        val, _ = winreg.QueryValueEx(key, "UEFISecureBootEnabled")
        winreg.CloseKey(key)
        if val == 1:
            results.append((
                "fail",
                "Secure Boot is ENABLED — the driver mapper cannot load unsigned drivers. "
                "Disable in BIOS/UEFI settings."
            ))
        else:
            results.append(("ok", "Secure Boot is disabled"))
    except FileNotFoundError:
        results.append(("ok", "Secure Boot not present (Legacy BIOS)"))
    except Exception as e:
        results.append(("warn", f"Could not check Secure Boot status: {e}"))

    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard"
        )
        try:
            vbs_val, _ = winreg.QueryValueEx(key, "EnableVirtualizationBasedSecurity")
        except FileNotFoundError:
            vbs_val = 0
        try:
            hvci_val, _ = winreg.QueryValueEx(key, "HypervisorEnforcedCodeIntegrity")
        except FileNotFoundError:
            hvci_val = 0
        winreg.CloseKey(key)

        if hvci_val == 1:
            results.append((
                "fail",
                "Core Isolation Memory Integrity (HVCI) is ENABLED — "
                "blocks unsigned kernel code. Disable in Windows Security > "
                "Device Security > Core Isolation > Memory Integrity."
            ))
        elif vbs_val == 1:
            results.append((
                "warn",
                "Virtualization Based Security (VBS) is enabled. "
                "This may interfere with driver loading. Consider disabling "
                "in Windows Features if you have issues."
            ))
        else:
            results.append(("ok", "Core Isolation / HVCI is disabled"))
    except FileNotFoundError:
        results.append(("ok", "Device Guard not configured"))
    except Exception as e:
        results.append(("warn", f"Could not check HVCI status: {e}"))

    build_int = 0
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        )
        build, _ = winreg.QueryValueEx(key, "CurrentBuildNumber")
        display, _ = winreg.QueryValueEx(key, "DisplayVersion")
        winreg.CloseKey(key)
        build_int = int(build)
        if build_int >= 17134:
            results.append(("ok", f"Windows {display} (Build {build}) — compatible"))
        else:
            results.append(("warn", f"Windows Build {build} — may have different EPROCESS layout"))
    except Exception:
        results.append(("warn", "Could not determine Windows version"))

    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\CI\Config"
        )
        try:
            vuln_val, _ = winreg.QueryValueEx(key, "VulnerableDriverBlocklistEnable")
        except FileNotFoundError:
            vuln_val = -1
        winreg.CloseKey(key)

        if vuln_val == 1:
            results.append((
                "warn",
                "Microsoft Driver Blocklist is ENABLED — the default "
                "Intel NAL driver used by the driver mapper is "
                "default iqvw64e.sys is blocklisted and will fail with "
                "STATUS_IMAGE_CERT_REVOKED. Disable via: "
                "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config\" "
                "/v VulnerableDriverBlocklistEnable /t REG_DWORD /d 0 /f (then reboot). "
                "Alternatively, use a different driver or disable the blocklist."
            ))
        elif vuln_val == 0:
            results.append(("ok", "Driver Blocklist is disabled"))
        else:
            if build_int >= 26100:
                results.append((
                    "warn",
                    "Windows 24H2+ detected — Driver Blocklist is ON by "
                    "default. The Intel NAL driver (iqvw64e.sys) may be blocked. If loading fails, "
                    "disable the blocklist or use an alternative driver."
                ))
            else:
                results.append(("ok", "Driver Blocklist: not enforced on this build"))
    except Exception:
        results.append(("warn", "Could not check Driver Blocklist status"))

    try:
        import subprocess
        out = subprocess.check_output(
            ["bcdedit", "/enum", "{current}"],
            stderr=subprocess.DEVNULL, timeout=5
        ).decode("utf-8", errors="ignore")
        import re
        ts_match = re.search(r'testsigning\s+(yes|no)', out, re.IGNORECASE)
        if ts_match and ts_match.group(1).lower() == "yes":
            results.append((
                "fail",
                "Test Signing mode is ON — most anti-cheats (EAC, BattlEye, ACE) "
                "will refuse to launch the game while test signing is enabled. "
                "Disable it with: bcdedit /set testsigning off (then reboot)."
            ))
        else:
            results.append(("ok", "Test Signing mode is OFF (required for anti-cheat games)"))
    except Exception:
        results.append(("warn", "Could not check Test Signing status"))

    return results

def shutdown_driver() -> None:
    global _g_mapping, _g_view, _cr3_cache, _health_cache

    if _g_view:
        _k32.UnmapViewOfFile(_g_view)
        _g_view = 0
    _g_mapping = 0
    _cr3_cache.clear()
    _health_cache = None
    reset_command_metrics()
    logger.info("[Driver] Disconnected.")

def is_connected() -> bool:
    return bool(_g_view)

def set_stealth_jitter(enabled: bool, min_us: int = 50, max_us: int = 500) -> None:
    global _JITTER_ENABLED, _JITTER_MIN_US, _JITTER_MAX_US
    _JITTER_ENABLED = enabled
    _JITTER_MIN_US = min_us
    _JITTER_MAX_US = max_us

def _apply_jitter() -> None:
    if _BULK_MODE:
        return
    if _JITTER_ENABLED:
        jitter_s = random.randint(_JITTER_MIN_US, _JITTER_MAX_US) / 1_000_000.0
        time.sleep(jitter_s)

@contextmanager
def bulk_read_mode():
    global _BULK_MODE
    prev = _BULK_MODE
    _BULK_MODE = True
    dbg("bulk_read_mode: ENABLED (jitter suspended)")
    try:
        yield
    finally:
        _BULK_MODE = prev
        dbg("bulk_read_mode: DISABLED (jitter restored)")

def _send_command(
    pid: int,
    address: int,
    size: int,
    instruction: int,
    timeout_ms: int = 500,
    retries: int = 2,
) -> bool:
    if not _g_view:
        return False

    try:
        pid = int(pid)
        address = int(address)
        size = int(size)
        instruction = int(instruction)
    except Exception as exc:
        logger.debug("[Driver] Invalid command field type: %s", exc)
        _record_command_failure()
        return False

    if pid < 0 or pid > 0xFFFFFFFF:
        logger.debug("[Driver] Rejecting command with invalid pid=%s", pid)
        _record_command_failure()
        return False
    if address < 0 or address > 0xFFFFFFFFFFFFFFFF:
        logger.debug("[Driver] Rejecting command with invalid address=0x%X", address)
        _record_command_failure()
        return False
    if size < 0 or size > 0xFFFFFFFFFFFFFFFF:
        logger.debug("[Driver] Rejecting command with invalid size=%s", size)
        _record_command_failure()
        return False

    for attempt in range(1 + retries):
        if attempt > 0:
            _command_metrics.retries += 1
            backoff_ms = min(100 * (2 ** (attempt - 1)), 1000)
            time.sleep(backoff_ms / 1000.0)
            logger.debug(
                f"[Driver] Retry {attempt}/{retries} for command {instruction} "
                f"at 0x{address:X}"
            )

        try:
            payload = _CMD_STRUCT.pack(
            0,
            instruction,
            pid,
            0,
            address,
            0,
            size,
            CMD_STATUS_WAITING,
            0,
            )
        except Exception as exc:
            logger.debug(
                "[Driver] Failed to pack command fields (pid=%s, addr=%s, size=%s, cmd=%s): %s",
                pid,
                address,
                size,
                instruction,
                exc,
            )
            _record_command_failure()
            return False

        with _ipc_lock:
            ctypes.memmove(_g_view + 4, payload[4:], COMM_HEADER_SIZE - 4)
            magic_bytes = struct.pack("<I", COMMAND_MAGIC)
            ctypes.memmove(_g_view, magic_bytes, 4)
            _record_command_dispatch(instruction, size)
            dbg("_send_command: cmd=%d pid=%d addr=0x%X size=%d (attempt %d)",
                instruction, pid, address, size, attempt)

            _status_offset = 40
            deadline = time.monotonic() + timeout_ms / 1000.0
            while time.monotonic() < deadline:
                status = struct.unpack_from(
                    "<I", ctypes.string_at(_g_view + _status_offset, 4)
                )[0]
                if status != CMD_STATUS_WAITING:
                    if status == CMD_STATUS_COMPLETE:
                        _apply_jitter()
                        return True
                    logger.debug(
                        f"[Driver] Command {instruction} returned error status "
                        f"for addr 0x{address:X}"
                    )
                    _record_command_failure()
                    return False

            if attempt < retries:
                logger.debug(
                    f"[Driver] Command {instruction} timed out after {timeout_ms}ms, "
                    f"will retry"
                )

    logger.warning(
        f"[Driver] Command {instruction} timed out after {timeout_ms}ms "
        f"({retries} retries exhausted)"
    )
    _record_command_failure()
    return False

def find_cr3(pid: int, timeout_ms: int = 2000, force: bool = False) -> int:
    if not _g_view:
        logger.warning("[Driver] find_cr3 called but driver is not connected.")
        return 0

    if not force and pid in _cr3_cache:
        cached = _cr3_cache[pid]
        if len(cached) >= 3:
            cr3, ts, identity = cached[:3]
        else:
            cr3, ts = cached[:2]
            identity = 0
        if time.monotonic() - ts < _CR3_CACHE_TTL:
            current_identity = _get_process_identity(pid) if identity else 0
            if identity and current_identity and current_identity != identity:
                dbg(
                    "find_cr3: PID %d identity changed (0x%X -> 0x%X), invalidating cached CR3",
                    pid,
                    identity,
                    current_identity,
                )
                _cr3_cache.pop(pid, None)
            else:
                dbg("find_cr3: PID %d cached CR3=0x%X", pid, cr3)
                return cr3

    dbg("find_cr3: querying CR3 for PID %d", pid)
    if _send_command(pid, 0, 0, COMMAND_FINDCR3, timeout_ms=timeout_ms, retries=3):
        raw = ctypes.string_at(_g_view + COMM_HEADER_SIZE, 8)
        cr3 = struct.unpack_from("<Q", raw)[0]
        if cr3 and cr3 > 0:
            _cr3_cache[pid] = (cr3, time.monotonic(), _get_process_identity(pid))
            dbg("find_cr3: PID %d => CR3=0x%X", pid, cr3)
            logger.info(f"[Driver] CR3 for PID {pid}: 0x{cr3:X}")
            return cr3

    dbg("find_cr3: FAILED for PID %d", pid)
    logger.warning(f"[Driver] Failed to find CR3 for PID {pid}")
    return 0

def invalidate_cr3_cache(pid: int = 0) -> None:
    if pid:
        _cr3_cache.pop(pid, None)
    else:
        _cr3_cache.clear()

def diagnose_kernel_reads(pid: int, module_base: int) -> None:
    if not _g_view:
        logger.warning("[Kernel Diag] Driver not connected")
        return

    logger.info("[Kernel Diag] Running kernel read diagnostics...")

    cr3 = find_cr3(pid, force=True)
    if not cr3:
        logger.error(
            "[Kernel Diag] FINDCR3 returned 0 — driver cannot resolve "
            "DirectoryTableBase for PID %d. The EPROCESS offset 0x28 "
            "may be wrong for this Windows build.", pid
        )
        return
    logger.info("[Kernel Diag] CR3 = 0x%X for PID %d", cr3, pid)

    READ_DIAG_MAGIC = 0x4449414744494147
    if _send_command(pid, module_base, 2, COMMAND_READ):
        mz_data = ctypes.string_at(_g_view + COMM_HEADER_SIZE, 2)
        if mz_data == b"MZ":
            logger.info(
                "[Kernel Diag] Small read OK — MZ signature at 0x%X confirmed",
                module_base,
            )
        else:
            logger.warning(
                "[Kernel Diag] Small read returned data but NOT MZ: %s",
                mz_data.hex(),
            )
    else:
        diag_raw = ctypes.string_at(_g_view + COMM_HEADER_SIZE, 64)
        diag_magic = struct.unpack_from("<Q", diag_raw, 0)[0]
        if diag_magic == READ_DIAG_MAGIC:
            diag_cr3 = struct.unpack_from("<Q", diag_raw, 8)[0]
            diag_phys = struct.unpack_from("<Q", diag_raw, 16)[0]
            diag_pml4e = struct.unpack_from("<Q", diag_raw, 24)[0]
            diag_pdpte = struct.unpack_from("<Q", diag_raw, 32)[0]
            diag_pde = struct.unpack_from("<Q", diag_raw, 40)[0]
            diag_pte = struct.unpack_from("<Q", diag_raw, 48)[0]
            diag_status = struct.unpack_from("<I", diag_raw, 56)[0]
            diag_bytes = struct.unpack_from("<I", diag_raw, 60)[0]

            logger.error(
                "[Kernel Diag] Read FAILED — page table walk for 0x%X:",
                module_base,
            )
            logger.error(
                "[Kernel Diag]   CR3 used:    0x%X", diag_cr3
            )
            pml4_present = "PRESENT" if (diag_pml4e & 1) else "NOT PRESENT"
            logger.error(
                "[Kernel Diag]   PML4E [%d]:  0x%X (%s)",
                (module_base >> 39) & 0x1FF, diag_pml4e, pml4_present,
            )
            if diag_pml4e & 1:
                pdpt_present = "PRESENT" if (diag_pdpte & 1) else "NOT PRESENT"
                logger.error(
                    "[Kernel Diag]   PDPTE [%d]: 0x%X (%s)",
                    (module_base >> 30) & 0x1FF, diag_pdpte, pdpt_present,
                )
            if diag_pdpte & 1:
                pde_present = "PRESENT" if (diag_pde & 1) else "NOT PRESENT"
                logger.error(
                    "[Kernel Diag]   PDE [%d]:   0x%X (%s)",
                    (module_base >> 21) & 0x1FF, diag_pde, pde_present,
                )
            if diag_pde & 1:
                pte_present = "PRESENT" if (diag_pte & 1) else "NOT PRESENT"
                logger.error(
                    "[Kernel Diag]   PTE [%d]:   0x%X (%s)",
                    (module_base >> 12) & 0x1FF, diag_pte, pte_present,
                )
            logger.error(
                "[Kernel Diag]   VirtToPhys result: 0x%X", diag_phys
            )
            logger.error(
                "[Kernel Diag]   ReadPhys status: 0x%X, bytesRead: %d",
                diag_status, diag_bytes,
            )
            if not (diag_pml4e & 1):
                logger.error(
                    "[Kernel Diag]   >>> PML4 entry NOT PRESENT — CR3 0x%X "
                    "does not map user-space for this process. "
                    "This may be the kernel DTB (KVAS). Try UserDirectoryTableBase.",
                    diag_cr3,
                )
        else:
            logger.error(
                "[Kernel Diag] Small read at 0x%X FAILED (no driver diag available)",
                module_base,
            )
        logger.info("[Kernel Diag] Diagnostics complete.")
        return

    logger.info("[Kernel Diag] Diagnostics complete.")

def _read_memory_kernel_command(pid: int, address: int, size: int, command: int) -> KernelReadResult:
    if not _g_view:
        logger.warning(
            "[Driver] read_memory_kernel called but driver is not connected."
        )
        return KernelReadResult(data=b"", total_chunks=0, failed_chunks=frozenset())

    tolerant = command == COMMAND_READ_TOLERANT

    if size <= COMM_DATA_MAXSIZE:
        if _send_command(pid, address, size, command):
            return KernelReadResult(
                data=ctypes.string_at(_g_view + COMM_HEADER_SIZE, size),
                total_chunks=1,
                failed_chunks=frozenset(),
            )
        dbg(
            "read_memory_kernel%s: FAILED single read at 0x%X (%d bytes)",
            "_tolerant" if tolerant else "",
            address,
            size,
        )
        return KernelReadResult(data=b"", total_chunks=1, failed_chunks=frozenset({0}))

    total_chunks = (size + COMM_DATA_MAXSIZE - 1) // COMM_DATA_MAXSIZE
    if size > 0x10000:
        dbg(
            "read_memory_kernel%s: large read 0x%X + 0x%X (%d chunks)",
            "_tolerant" if tolerant else "",
            address,
            size,
            total_chunks,
        )
    result = bytearray(size)
    offset = 0
    chunk_idx = 0
    total_failed = 0
    total_success = 0
    consecutive_fails = 0
    failed_set: set = set()

    with bulk_read_mode():
        while offset < size:
            chunk = min(COMM_DATA_MAXSIZE, size - offset)
            if _send_command(pid, address + offset, chunk, command):
                data = ctypes.string_at(_g_view + COMM_HEADER_SIZE, chunk)
                result[offset:offset + chunk] = data
                total_success += 1
                consecutive_fails = 0
            else:
                total_failed += 1
                consecutive_fails += 1
                failed_set.add(chunk_idx)

                if consecutive_fails >= 50 and (consecutive_fails % 50) == 0:
                    dbg(
                        "read_memory_kernel%s: %d consecutive failures at "
                        "offset 0x%X (continuing, %d/%d success so far)",
                        "_tolerant" if tolerant else "",
                        consecutive_fails,
                        offset,
                        total_success,
                        total_chunks,
                    )
            offset += chunk
            chunk_idx += 1

    if total_failed:
        pct = total_success * 100 // max(total_chunks, 1)
        dbg(
            "read_memory_kernel%s: completed %d/%d chunks OK (%d%% readable)",
            "_tolerant" if tolerant else "",
            total_success,
            total_chunks,
            pct,
        )
    return KernelReadResult(
        data=bytes(result),
        total_chunks=total_chunks,
        failed_chunks=frozenset(failed_set),
    )

def read_memory_kernel(pid: int, address: int, size: int) -> bytes:
    result = _store_last_read_result(
        _read_memory_kernel_command(pid, address, size, COMMAND_READ)
    )
    return result.data

def read_memory_kernel_tolerant(pid: int, address: int, size: int) -> bytes:
    result = _store_last_read_result(
        _read_memory_kernel_command(pid, address, size, COMMAND_READ_TOLERANT)
    )
    return result.data

def read_memory_kernel_ex(pid: int, address: int, size: int, tolerant: bool = False) -> KernelReadResult:
    cmd = COMMAND_READ_TOLERANT if tolerant else COMMAND_READ
    return _store_last_read_result(_read_memory_kernel_command(pid, address, size, cmd))

def write_memory_kernel(pid: int, address: int, data: bytes) -> bool:
    if not _g_view:
        logger.warning(
            "[Driver] write_memory_kernel called but driver is not connected."
        )
        return False

    offset = 0
    total = len(data)
    while offset < total:
        chunk = min(COMM_DATA_MAXSIZE, total - offset)
        ctypes.memmove(_g_view + COMM_HEADER_SIZE, data[offset : offset + chunk], chunk)
        if not _send_command(pid, address + offset, chunk, COMMAND_WRITE):
            return False
        offset += chunk
    return True

def scatter_read(
    pid: int,
    requests: List[Tuple[int, int]],
    timeout_ms: int = 1000,
) -> List[bytes]:
    if not _g_view or not requests:
        return [b""] * len(requests)

    safe_requests = []
    for addr, sz in requests:
        if addr < 0 or addr > 0xFFFFFFFFFFFFFFFF:
            addr = 0
        safe_requests.append((addr, sz))
    requests = safe_requests

    results: List[bytes] = []

    idx = 0
    while idx < len(requests):
        batch_end = idx
        total_response_size = 0
        entries_size = 0

        while batch_end < len(requests):
            addr, sz = requests[batch_end]
            new_entries_size = entries_size + SCATTER_ENTRY_SIZE
            new_response_size = total_response_size + sz

            if max(new_entries_size, new_response_size) > COMM_DATA_MAXSIZE:
                break

            entries_size = new_entries_size
            total_response_size = new_response_size
            batch_end += 1

        if batch_end == idx:
            addr, sz = requests[idx]
            results.append(read_memory_kernel(pid, addr, sz))
            idx += 1
            continue

        batch = requests[idx:batch_end]
        num_entries = len(batch)

        entry_data = bytearray()
        for addr, sz in batch:
            entry_data.extend(_SCATTER_ENTRY.pack(addr, sz))

        ctypes.memmove(
            _g_view + COMM_HEADER_SIZE,
            bytes(entry_data),
            len(entry_data),
        )

        if _send_command(
            pid, num_entries, total_response_size,
            COMMAND_SCATTER_READ, timeout_ms=timeout_ms, retries=1,
        ):
            raw = ctypes.string_at(_g_view + COMM_HEADER_SIZE, total_response_size)
            offset = 0
            for _, sz in batch:
                if offset + sz <= len(raw):
                    results.append(raw[offset:offset + sz])
                else:
                    results.append(b"\x00" * sz)
                offset += sz
        else:
            logger.debug(
                f"[Driver] Scatter read failed for batch of {num_entries}, "
                f"falling back to individual reads"
            )
            for addr, sz in batch:
                results.append(read_memory_kernel(pid, addr, sz))

        idx = batch_end

    return results

def get_module_base_kernel(pid: int, timeout_ms: int = 1000) -> int:
    if not _g_view:
        return 0

    if _send_command(pid, 0, 64, COMMAND_GETBASE, timeout_ms=timeout_ms, retries=2):
        raw = ctypes.string_at(_g_view + COMM_HEADER_SIZE, 8)
        base = struct.unpack_from("<Q", raw)[0]
        if base and base > 0x10000 and (base & 0xFFF) == 0 and base < 0x7FFFFFFFFFFF:
            return base
    return 0

def get_module_size_kernel(pid: int, module_base: int) -> int:
    if not module_base:
        return 0

    pe_data = read_memory_kernel(pid, module_base, 0x400)
    if not pe_data or len(pe_data) < 0x100:
        return 0

    if pe_data[:2] != b"MZ":
        return 0

    e_lfanew = struct.unpack_from("<I", pe_data, 0x3C)[0]
    if not e_lfanew or e_lfanew + 0x58 > len(pe_data):
        return 0

    if pe_data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return 0

    size_of_image = struct.unpack_from("<I", pe_data, e_lfanew + 0x50)[0]
    if 0x1000 < size_of_image < 0x20000000:
        return size_of_image

    return 0

def iter_readable_regions_kernel(pid: int) -> Iterator[Tuple[int, int]]:
    base = get_module_base_kernel(pid)
    if base:
        size = get_module_size_kernel(pid, base)
        if size:
            logger.info(
                f"[Driver] Module at 0x{base:X}, size 0x{size:X} "
                f"({size // (1024 * 1024)} MB) — from PE header"
            )
            yield (base, size)
            return

        logger.info(
            f"[Driver] Module at 0x{base:X}, PE size unavailable — "
            f"using 256 MB scan window"
        )
        yield (base, 256 * 1024 * 1024)
        return

    logger.warning(
        "[Driver] GETBASE failed — falling back to Win32 module enumeration. "
        "This may fail under kernel-level anti-cheat."
    )
    from src.core.memory import get_module_info, get_running_processes

    for p, name in get_running_processes():
        if p == pid:
            mod_base, mod_size = get_module_info(pid, name)
            if mod_base and mod_size:
                yield (mod_base, mod_size)
            return
