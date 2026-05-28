from __future__ import annotations

import ctypes
import logging
import os
import sys
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

ABI_VERSION = 1
DEFAULT_DLL_NAME = "gamesdk_native.dll"
ENV_DLL_PATH = "GSDK_NATIVE_BACKEND_DLL"
ENV_MEMORY_BACKEND = "GSDK_MEMORY_BACKEND"

GSD_OK = 0
GSD_ERROR = 1
GSD_PARTIAL = 2
GSD_INVALID_ARGUMENT = 3
GSD_NOT_FOUND = 4


class NativeBackendError(RuntimeError):
    pass


class NativeReadRequest(ctypes.Structure):
    _fields_ = [
        ("address", ctypes.c_uint64),
        ("size", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
    ]


class NativeReadResult(ctypes.Structure):
    _fields_ = [
        ("bytes_read", ctypes.c_uint32),
        ("status", ctypes.c_uint32),
    ]


class NativeModuleInfo(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_wchar * 260),
        ("path", ctypes.c_wchar * 260),
        ("base", ctypes.c_uint64),
        ("size", ctypes.c_uint64),
    ]


class NativeMemoryRegion(ctypes.Structure):
    _fields_ = [
        ("base", ctypes.c_uint64),
        ("size", ctypes.c_uint64),
        ("protect", ctypes.c_uint32),
        ("type", ctypes.c_uint32),
    ]


class NativePatternByte(ctypes.Structure):
    _fields_ = [
        ("value", ctypes.c_uint8),
        ("mask", ctypes.c_uint8),
    ]


class NativePeFingerprint(ctypes.Structure):
    _fields_ = [
        ("machine", ctypes.c_uint16),
        ("number_of_sections", ctypes.c_uint16),
        ("timestamp", ctypes.c_uint32),
        ("size_of_image", ctypes.c_uint32),
        ("checksum", ctypes.c_uint32),
        ("entry_point_rva", ctypes.c_uint32),
        ("header_fingerprint", ctypes.c_uint64),
    ]


@dataclass(frozen=True)
class BackendStatus:
    requested: str
    available: bool
    active: bool
    path: str = ""
    error: str = ""


def _repo_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _runtime_root() -> str:
    return os.path.abspath(getattr(sys, "_MEIPASS", _repo_root()))


def candidate_dll_paths() -> List[str]:
    paths: List[str] = []
    env_path = os.environ.get(ENV_DLL_PATH)
    if env_path:
        paths.append(env_path)

    runtime_root = _runtime_root()
    repo_root = _repo_root()
    paths.extend(
        [
            os.path.join(runtime_root, "bin", DEFAULT_DLL_NAME),
            os.path.join(repo_root, "bin", DEFAULT_DLL_NAME),
            os.path.join(repo_root, DEFAULT_DLL_NAME),
        ]
    )

    seen = set()
    unique: List[str] = []
    for path in paths:
        norm = os.path.normcase(os.path.abspath(path))
        if norm in seen:
            continue
        seen.add(norm)
        unique.append(path)
    return unique


def parse_pattern(pattern: str) -> Tuple[List[int], List[bool]]:
    values: List[int] = []
    masks: List[bool] = []
    for token in pattern.strip().split():
        if token in ("?", "??"):
            values.append(0)
            masks.append(False)
            continue
        values.append(int(token, 16) & 0xFF)
        masks.append(True)
    return values, masks


def _match_at(data: bytes, offset: int, values: Sequence[int], masks: Sequence[bool]) -> bool:
    for i, masked in enumerate(masks):
        if masked and data[offset + i] != values[i]:
            return False
    return True


def scan_buffer(
    data: bytes,
    base_address: int,
    pattern: str,
    max_results: int = 50,
) -> List[int]:
    values, masks = parse_pattern(pattern)
    pat_len = len(values)
    if not data or pat_len == 0 or max_results <= 0 or len(data) < pat_len:
        return []

    results: List[int] = []
    search_end = len(data) - pat_len + 1
    for offset in range(search_end):
        if _match_at(data, offset, values, masks):
            results.append(base_address + offset)
            if len(results) >= max_results:
                break
    return results


class NativeBackend:
    def __init__(self, dll_path: Optional[str] = None):
        self.path = ""
        self.load_error = ""
        self._dll = None

        paths = [dll_path] if dll_path else candidate_dll_paths()
        for path in paths:
            if not path:
                continue
            abs_path = os.path.abspath(path)
            if not os.path.isfile(abs_path):
                continue
            try:
                dll = ctypes.WinDLL(abs_path)
                self._bind(dll)
                version = int(dll.gsd_abi_version())
                if version != ABI_VERSION:
                    raise NativeBackendError(
                        f"unsupported ABI {version}; expected {ABI_VERSION}"
                    )
                self._dll = dll
                self.path = abs_path
                self.load_error = ""
                logger.info("Loaded native memory backend: %s", abs_path)
                return
            except Exception as exc:
                self.load_error = f"{abs_path}: {exc}"
                logger.debug("Native backend load failed: %s", self.load_error)

        if not self.load_error:
            self.load_error = f"{DEFAULT_DLL_NAME} not found"

    @property
    def available(self) -> bool:
        return self._dll is not None

    def _require(self):
        if self._dll is None:
            raise NativeBackendError(self.load_error or "native backend unavailable")
        return self._dll

    @staticmethod
    def _bind(dll) -> None:
        dll.gsd_abi_version.argtypes = []
        dll.gsd_abi_version.restype = ctypes.c_uint32

        dll.gsd_attach.argtypes = [
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        dll.gsd_attach.restype = ctypes.c_uint64

        dll.gsd_detach.argtypes = [ctypes.c_uint64]
        dll.gsd_detach.restype = None

        dll.gsd_read.argtypes = [
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        dll.gsd_read.restype = ctypes.c_uint32

        dll.gsd_scatter_read.argtypes = [
            ctypes.c_uint64,
            ctypes.POINTER(NativeReadRequest),
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_uint32,
            ctypes.POINTER(NativeReadResult),
        ]
        dll.gsd_scatter_read.restype = ctypes.c_uint32

        dll.gsd_enumerate_modules.argtypes = [
            ctypes.c_uint32,
            ctypes.POINTER(NativeModuleInfo),
            ctypes.c_uint32,
        ]
        dll.gsd_enumerate_modules.restype = ctypes.c_uint32

        dll.gsd_get_module_info.argtypes = [
            ctypes.c_uint32,
            ctypes.c_wchar_p,
            ctypes.POINTER(NativeModuleInfo),
        ]
        dll.gsd_get_module_info.restype = ctypes.c_uint32

        dll.gsd_iter_readable_regions.argtypes = [
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.POINTER(NativeMemoryRegion),
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint64),
        ]
        dll.gsd_iter_readable_regions.restype = ctypes.c_uint32

        dll.gsd_scan_pattern.argtypes = [
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.POINTER(NativePatternByte),
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_uint32,
        ]
        dll.gsd_scan_pattern.restype = ctypes.c_uint32

        dll.gsd_resolve_rip.argtypes = [
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint64),
        ]
        dll.gsd_resolve_rip.restype = ctypes.c_uint32

        dll.gsd_pe_fingerprint.argtypes = [
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.POINTER(NativePeFingerprint),
        ]
        dll.gsd_pe_fingerprint.restype = ctypes.c_uint32

    def attach(self, pid: int, access: int) -> Optional[int]:
        dll = self._require()
        error = ctypes.c_uint32(0)
        handle = int(dll.gsd_attach(int(pid), int(access), ctypes.byref(error)))
        if not handle:
            logger.debug("native attach failed for pid=%d error=%d", pid, error.value)
            return None
        return handle

    def detach(self, handle: int) -> None:
        if handle:
            self._require().gsd_detach(int(handle))

    def read_bytes(self, handle: int, address: int, size: int) -> bytes:
        if size <= 0:
            return b""
        if size > 0xFFFFFFFF:
            raise ValueError("native reads are limited to 4 GB per request")
        dll = self._require()
        buf = (ctypes.c_uint8 * size)()
        bytes_read = ctypes.c_uint32(0)
        status = int(
            dll.gsd_read(
                int(handle),
                int(address),
                buf,
                int(size),
                ctypes.byref(bytes_read),
            )
        )
        if status not in (GSD_OK, GSD_PARTIAL) or bytes_read.value == 0:
            return b""
        return bytes(bytearray(buf)[: bytes_read.value])

    def scatter_read(self, handle: int, requests: Iterable[Tuple[int, int]]) -> List[bytes]:
        req_list = [(int(address), int(size)) for address, size in requests]
        if not req_list:
            return []

        max_size = max(max(size, 0) for _, size in req_list)
        if max_size <= 0:
            return [b"" for _ in req_list]
        if max_size > 0xFFFFFFFF:
            raise ValueError("native scatter read request is too large")

        dll = self._require()
        count = len(req_list)
        req_array = (NativeReadRequest * count)(
            *[
                NativeReadRequest(address=address, size=max(0, size), reserved=0)
                for address, size in req_list
            ]
        )
        result_array = (NativeReadResult * count)()
        out_size = max_size * count
        out_buf = (ctypes.c_uint8 * out_size)()
        dll.gsd_scatter_read(
            int(handle),
            req_array,
            count,
            out_buf,
            max_size,
            result_array,
        )

        raw = bytearray(out_buf)
        results: List[bytes] = []
        for i, result in enumerate(result_array):
            if result.status not in (GSD_OK, GSD_PARTIAL) or result.bytes_read == 0:
                results.append(b"")
                continue
            start = i * max_size
            results.append(bytes(raw[start : start + result.bytes_read]))
        return results

    def enumerate_modules(self, pid: int, capacity: int = 1024) -> List[Tuple[str, int, int, str]]:
        dll = self._require()
        modules: List[Tuple[str, int, int, str]] = []
        capacity = max(1, int(capacity))
        while True:
            array = (NativeModuleInfo * capacity)()
            total = int(dll.gsd_enumerate_modules(int(pid), array, capacity))
            take = min(total, capacity)
            modules = [
                (array[i].name, int(array[i].base), int(array[i].size), array[i].path)
                for i in range(take)
            ]
            if total <= capacity:
                return modules
            capacity = total

    def get_module_info(self, pid: int, module_name: str) -> Tuple[int, int]:
        dll = self._require()
        info = NativeModuleInfo()
        status = int(dll.gsd_get_module_info(int(pid), str(module_name), ctypes.byref(info)))
        if status != GSD_OK:
            return 0, 0
        return int(info.base), int(info.size)

    def iter_readable_regions(self, handle: int, capacity: int = 4096) -> List[Tuple[int, int]]:
        dll = self._require()
        start = 0
        regions: List[Tuple[int, int]] = []
        capacity = max(1, int(capacity))
        while True:
            array = (NativeMemoryRegion * capacity)()
            next_address = ctypes.c_uint64(0)
            count = int(
                dll.gsd_iter_readable_regions(
                    int(handle),
                    int(start),
                    array,
                    capacity,
                    ctypes.byref(next_address),
                )
            )
            for i in range(min(count, capacity)):
                regions.append((int(array[i].base), int(array[i].size)))
            if next_address.value == 0 or count < capacity:
                break
            if next_address.value <= start:
                break
            start = int(next_address.value)
        return regions

    def scan_pattern(
        self,
        handle: int,
        module_base: int,
        module_size: int,
        pattern: str,
        max_results: int = 50,
    ) -> List[int]:
        values, masks = parse_pattern(pattern)
        if not values or max_results <= 0:
            return []
        dll = self._require()
        pattern_array = (NativePatternByte * len(values))(
            *[
                NativePatternByte(value=value, mask=1 if masked else 0)
                for value, masked in zip(values, masks)
            ]
        )
        out = (ctypes.c_uint64 * max_results)()
        count = int(
            dll.gsd_scan_pattern(
                int(handle),
                int(module_base),
                int(module_size),
                pattern_array,
                len(values),
                out,
                int(max_results),
            )
        )
        return [int(out[i]) for i in range(min(count, max_results))]

    def resolve_rip(
        self,
        handle: int,
        match_address: int,
        disp_offset: int = 3,
        instruction_size: int = 7,
    ) -> int:
        dll = self._require()
        target = ctypes.c_uint64(0)
        status = int(
            dll.gsd_resolve_rip(
                int(handle),
                int(match_address),
                int(disp_offset),
                int(instruction_size),
                ctypes.byref(target),
            )
        )
        return int(target.value) if status == GSD_OK else 0

    def pe_fingerprint(self, handle: int, module_base: int) -> dict:
        dll = self._require()
        fp = NativePeFingerprint()
        status = int(dll.gsd_pe_fingerprint(int(handle), int(module_base), ctypes.byref(fp)))
        if status != GSD_OK:
            return {}
        return {
            "machine": int(fp.machine),
            "number_of_sections": int(fp.number_of_sections),
            "timestamp": int(fp.timestamp),
            "size_of_image": int(fp.size_of_image),
            "checksum": int(fp.checksum),
            "entry_point_rva": int(fp.entry_point_rva),
            "header_fingerprint": f"{int(fp.header_fingerprint):016x}",
        }


_backend: Optional[NativeBackend] = None


def get_native_backend() -> NativeBackend:
    global _backend
    if _backend is None:
        _backend = NativeBackend()
    return _backend


def reset_native_backend_for_tests() -> None:
    global _backend
    _backend = None
