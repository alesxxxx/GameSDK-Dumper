
import ctypes
import ctypes.wintypes as wt
import logging
import os
import sys
import time

logger = logging.getLogger("sdkkit.debug")

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_OutputDebugStringW = _k32.OutputDebugStringW
_OutputDebugStringW.argtypes = [wt.LPCWSTR]
_OutputDebugStringW.restype = None

_DEBUG_ENABLED = True
_DEBUGVIEW_ENABLED = False
_PREFIX = "[SDKKIT] "
_start_time = time.monotonic()

_log_file = None
_log_path = ""

def _get_log_path() -> str:
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    return os.path.join(base, "sdkkit_debug.log")

def _ensure_log_file():
    global _log_file, _log_path
    if _log_file is not None:
        return
    try:
        _log_path = _get_log_path()
        _log_file = open(_log_path, "w", encoding="utf-8", buffering=1)
        _log_file.write(f"\n{'='*60}\n")
        _log_file.write(f"SDKKit debug session started at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        _log_file.write(f"{'='*60}\n")
    except Exception:
        _log_file = None

def get_log_path() -> str:
    _ensure_log_file()
    return _log_path

def set_debug_enabled(enabled: bool) -> None:
    global _DEBUG_ENABLED
    _DEBUG_ENABLED = enabled

def set_debugview_enabled(enabled: bool) -> None:
    global _DEBUGVIEW_ENABLED
    _DEBUGVIEW_ENABLED = enabled

def set_debug_prefix(prefix: str) -> None:
    global _PREFIX
    _PREFIX = prefix

def dbg(fmt: str, *args) -> None:
    if not _DEBUG_ENABLED:
        return

    try:
        msg = fmt % args if args else fmt
    except (TypeError, ValueError):
        msg = fmt

    elapsed = time.monotonic() - _start_time
    full_msg = f"{_PREFIX}[{elapsed:8.3f}s] {msg}"

    try:
        _ensure_log_file()
        if _log_file:
            _log_file.write(full_msg + "\n")
    except Exception:
        pass

    if _DEBUGVIEW_ENABLED:
        try:
            _OutputDebugStringW(full_msg)
        except Exception:
            pass

    logger.debug(full_msg)

def dbg_hex(label: str, data: bytes, max_bytes: int = 32) -> None:
    if not _DEBUG_ENABLED:
        return
    preview = data[:max_bytes]
    hex_str = " ".join(f"{b:02X}" for b in preview)
    suffix = f"... ({len(data)} total)" if len(data) > max_bytes else ""
    dbg("%s: %s%s", label, hex_str, suffix)

class _StdoutTee:
    def __init__(self, original_stdout):
        self.original_stdout = original_stdout

    def write(self, data):
        self.original_stdout.write(data)
        if _DEBUG_ENABLED:
            _ensure_log_file()
            if _log_file:
                _log_file.write(data)

    def flush(self):
        self.original_stdout.flush()
        if _DEBUG_ENABLED and _log_file:
            _log_file.flush()

    def isatty(self):
        return getattr(self.original_stdout, "isatty", lambda: False)()

def enable_stdout_tee():
    if not isinstance(sys.stdout, _StdoutTee):
        sys.stdout = _StdoutTee(sys.stdout)

