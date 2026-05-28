"""
Hardware Breakpoint Tracer for Windows x64

Uses Windows debug APIs (DebugActiveProcess, SetThreadContext with DR0-DR3)
to set hardware write-breakpoints and trace which instructions write to target
memory addresses.

Integrates with existing src.core.memory process model.
"""

import ctypes
import ctypes.wintypes as wt
import struct
import time
from dataclasses import dataclass
from typing import Optional, List, Callable


_k32 = ctypes.WinDLL("kernel32", use_last_error=True)

# Debug API constants
DEBUG_PROCESS = 0x00000001
DEBUG_ONLY_THIS_PROCESS = 0x00000002
EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9

DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x00010001
DBG_TERMINATE_PROCESS = 0x40010001

EXCEPTION_SINGLE_STEP = 0x80000004
EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_BREAKPOINT = 0x80000003

# CONTEXT flags for x64
CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = CONTEXT_AMD64 | 0x00000001
CONTEXT_INTEGER = CONTEXT_AMD64 | 0x00000002
CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x00000004
CONTEXT_FLOATING_POINT = CONTEXT_AMD64 | 0x00000008
CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x00000010
CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS
CONTEXT_ALL = CONTEXT_FULL | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS


class EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [
        ("ExceptionCode", wt.DWORD),
        ("ExceptionFlags", wt.DWORD),
        ("ExceptionRecord", ctypes.c_void_p),
        ("ExceptionAddress", ctypes.c_void_p),
        ("NumberParameters", wt.DWORD),
        ("__unusedAlignment", wt.DWORD),
        ("ExceptionInformation", ctypes.c_ulonglong * 15),
    ]


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance", wt.DWORD),
    ]


class CREATE_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hThread", wt.HANDLE),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.c_void_p),
    ]


class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile", wt.HANDLE),
        ("hProcess", wt.HANDLE),
        ("hThread", wt.HANDLE),
        ("lpBaseOfImage", ctypes.c_void_p),
        ("dwDebugInfoFileOffset", wt.DWORD),
        ("nDebugInfoSize", wt.DWORD),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.c_void_p),
        ("lpImageName", ctypes.c_void_p),
        ("fUnicode", wt.WORD),
    ]


class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile", wt.HANDLE),
        ("lpBaseOfDll", ctypes.c_void_p),
        ("dwDebugInfoFileOffset", wt.DWORD),
        ("nDebugInfoSize", wt.DWORD),
        ("lpImageName", ctypes.c_void_p),
        ("fUnicode", wt.WORD),
    ]


class DEBUG_EVENT_U(ctypes.Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateThread", CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread", ctypes.c_ulonglong * 2),
        ("ExitProcess", ctypes.c_ulonglong * 2),
        ("LoadDll", LOAD_DLL_DEBUG_INFO),
        ("UnloadDll", ctypes.c_ulonglong * 2),
        ("DebugString", ctypes.c_ulonglong * 4),
        ("RipInfo", ctypes.c_ulonglong * 2),
    ]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ("dwDebugEventCode", wt.DWORD),
        ("dwProcessId", wt.DWORD),
        ("dwThreadId", wt.DWORD),
        ("u", DEBUG_EVENT_U),
    ]


class _CONTEXT_RAW(ctypes.Structure):
    """Raw 1232-byte x64 CONTEXT buffer. Fields accessed by offset."""
    _fields_ = [("_raw", ctypes.c_byte * 1232)]


class CONTEXT:
    """Wrapper around raw CONTEXT buffer with field accessors."""

    # Offsets into the raw buffer
    OFF_ContextFlags = 0x30
    OFF_Dr0 = 0x48
    OFF_Dr1 = 0x50
    OFF_Dr2 = 0x58
    OFF_Dr3 = 0x60
    OFF_Dr6 = 0x68
    OFF_Dr7 = 0x70
    OFF_Rax = 0x448
    OFF_Rcx = 0x450
    OFF_Rdx = 0x458
    OFF_Rbx = 0x460
    OFF_Rsp = 0x468
    OFF_Rbp = 0x470
    OFF_Rsi = 0x478
    OFF_Rdi = 0x480
    OFF_R8 = 0x488
    OFF_R9 = 0x490
    OFF_R10 = 0x498
    OFF_R11 = 0x4A0
    OFF_R12 = 0x4A8
    OFF_R13 = 0x4B0
    OFF_R14 = 0x4B8
    OFF_R15 = 0x4C0
    OFF_Rip = 0x4C8

    def __init__(self):
        # Allocate with 16-byte alignment using a ctypes array
        self._buf = (ctypes.c_byte * 1232)()
        self._addr = ctypes.addressof(self._buf)

    def _read_u64(self, offset: int) -> int:
        return ctypes.cast(self._addr + offset, ctypes.POINTER(ctypes.c_ulonglong)).contents.value

    def _write_u64(self, offset: int, value: int):
        ctypes.cast(self._addr + offset, ctypes.POINTER(ctypes.c_ulonglong)).contents.value = value

    def _read_u32(self, offset: int) -> int:
        return ctypes.cast(self._addr + offset, ctypes.POINTER(ctypes.c_uint32)).contents.value

    def _write_u32(self, offset: int, value: int):
        ctypes.cast(self._addr + offset, ctypes.POINTER(ctypes.c_uint32)).contents.value = value

    @property
    def ContextFlags(self) -> int:
        return self._read_u32(self.OFF_ContextFlags)

    @ContextFlags.setter
    def ContextFlags(self, value: int):
        self._write_u32(self.OFF_ContextFlags, value)

    @property
    def Dr0(self) -> int:
        return self._read_u64(self.OFF_Dr0)

    @Dr0.setter
    def Dr0(self, value: int):
        self._write_u64(self.OFF_Dr0, value)

    @property
    def Dr1(self) -> int:
        return self._read_u64(self.OFF_Dr1)

    @Dr1.setter
    def Dr1(self, value: int):
        self._write_u64(self.OFF_Dr1, value)

    @property
    def Dr2(self) -> int:
        return self._read_u64(self.OFF_Dr2)

    @Dr2.setter
    def Dr2(self, value: int):
        self._write_u64(self.OFF_Dr2, value)

    @property
    def Dr3(self) -> int:
        return self._read_u64(self.OFF_Dr3)

    @Dr3.setter
    def Dr3(self, value: int):
        self._write_u64(self.OFF_Dr3, value)

    @property
    def Dr6(self) -> int:
        return self._read_u64(self.OFF_Dr6)

    @Dr6.setter
    def Dr6(self, value: int):
        self._write_u64(self.OFF_Dr6, value)

    @property
    def Dr7(self) -> int:
        return self._read_u64(self.OFF_Dr7)

    @Dr7.setter
    def Dr7(self, value: int):
        self._write_u64(self.OFF_Dr7, value)

    @property
    def Rax(self) -> int:
        return self._read_u64(self.OFF_Rax)

    @property
    def Rcx(self) -> int:
        return self._read_u64(self.OFF_Rcx)

    @property
    def Rdx(self) -> int:
        return self._read_u64(self.OFF_Rdx)

    @property
    def Rbx(self) -> int:
        return self._read_u64(self.OFF_Rbx)

    @property
    def Rsp(self) -> int:
        return self._read_u64(self.OFF_Rsp)

    @property
    def Rbp(self) -> int:
        return self._read_u64(self.OFF_Rbp)

    @property
    def Rsi(self) -> int:
        return self._read_u64(self.OFF_Rsi)

    @property
    def Rdi(self) -> int:
        return self._read_u64(self.OFF_Rdi)

    @property
    def R8(self) -> int:
        return self._read_u64(self.OFF_R8)

    @property
    def R9(self) -> int:
        return self._read_u64(self.OFF_R9)

    @property
    def R10(self) -> int:
        return self._read_u64(self.OFF_R10)

    @property
    def R11(self) -> int:
        return self._read_u64(self.OFF_R11)

    @property
    def R12(self) -> int:
        return self._read_u64(self.OFF_R12)

    @property
    def R13(self) -> int:
        return self._read_u64(self.OFF_R13)

    @property
    def R14(self) -> int:
        return self._read_u64(self.OFF_R14)

    @property
    def R15(self) -> int:
        return self._read_u64(self.OFF_R15)

    @property
    def Rip(self) -> int:
        return self._read_u64(self.OFF_Rip)

    def __ctypes_from_outparam__(self):
        """Allow ctypes to use this object as a pointer."""
        return ctypes.cast(self._addr, ctypes.POINTER(_CONTEXT_RAW))

    def byref(self):
        """Return a byref suitable for GetThreadContext/SetThreadContext."""
        return ctypes.byref(self._buf)


@dataclass
class BreakpointHit:
    """Information about a hardware breakpoint hit."""

    breakpoint_index: int
    instruction_address: int
    write_address: int
    dr6: int
    dr7: int
    thread_id: int
    call_stack: List[int]
    exception_address: int = 0


class DebugTracer:
    """
    Windows hardware breakpoint tracer.

    Usage:
        tracer = DebugTracer(pid)
        tracer.set_hw_breakpoint(0xADDRESS, size=4, bp_index=0)
        hit = tracer.run(timeout=10.0)
        if hit:
            print(f"Hit at 0x{hit.instruction_address:X}")
        tracer.detach()
    """

    def __init__(self, pid: int):
        self.pid = pid
        self.attached = False
        self._bp_addresses = [0, 0, 0, 0]  # DR0-DR3
        self._bp_sizes = [1, 1, 1, 1]
        self._bp_types = ["write", "write", "write", "write"]
        self._bp_active = [False, False, False, False]
        self._thread_handles = {}  # tid -> handle
        self._process_handle = None

    def attach(self) -> bool:
        """Attach debugger to target process."""
        if self.attached:
            return True

        ok = _k32.DebugActiveProcess(self.pid)
        if not ok:
            err = ctypes.get_last_error()
            if err == 5:  # ERROR_ACCESS_DENIED
                print(
                    f"[!] Access denied attaching to PID {self.pid}. "
                    "Try running as Administrator."
                )
            elif err == 87:  # ERROR_INVALID_PARAMETER
                print(f"[!] Invalid PID {self.pid}")
            else:
                print(f"[!] DebugActiveProcess failed: error {err}")
            return False

        self.attached = True
        print(f"[+] Debugger attached to PID {self.pid}")

        # Consume initial events quickly
        self._pump_initial_events(timeout_ms=3000)
        return True

    def _pump_initial_events(self, timeout_ms: int = 3000):
        """Handle create/process/thread events that occur on attach."""
        start = time.time()
        event = DEBUG_EVENT()
        while time.time() - start < timeout_ms / 1000.0:
            ret = _k32.WaitForDebugEvent(ctypes.byref(event), 100)
            if ret:
                if event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT:
                    self._process_handle = event.u.CreateProcessInfo.hProcess
                    self._thread_handles[event.dwThreadId] = (
                        event.u.CreateProcessInfo.hThread
                    )
                elif event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT:
                    self._thread_handles[event.dwThreadId] = (
                        event.u.CreateThread.hThread
                    )
                elif event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT:
                    self._thread_handles.pop(event.dwThreadId, None)

                # Continue all initial events
                _k32.ContinueDebugEvent(
                    event.dwProcessId, event.dwThreadId, DBG_CONTINUE
                )
            else:
                break

    def set_hw_breakpoint(
        self,
        address: int,
        size: int = 4,
        bp_type: str = "write",
        bp_index: int = 0,
    ) -> bool:
        """
        Set a hardware breakpoint using debug registers.

        Args:
            address: Memory address to watch
            size: Watch size (1, 2, 4, or 8 bytes)
            bp_type: 'write', 'readwrite', or 'execute'
            bp_index: Which debug register (0-3)
        """
        if not (0 <= bp_index <= 3):
            print("[!] bp_index must be 0-3")
            return False

        if size not in (1, 2, 4, 8):
            print("[!] size must be 1, 2, 4, or 8")
            return False

        self._bp_addresses[bp_index] = address
        self._bp_sizes[bp_index] = size
        self._bp_types[bp_index] = bp_type
        self._bp_active[bp_index] = True

        # Build DR7 control word
        dr7 = self._build_dr7()

        # Apply to all threads
        for tid, h_thread in list(self._thread_handles.items()):
            ctx = CONTEXT()
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS

            if not _k32.GetThreadContext(h_thread, ctx.byref()):
                print(f"[!] GetThreadContext failed for tid={tid}")
                continue

            # Set the debug register
            if bp_index == 0:
                ctx.Dr0 = address
            elif bp_index == 1:
                ctx.Dr1 = address
            elif bp_index == 2:
                ctx.Dr2 = address
            elif bp_index == 3:
                ctx.Dr3 = address

            ctx.Dr7 = dr7
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS

            if not _k32.SetThreadContext(h_thread, ctx.byref()):
                print(f"[!] SetThreadContext failed for tid={tid}")
                return False

        print(
            f"[+] HW breakpoint {bp_index}: addr=0x{address:X} "
            f"size={size} type={bp_type}"
        )
        return True

    def _build_dr7(self) -> int:
        """Build DR7 control register value from active breakpoints."""
        dr7 = 0
        for i in range(4):
            if not self._bp_active[i]:
                continue

            # Local enable
            dr7 |= 1 << (i * 2)

            # Type (RW)
            t = self._bp_types[i]
            if t == "execute":
                rw = 0b00
            elif t == "write":
                rw = 0b01
            elif t == "readwrite":
                rw = 0b11
            else:
                rw = 0b01

            # Size
            s = self._bp_sizes[i]
            if s == 1:
                ln = 0b00
            elif s == 2:
                ln = 0b01
            elif s == 4:
                ln = 0b11
            elif s == 8:
                ln = 0b10
            else:
                ln = 0b11

            dr7 |= rw << (16 + i * 4)
            dr7 |= ln << (18 + i * 4)

        return dr7

    def run(
        self,
        timeout: float = 10.0,
        on_hit: Optional[Callable[[BreakpointHit], bool]] = None,
    ) -> Optional[BreakpointHit]:
        """
        Run the debug event loop until a breakpoint hits or timeout.

        Args:
            timeout: Maximum seconds to wait
            on_hit: Optional callback(hit) -> bool. Return False to stop.

        Returns:
            BreakpointHit if a hit occurred, None on timeout.
        """
        if not self.attached:
            print("[!] Not attached. Call attach() first.")
            return None

        print(f"[*] Waiting for breakpoint hit (timeout={timeout}s)...")
        start = time.time()
        event = DEBUG_EVENT()

        while time.time() - start < timeout:
            remaining_ms = max(1, int((timeout - (time.time() - start)) * 1000))
            ret = _k32.WaitForDebugEvent(ctypes.byref(event), min(remaining_ms, 100))

            if not ret:
                continue

            if event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                exc = event.u.Exception.ExceptionRecord
                code = exc.ExceptionCode
                addr = exc.ExceptionAddress
                tid = event.dwThreadId

                if code == EXCEPTION_SINGLE_STEP:
                    # Check DR6 to see which breakpoint triggered
                    h_thread = self._thread_handles.get(tid)
                    if not h_thread:
                        # New thread — try to open it
                        h_thread = _k32.OpenThread(
                            0x0010 | 0x0008 | 0x0040,  # GET_CONTEXT | SET_CONTEXT | SUSPEND_RESUME
                            False,
                            tid,
                        )
                        if h_thread:
                            self._thread_handles[tid] = h_thread

                    if h_thread:
                        ctx = CONTEXT()
                        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL
                        if _k32.GetThreadContext(h_thread, ctx.byref()):
                            dr6 = ctx.Dr6
                            dr7 = ctx.Dr7

                            # Determine which breakpoint triggered
                            bp_idx = None
                            for i in range(4):
                                if dr6 & (1 << i):
                                    bp_idx = i
                                    break

                            if bp_idx is not None and self._bp_active[bp_idx]:
                                # Build call stack
                                call_stack = self._read_call_stack(ctx)

                                # ExceptionAddress is often more reliable than ctx.Rip
                                exc_addr = ctypes.cast(
                                    exc.ExceptionAddress, ctypes.c_void_p
                                ).value or 0
                                rip = ctx.Rip or exc_addr

                                hit = BreakpointHit(
                                    breakpoint_index=bp_idx,
                                    instruction_address=rip,
                                    write_address=self._bp_addresses[bp_idx],
                                    dr6=dr6,
                                    dr7=dr7,
                                    thread_id=tid,
                                    call_stack=call_stack,
                                    exception_address=exc_addr,
                                )

                                print(
                                    f"[+] BREAKPOINT {bp_idx} HIT @ RIP=0x{rip:X} "
                                    f"EXC=0x{exc_addr:X} (tid={tid})"
                                )
                                print(f"    DR6=0x{dr6:08X} DR7=0x{dr7:08X}")
                                print(f"    Call stack: {[hex(a) for a in call_stack[:5]]}")

                                # Clear DR6 Bn bits
                                ctx.Dr6 = 0
                                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
                                _k32.SetThreadContext(h_thread, ctx.byref())

                                # Continue
                                _k32.ContinueDebugEvent(
                                    event.dwProcessId, tid, DBG_CONTINUE
                                )

                                if on_hit is None or on_hit(hit):
                                    return hit
                                else:
                                    continue

                # Not our breakpoint — pass through
                _k32.ContinueDebugEvent(
                    event.dwProcessId, tid, DBG_EXCEPTION_NOT_HANDLED
                )

            elif event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT:
                self._thread_handles[event.dwThreadId] = event.u.CreateThread.hThread
                _k32.ContinueDebugEvent(
                    event.dwProcessId, event.dwThreadId, DBG_CONTINUE
                )

            elif event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT:
                self._thread_handles.pop(event.dwThreadId, None)
                _k32.ContinueDebugEvent(
                    event.dwProcessId, event.dwThreadId, DBG_CONTINUE
                )

            elif event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
                print("[!] Target process exited")
                self.attached = False
                return None

            else:
                # LOAD_DLL, UNLOAD_DLL, OUTPUT_DEBUG_STRING, etc.
                _k32.ContinueDebugEvent(
                    event.dwProcessId, event.dwThreadId, DBG_CONTINUE
                )

        print("[*] Timeout reached, no breakpoint hit")
        return None

    def _read_call_stack(self, ctx: CONTEXT, depth: int = 10) -> List[int]:
        """Walk RBP chain to build a call stack."""
        stack = []
        try:
            rsp = ctx.Rsp
            rbp = ctx.Rbp
            rip = ctx.Rip
            stack.append(rip)

            # For x64, the return address is at [RSP] for leaf functions,
            # but for non-leaf it's at [RBP+8]. We need process memory access.
            # Since we don't have a ReadProcessMemory handle here, we'll just
            # capture RIP, RSP, RBP in the hit object and let the caller
            # resolve the stack if needed.
            stack.extend([rsp, rbp])
        except Exception:
            pass
        return stack

    def detach(self):
        """Detach debugger from target process."""
        if not self.attached:
            return

        # Clear all breakpoints before detaching
        for i in range(4):
            if self._bp_active[i]:
                self.clear_hw_breakpoint(i)

        _k32.DebugActiveProcessStop(self.pid)
        self.attached = False
        print(f"[+] Debugger detached from PID {self.pid}")

    def clear_hw_breakpoint(self, bp_index: int):
        """Clear a hardware breakpoint."""
        if not (0 <= bp_index <= 3):
            return

        self._bp_active[bp_index] = False
        self._bp_addresses[bp_index] = 0

        dr7 = self._build_dr7()
        for tid, h_thread in list(self._thread_handles.items()):
            ctx = CONTEXT()
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
            if _k32.GetThreadContext(h_thread, ctx.byref()):
                if bp_index == 0:
                    ctx.Dr0 = 0
                elif bp_index == 1:
                    ctx.Dr1 = 0
                elif bp_index == 2:
                    ctx.Dr2 = 0
                elif bp_index == 3:
                    ctx.Dr3 = 0
                ctx.Dr7 = dr7
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
                _k32.SetThreadContext(h_thread, ctx.byref())

    def __del__(self):
        self.detach()


def trace_memory_write(
    pid: int,
    target_address: int,
    size: int = 4,
    timeout: float = 10.0,
) -> Optional[BreakpointHit]:
    """
    Convenience function: attach, set breakpoint, run, detach.

    Args:
        pid: Target process ID
        target_address: Memory address to watch for writes
        size: Watch size in bytes
        timeout: Max seconds to wait

    Returns:
        BreakpointHit on success, None on timeout/error.
    """
    tracer = DebugTracer(pid)
    if not tracer.attach():
        return None

    try:
        if not tracer.set_hw_breakpoint(target_address, size=size, bp_index=0):
            return None
        return tracer.run(timeout=timeout)
    finally:
        tracer.detach()


if __name__ == "__main__":
    # Simple test: attach to a process and trace writes to an address
    import sys

    sys.path.insert(0, r"C:\Users\hunnid\Documents\code\01_My_Projects\Ue-offset-dumper")
    from src.core.memory import get_pid_by_name

    test_pid = get_pid_by_name("Brawlhalla.exe")
    if not test_pid:
        print("Brawlhalla.exe not running")
        sys.exit(1)

    print(f"Tracing PID {test_pid}...")
    # We'll trace a dummy address — in real usage you'd pass a valid heap addr
    hit = trace_memory_write(test_pid, 0x0, size=4, timeout=2.0)
    if hit:
        print(f"Hit: {hit}")
    else:
        print("No hit (expected for invalid address)")
