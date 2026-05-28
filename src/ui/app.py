
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.core.memory import get_pid_by_name, attach, detach, get_module_base, get_module_size
from src.core.gui_state import (
    append_dump_history,
    load_gui_settings,
    save_gui_settings,
)
from src.core.known_good import collect_known_good_records, normalize_game_key
from src.core.steam_secrets import load_steam_audit_settings, save_steam_audit_settings
from src.core.update_resolver import SteamUpdateResolver, parse_user_date
from src.core.steam_appid import infer_steam_appid
from src.core.webhook_settings import load_webhook_settings, save_webhook_settings
from src.core.steam_audit import (
    format_steam_audit_report,
    get_steam_accounts,
    get_steam_install_path,
    scan_steam_library,
    write_steam_audit_report,
)
from src.engines.ue.detector import detect_engine_full
from src.engines.ue.gnames import find_gnames, validate_gnames, clear_fname_cache
from src.engines.ue.gobjects import (
    clear_gobjects_scan_state,
    find_gobjects,
    get_last_gobjects_resolution_meta,
    get_object_count,
)
from src.engines.ue.gworld import find_gworld, validate_gworld, get_world_info, find_gengine
from src.engines.ue.sdk_walker import walk_sdk
from src.output.share_pack import create_partner_share_pack, create_share_pack
from src.output.json_writer import write_all

from src.ui.theme import (
    BG, BG_CARD, BG_INPUT, BG_HOVER, BORDER, SURFACE, OVERLAY,
    FG, FG_DIM, FG_SUBTLE,
    ACCENT, GREEN, YELLOW, RED, PURPLE, TEAL, CYAN,
    COPY_FLASH,
    FONT_UI, FONT_UI_SM, FONT_UI_XS, FONT_UI_BOLD, FONT_UI_LG, FONT_TITLE,
    FONT_MONO, FONT_MONO_SM, FONT_MONO_SM_BOLD,
    MinimalDropdown, make_entry, make_scrollbar, make_gradient_rule,
    make_button as _make_button, make_card as _make_card,
    configure_treeview_style, configure_combobox_style,
    configure_progressbar_style, configure_entry_style, set_ui_scale,
)

DIM = FG_DIM

_KNOWN_GOOD_STATUS_COLORS = {
    "Verified": GREEN,
    "Not Verified": RED,
    "Unknown": YELLOW,
}
_DPI_SCALE_PRESETS = (
    ("80%", 0.80),
    ("90%", 0.90),
    ("100%", 1.00),
    ("110%", 1.10),
    ("125%", 1.25),
    ("150%", 1.50),
    ("175%", 1.75),
    ("200%", 2.00),
)

def _format_short_date(value):
    if not value:
        return "--"
    return value.strftime("%Y-%m-%d")

def _count_offsets_in_games_root(path: str) -> int:
    if not path or not os.path.isdir(path):
        return 0
    count = 0
    try:
        entries = os.listdir(path)
    except OSError:
        return 0
    for name in entries:
        if os.path.isfile(os.path.join(path, name, "Offsets", "OffsetsInfo.json")):
            count += 1
    return count

def _resolve_games_root() -> str:
    candidates = []
    env_root = (os.environ.get("SDKKIT_GAMES_ROOT") or "").strip()
    if env_root:
        candidates.append(os.path.abspath(env_root))
    candidates.append(os.path.join(_ROOT, "games"))
    candidates.append(os.path.abspath(os.path.join(os.getcwd(), "games")))
    if getattr(sys, "frozen", False):
        candidates.append(os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "games"))

    local_data = os.environ.get("LOCALAPPDATA")
    if local_data:
        candidates.append(os.path.join(local_data, "GameSDKKit", "games"))

    deduped = []
    seen = set()
    for item in candidates:
        norm = os.path.normcase(os.path.normpath(item))
        if norm in seen:
            continue
        seen.add(norm)
        deduped.append(item)

    for candidate in deduped:
        if _count_offsets_in_games_root(candidate) > 0:
            return candidate
    for candidate in deduped:
        if os.path.isdir(candidate):
            return candidate
    return os.path.join(_ROOT, "games")

def _write_template(path: str, content: str):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)

_TPL_COMM_H = r"""/*
 * comm.h  -  Shared memory IPC protocol.
 *
 * This file is shared between the kernel driver and the user-mode client.
 * The driver creates a named section; both sides map it.  Communication
 * happens through a single 4096-byte shared page.
 *
 * Protocol:
 *   1. Client writes a COMMAND struct to the shared page.
 *   2. Client sets MagicCode last (the "go" signal).
 *   3. Kernel worker sees the magic, executes the command.
 *   4. Results written into the data area (offset +48).
 *   5. Kernel sets Status = STATUS_COMPLETE / STATUS_ERROR.
 *   6. Client polls Status until != STATUS_WAITING.
 */
#pragma once
#include <ntifs.h>

/* -- Command IDs ------------------------------------------------ */
#define COMMAND_MAGIC       0x4E564D52   /* trigger signal             */
#define COMMAND_READ        1            /* physical read              */
#define COMMAND_WRITE       2            /* physical write             */
#define COMMAND_GETBASE     3            /* PsGetProcessSectionBaseAddress */
#define COMMAND_FINDCR3     4            /* read DirectoryTableBase    */

/* -- Status ----------------------------------------------------- */
#define STATUS_WAITING      0
#define STATUS_COMPLETE     1
#define STATUS_ERROR        2

/* -- Shared page layout ----------------------------------------- */
/*  TODO: Change this GUID to your own unique value!               */
#define SECTION_NAME  L"\\BaseNamedObjects\\Global\\{CHANGE-ME-0000-0000-000000000000}"
#define PAGE_SIZE_    4096
#define HEADER_SIZE   48
#define DATA_MAX      (PAGE_SIZE_ - HEADER_SIZE)

/* -- Command struct (48 bytes) ---------------------------------- */
#pragma pack(push, 8)
typedef struct _COMMAND {
    ULONG       MagicCode;       /* 0x00 */
    ULONG       Instruction;     /* 0x04 */
    ULONG       ProcessId;       /* 0x08 */
    ULONG       _Pad0;           /* 0x0C */
    ULONGLONG   TargetAddress;   /* 0x10 */
    ULONGLONG   BufferAddress;   /* 0x18 */
    SIZE_T      Size;            /* 0x20 */
    ULONG       Status;          /* 0x28 */
    ULONG       _Pad1;           /* 0x2C */
} COMMAND, *PCOMMAND;
#pragma pack(pop)
C_ASSERT(sizeof(COMMAND) == HEADER_SIZE);
"""

_TPL_KERNEL_MAIN = r"""/*
 * main.c  -  Minimal kernel driver skeleton.
 *
 * This is a starting point for a KMDF driver that communicates with
 * user-mode through a shared memory section.  It demonstrates:
 *
 *   - Creating a named section for IPC
 *   - Physical memory reads via MmCopyMemory  (safe from AC hooks)
 *   - Worker thread with anti-detection basics
 *
 * BUILD:
 *   Requires Visual Studio + WDK.  Build as KMDF driver, Release|x64.
 *   Use /GS- in release to remove compiler cookie artifacts.
 *
 * LOAD:
 *   Use gsd_mapper or another manual mapper.
 *
 * IMPORTANT ANTI-DETECTION NOTES  (read docs/DETECTION_VECTORS.md):
 *   - Never call MmCopyVirtualMemory (hooked by all ACs)
 *   - Never call MmMapIoSpace for RAM reads (hooked by EAC)
 *   - Spoof ETHREAD->StartAddress after thread creation
 *   - Wipe PE header + module name after init
 *   - Use KeEnterCriticalRegion to block BattlEye APC stack walks
 *   - Choose a pool tag that mimics a legit driver (e.g. fltmgr)
 */
#include "../shared/comm.h"

#define POOL_TAG 'nfMF'   /* mimics fltmgr.sys */

/* Forward declarations */
static VOID   WorkerThread(PVOID ctx);
static VOID   HandleRead(PCOMMAND cmd, PVOID dataArea);
static VOID   HandleGetBase(PCOMMAND cmd, PVOID dataArea);

/* Globals */
static PVOID   g_SharedSection = NULL;
static PVOID   g_SharedPage    = NULL;
static HANDLE  g_ThreadHandle  = NULL;
static BOOLEAN g_Running       = TRUE;

/* ── Physical read via MmCopyMemory ─────────────────────────── */

static NTSTATUS ReadPhysical(ULONGLONG physAddr, PVOID buf, SIZE_T size)
{
    MM_COPY_ADDRESS src;
    src.PhysicalAddress.QuadPart = (LONGLONG)physAddr;
    SIZE_T bytesRead = 0;
    return MmCopyMemory(buf, src, size, MM_COPY_MEMORY_PHYSICAL, &bytesRead);
}

/* ── Worker thread ──────────────────────────────────────────── */

static VOID WorkerThread(PVOID ctx)
{
    UNREFERENCED_PARAMETER(ctx);
    LARGE_INTEGER delay;
    delay.QuadPart = -1000;  /* 100 us (relative, in 100ns units) */

    KeEnterCriticalRegion();  /* block BattlEye kernel APCs */

    while (g_Running) {
        PCOMMAND cmd = (PCOMMAND)g_SharedPage;
        PVOID dataArea = (PUCHAR)g_SharedPage + HEADER_SIZE;

        if (cmd->MagicCode == COMMAND_MAGIC) {
            cmd->MagicCode = 0;  /* consume */

            switch (cmd->Instruction) {
            case COMMAND_READ:
                HandleRead(cmd, dataArea);
                break;
            case COMMAND_GETBASE:
                HandleGetBase(cmd, dataArea);
                break;
            default:
                cmd->Status = STATUS_ERROR;
                break;
            }
        }

        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    KeLeaveCriticalRegion();
    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* ── Command handlers ───────────────────────────────────────── */

static VOID HandleRead(PCOMMAND cmd, PVOID dataArea)
{
    /*
     * TODO: Translate cmd->TargetAddress (virtual) to physical using
     * the target process's CR3 (DirectoryTableBase).  Then read via
     * ReadPhysical().  This is the core of the driver.
     *
     * Steps:
     *   1. Find EPROCESS for cmd->ProcessId via PsLookupProcessByProcessId
     *   2. Read DirectoryTableBase from EPROCESS (offset varies by OS)
     *   3. Walk the page tables:  PML4 -> PDPT -> PD -> PT -> phys
     *   4. Call ReadPhysical() to copy data into dataArea
     *   5. Set cmd->Status = STATUS_COMPLETE
     *
     */

    cmd->Status = STATUS_ERROR;  /* placeholder */
}

static VOID HandleGetBase(PCOMMAND cmd, PVOID dataArea)
{
    PEPROCESS proc = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)cmd->ProcessId, &proc);

    if (NT_SUCCESS(status)) {
        PVOID base = PsGetProcessSectionBaseAddress(proc);
        *(ULONGLONG*)dataArea = (ULONGLONG)base;
        cmd->Status = STATUS_COMPLETE;
        ObDereferenceObject(proc);
    } else {
        cmd->Status = STATUS_ERROR;
    }
}

/* ── Driver entry ───────────────────────────────────────────── */

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    /* 1. Create shared memory section */
    UNICODE_STRING sectionName;
    RtlInitUnicodeString(&sectionName, SECTION_NAME);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &sectionName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    LARGE_INTEGER maxSize;
    maxSize.QuadPart = PAGE_SIZE_;

    HANDLE sectionHandle = NULL;
    status = ZwCreateSection(&sectionHandle, SECTION_ALL_ACCESS, &oa,
        &maxSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(status))
        return status;

    /* 2. Map the section into system space */
    SIZE_T viewSize = PAGE_SIZE_;
    status = ZwMapViewOfSection(sectionHandle, NtCurrentProcess(),
        &g_SharedPage, 0, PAGE_SIZE_, NULL, &viewSize,
        ViewUnmap, 0, PAGE_READWRITE);
    ZwClose(sectionHandle);
    if (!NT_SUCCESS(status))
        return status;

    RtlZeroMemory(g_SharedPage, PAGE_SIZE_);

    /* 3. Create worker thread */
    status = PsCreateSystemThread(&g_ThreadHandle, THREAD_ALL_ACCESS,
        NULL, NULL, NULL, WorkerThread, NULL);
    if (!NT_SUCCESS(status))
        return status;

    /*
     * 4. Anti-detection (implement these yourself):
     *    - SpoofThreadStartAddress(g_ThreadHandle, WorkerThread)
     *    - HideDriverFromModuleList(DriverObject)
     *    - WipePEHeader(DriverObject)
     *
     *    See docs/DETECTION_VECTORS.md sections 3, 5, 6 for details.
     */

    return STATUS_SUCCESS;
}
"""

_TPL_USERMODE_MAIN = r"""/*
 * main.cpp  -  User-mode client skeleton.
 *
 * Opens the shared memory section created by the kernel driver and
 * demonstrates sending a GETBASE command.
 *
 * BUILD:  cl /EHsc /O2 main.cpp  (or Visual Studio, Release|x64)
 */
#include <windows.h>
#include <cstdio>
#include <cstdint>

/* Mirror the kernel-side protocol (keep in sync with shared/comm.h) */
#define COMMAND_MAGIC       0x4E564D52
#define COMMAND_READ        1
#define COMMAND_GETBASE     3
#define STATUS_WAITING      0
#define STATUS_COMPLETE     1
#define STATUS_ERROR        2
#define HEADER_SIZE         48

/* TODO: Change this to match your driver's section name! */
static const wchar_t* SECTION_NAME =
    L"Global\\{CHANGE-ME-0000-0000-000000000000}";

#pragma pack(push, 8)
struct Command {
    uint32_t MagicCode;
    uint32_t Instruction;
    uint32_t ProcessId;
    uint32_t _Pad0;
    uint64_t TargetAddress;
    uint64_t BufferAddress;
    uint64_t Size;
    uint32_t Status;
    uint32_t _Pad1;
};
#pragma pack(pop)

static uint8_t* g_View = nullptr;

bool InitDriver()
{
    HANDLE mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, SECTION_NAME);
    if (!mapping) {
        printf("[!] OpenFileMapping failed (%lu). Is the driver loaded?\n",
               GetLastError());
        return false;
    }

    g_View = (uint8_t*)MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, 4096);
    CloseHandle(mapping);  /* close handle immediately — view stays valid */

    if (!g_View) {
        printf("[!] MapViewOfFile failed (%lu)\n", GetLastError());
        return false;
    }

    printf("[+] Connected to driver.\n");
    return true;
}

bool SendCommand(uint32_t instruction, uint32_t pid,
                 uint64_t address, uint64_t size)
{
    auto* cmd = (Command*)g_View;
    cmd->Instruction   = instruction;
    cmd->ProcessId     = pid;
    cmd->TargetAddress = address;
    cmd->Size          = size;
    cmd->Status        = STATUS_WAITING;

    /* Set magic last — this is the "go" signal for the driver */
    cmd->MagicCode = COMMAND_MAGIC;

    /* Poll for completion */
    for (int i = 0; i < 1000; i++) {
        if (cmd->Status != STATUS_WAITING)
            return cmd->Status == STATUS_COMPLETE;
        Sleep(1);
    }

    printf("[!] Command timed out.\n");
    return false;
}

uint64_t GetProcessBase(uint32_t pid)
{
    if (!SendCommand(COMMAND_GETBASE, pid, 0, 0))
        return 0;
    return *(uint64_t*)(g_View + HEADER_SIZE);
}

int main()
{
    if (!InitDriver())
        return 1;

    /* Example: get base address of a process */
    uint32_t pid = 0;
    printf("Enter target PID: ");
    scanf_s("%u", &pid);

    uint64_t base = GetProcessBase(pid);
    if (base)
        printf("[+] Process base: 0x%llX\n", base);
    else
        printf("[!] Failed to get process base.\n");

    /*
     * Next steps:
     *   1. Implement COMMAND_READ in the driver (page table walk)
     *   2. Add a Read() function here that sends COMMAND_READ
     *   3. Use the dumped offsets to read game structs:
     *
     *      uint64_t gworld = Read<uint64_t>(base + OFFSET_GWORLD);
     *      uint64_t level  = Read<uint64_t>(gworld + 0x30);  // ULevel
     *      ...
     */

    UnmapViewOfFile(g_View);
    return 0;
}
"""

_TPL_README = """# Cheat Template  -  Kernel Driver Example

A starter project for building a kernel-mode game cheat using offsets
from the GameSDK-Kit.

## Structure

```
dumper_example/
  kernel/main.c        Kernel driver skeleton (KMDF, shared mem IPC)
  usermode/main.cpp    User-mode client (connects to driver, reads memory)
  shared/comm.h        Shared IPC protocol header
```

## Quick Start

1. **Dump offsets** (Full SDK Dump on your target game).
2. **Build the kernel driver** (`kernel/main.c`):
   - Open in Visual Studio with WDK installed.
   - Create a KMDF driver project, replace the source.
   - Build Release|x64 with `/GS-`.
3. **Load the driver** via gsd_mapper or your preferred mapper.
4. **Build the user-mode client** (`usermode/main.cpp`):
   - `cl /EHsc /O2 main.cpp` or add to a VS project.
5. **Use the dumped offsets** in your client to read game memory.

## Anti-Detection Checklist

- [ ] Change section GUID to a unique value
- [ ] Implement ETHREAD StartAddress spoofing
- [ ] Implement PE header wipe
- [ ] Implement module name wipe
- [ ] Build with `/GS-` (no security cookie artifacts)
- [ ] Use a pool tag that mimics a legit driver
- [ ] Never call MmCopyVirtualMemory or MmMapIoSpace
"""

class SDKKitApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self._gui_settings = load_gui_settings()
        self._system_tk_scaling = self._read_tk_scaling()
        self._active_dpi_scale = self._sanitize_dpi_scale(self._gui_settings.get("dpi_scale", 1.0))
        self._apply_dpi_scale(self._active_dpi_scale)
        self._use_custom_chrome = True
        self._custom_titlebar = None
        self.root.title("GameSDK-Kit")
        self.root.geometry("980x860")
        self.root.minsize(780, 700)
        self.root.configure(bg=BG)
        self.root.resizable(True, True)
        try:
            self.root.attributes("-alpha", 0.0)
        except Exception:
            pass

        self._taskbar_icons = []
        self._install_window_identity()
        self.root.protocol("WM_DELETE_WINDOW", self._close_window)

        self.handle = None
        self.pid = 0
        self.base = 0
        self.size = 0
        self.process_name = ""
        self.gnames = 0
        self.legacy_names = False
        self.gobjects = 0
        self.gworld = 0
        self.ue_version = ""
        self.detected_engine = "unknown"
        self.case_preserving = False
        self.item_size = 24
        self.scanning = False
        self._anim_step = 0
        self.games_root = _resolve_games_root()
        self._steam_audit_default_report_path = os.path.join(
            os.environ.get("LOCALAPPDATA") or _ROOT,
            "games",
            "_steam_audit",
            "steam_library_scan.json",
        )
        self._steam_audit_window = None
        self._steam_audit_state = None
        self._webhook_settings = load_webhook_settings()
        self._update_resolver = SteamUpdateResolver()
        self._known_good_records = []
        self._known_good_state = None
        self._known_good_busy = False
        self._active_scan_stage = ""
        self._scan_stage_started_at = 0.0
        self._scan_stage_durations = {}
        self._scan_started_at = 0.0
        self._last_scan_failure = None
        self._latest_trust_snapshot = {
            "status": "Unknown",
            "reason": "No verified dump yet",
            "source": "unknown",
        }
        self._gworld_timeout_seconds = 120.0
        try:
            _timeout_raw = os.environ.get("SDKKIT_GWORLD_TIMEOUT_SEC", "").strip()
            if _timeout_raw:
                self._gworld_timeout_seconds = max(15.0, min(600.0, float(_timeout_raw)))
        except Exception:
            pass
        self._workspace_views = {}
        self._workspace_nav_buttons = {}
        self._active_workspace = "main"
        self._closing = False
        self._drag_origin = None
        self._window_maximized = False
        self._window_minimized = False
        self._restore_geometry = None

        self.game_presets = {
            "Manor Lords": {
                "process": "ManorLords-Win64-Shipping.exe",
                "engine": "ue",
                "description": "Confirmed  |  UE 5.5  |  7,399 structs",
            },
            "Palworld": {
                "process": "Palworld-Win64-Shipping.exe",
                "engine": "ue",
                "description": "Confirmed  |  UE 5.1  |  full dump verified",
            },
            "Medieval Dynasty": {
                "process": "Medieval_Dynasty-Win64-Shipping.exe",
                "engine": "ue",
                "description": "Confirmed  |  UE 4.27  |  full dump verified",
            },
            "Half Sword": {
                "process": "HalfSword-Win64-Shipping.exe",
                "engine": "ue",
                "description": "Confirmed  |  UE 5  |  full dump verified",
            },
            "VRising": {
                "process": "VRising.exe",
                "engine": "il2cpp",
                "description": "Confirmed  |  Unity IL2CPP  |  full dump verified",
            },
            "Team Fortress 2": {
                "process": "tf_win64.exe",
                "engine": "source",
                "description": "Confirmed  |  Source Engine  |  netvar dump verified",
            },
            "Counter-Strike 2": {
                "process": "cs2.exe",
                "engine": "source2",
                "description": "Confirmed  |  Source 2 Engine  |  schema dump",
            },
            "Rogue Company": {
                "process": "RogueCompany-Win64-Shipping.exe",
                "engine": "ue",
                "description": "Confirmed  |  UE 4  |  full dump verified",
            },
        }

        self._build_ui()
        self._refresh_dump_buttons()
        self._update_scan_btn_visibility()
        self._refresh_current_trust_badge()
        self.root.after(10, self._init_combo_display)
        self.root.after(40, self._finalize_window_chrome)
        self.root.after(180, self._sync_custom_chrome)
        self.root.after(500, self._sync_custom_chrome)
        self.root.after(220, self._present_main_window)
        self.root.after(90, lambda: self._fade_in_window(self.root, duration_ms=170))

    def _sanitize_dpi_scale(self, value) -> float:
        try:
            scale = float(value)
        except (TypeError, ValueError):
            scale = 1.0
        return max(0.8, min(2.0, round(scale, 2)))

    def _read_tk_scaling(self) -> float:
        try:
            return float(self.root.tk.call("tk", "scaling"))
        except Exception:
            return 1.3333333333333333

    def _dpi_scale_label(self, value) -> str:
        return f"{int(round(self._sanitize_dpi_scale(value) * 100.0))}%"

    def _parse_dpi_scale_label(self, label: str) -> float:
        raw = str(label or "").strip().replace("%", "")
        try:
            return self._sanitize_dpi_scale(float(raw) / 100.0)
        except (TypeError, ValueError):
            return self._sanitize_dpi_scale(getattr(self, "_active_dpi_scale", 1.0))

    def _configure_styles(self):
        style = ttk.Style()
        configure_entry_style(style, scale=self._active_dpi_scale)
        configure_progressbar_style(style, scale=self._active_dpi_scale)
        configure_combobox_style(style, self.root, scale=self._active_dpi_scale)
        configure_treeview_style(style, scale=self._active_dpi_scale)

    def _ui_px(self, value, minimum=0) -> int:
        return max(minimum, int(round(float(value) * max(0.8, float(self._active_dpi_scale or 1.0)))))

    def _geometry_spec(self, width: int, height: int) -> str:
        return f"{self._ui_px(width, minimum=1)}x{self._ui_px(height, minimum=1)}"

    def _set_window_size(
        self,
        window: tk.Toplevel | tk.Tk,
        width: int,
        height: int,
        *,
        min_width: int | None = None,
        min_height: int | None = None,
    ) -> tuple[int, int]:
        scaled_width = int(width)
        scaled_height = int(height)
        window.geometry(f"{scaled_width}x{scaled_height}")
        if min_width is not None and min_height is not None:
            window.minsize(int(min_width), int(min_height))
        return scaled_width, scaled_height

    def _center_popup(self, popup: tk.Toplevel, width: int, height: int):
        scaled_width = int(width)
        scaled_height = int(height)
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (scaled_width // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (scaled_height // 2)
        popup.geometry(f"{scaled_width}x{scaled_height}+{x}+{y}")

    def _apply_dpi_scale(self, scale=None, *, persist: bool = False) -> float:
        factor = self._sanitize_dpi_scale(
            self._gui_settings.get("dpi_scale", 1.0) if scale is None else scale
        )
        set_ui_scale(factor)
        try:
            self.root.tk.call("tk", "scaling", self._system_tk_scaling * factor)
        except Exception:
            pass
        self._active_dpi_scale = factor
        if isinstance(getattr(self, "_gui_settings", None), dict):
            self._gui_settings["dpi_scale"] = factor
            if persist:
                self._persist_gui_settings()
        self._configure_styles()
        return factor

    def _build_ui(self):
        self._configure_styles()

        self.root.overrideredirect(True)
        self.root.bind("<Map>", self._restore_custom_chrome)

        titlebar = tk.Frame(self.root, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1)
        self._custom_titlebar = titlebar
        titlebar.pack(fill=tk.X)
        titlebar.bind("<ButtonPress-1>", self._start_window_drag)
        titlebar.bind("<B1-Motion>", self._drag_window)
        titlebar.bind("<Double-Button-1>", self._toggle_maximize)

        brand = tk.Frame(titlebar, bg=BG_CARD)
        brand.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, pady=6)
        brand.bind("<ButtonPress-1>", self._start_window_drag)
        brand.bind("<B1-Motion>", self._drag_window)
        for text, font, fg in (
            ("GameSDK-Kit", FONT_UI_BOLD, FG),
            ("Multi-engine SDK analyzer", FONT_UI_XS, FG_SUBTLE),
        ):
            lbl = tk.Label(brand, text=text, font=font, fg=fg, bg=BG_CARD)
            lbl.pack(anchor="w")
            lbl.bind("<ButtonPress-1>", self._start_window_drag)
            lbl.bind("<B1-Motion>", self._drag_window)

        window_controls = tk.Frame(titlebar, bg=BG_CARD)
        window_controls.pack(side=tk.RIGHT, padx=6, pady=6)
        for text, command in (
            ("−", self._minimize_window),
            ("□", self._toggle_maximize),
            ("✕", self._close_window),
        ):
            btn = tk.Label(
                window_controls, text=text, width=3, cursor="hand2",
                bg=BG_CARD, fg=FG_DIM, font=FONT_UI_SM, padx=4, pady=3,
            )
            btn.pack(side=tk.LEFT, padx=(0, 4))
            btn.bind("<Button-1>", lambda _e, cmd=command: cmd())
            btn.bind("<Enter>", lambda _e, w=btn: w.configure(bg=BG_HOVER, fg=FG))
            btn.bind("<Leave>", lambda _e, w=btn: w.configure(bg=BG_CARD, fg=FG_DIM))

        make_gradient_rule(self.root, ("#59462e", "#7a6850", "#496159"), height=2).pack(fill=tk.X)

        workspace_shell = tk.Frame(self.root, bg=BG, padx=20, pady=14)
        workspace_shell.pack(fill=tk.BOTH, expand=True)
        self._workspace_shell = workspace_shell

        workspace_nav = tk.Frame(workspace_shell, bg=BG)
        workspace_nav.pack(fill=tk.X, pady=(0, 14))
        self._workspace_nav = workspace_nav

        nav_label = tk.Label(
            workspace_nav,
            text="Workspace",
            font=FONT_UI_XS,
            fg=FG_SUBTLE,
            bg=BG,
        )
        nav_label.pack(side=tk.LEFT, padx=(0, 10))

        workspace_host = tk.Frame(workspace_shell, bg=BG)
        workspace_host.pack(fill=tk.BOTH, expand=True)
        self._workspace_host = workspace_host

        main = tk.Frame(workspace_host, bg=BG)
        self._workspace_views["main"] = main

        self._workspace_nav_buttons["main"] = _make_button(
            workspace_nav,
            "Main Toolkit",
            lambda: self._show_workspace("main"),
            style="secondary",
            font=FONT_UI_SM,
            padx=12,
            pady=4,
        )
        self._workspace_nav_buttons["main"].pack(side=tk.LEFT, padx=(0, 6))

        self._workspace_nav_buttons["steam_audit"] = _make_button(
            workspace_nav,
            "Steam Audit",
            self._open_steam_audit,
            style="ghost",
            font=FONT_UI_SM,
            padx=12,
            pady=4,
        )
        self._workspace_nav_buttons["steam_audit"].pack(side=tk.LEFT)

        header = tk.Frame(main, bg=BG)
        header.pack(fill=tk.X, pady=(0, 16))

        title_frame = tk.Frame(header, bg=BG)
        title_frame.pack(side=tk.LEFT)
        tk.Label(title_frame, text="GameSDK-Kit", font=FONT_TITLE,
                 fg=FG, bg=BG).pack(anchor="w")
        tk.Label(title_frame, text="Unreal Engine / Unity / Source",
                 font=FONT_UI_LG, fg=FG_DIM, bg=BG).pack(anchor="w", pady=(2, 0))

        ver_wrap = tk.Frame(header, bg=BG)
        ver_wrap.pack(side=tk.RIGHT, pady=(6, 0))
        ver_badge = tk.Frame(ver_wrap, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        ver_badge.pack()
        tk.Label(ver_badge, text="v7.0", font=FONT_MONO_SM,
                 fg=ACCENT, bg=SURFACE, padx=10, pady=5).pack()

        make_gradient_rule(main, ("#59462e", "#7a6850", "#496159"), height=2).pack(fill=tk.X, pady=(0, 14))

        setup_card = _make_card(main)
        setup_card.pack(fill=tk.X, pady=(0, 10))

        row1 = tk.Frame(setup_card, bg=BG_CARD)
        row1.pack(fill=tk.X, pady=(0, 8))
        tk.Label(row1, text="Preset", font=FONT_UI_SM,
                 fg=FG_DIM, bg=BG_CARD, width=10, anchor="w").pack(side=tk.LEFT)
        self.preset_var = tk.StringVar(value="Custom")
        self.preset_combo = MinimalDropdown(
            row1, self.preset_var,
            values=["Custom"] + list(self.game_presets.keys()),
            width=220, font=FONT_MONO_SM,
        )
        self.preset_combo.pack(side=tk.LEFT, padx=(4, 12))
        self.preset_combo.bind("<<ComboboxSelected>>", self._on_preset_selected)
        self.preset_desc = tk.Label(
            row1, text="", font=FONT_UI_SM, fg=FG_SUBTLE, bg=BG_CARD,
        )
        self.preset_desc.pack(side=tk.LEFT, fill=tk.X, expand=True)

        row2 = tk.Frame(setup_card, bg=BG_CARD)
        row2.pack(fill=tk.X, pady=(0, 8))
        tk.Label(row2, text="Process", font=FONT_UI_SM,
                 fg=FG_DIM, bg=BG_CARD, width=10, anchor="w").pack(side=tk.LEFT)
        self.process_var = tk.StringVar()
        self.process_entry = make_entry(
            row2,
            self.process_var,
            font=FONT_MONO,
        )
        self.process_entry.pack(side=tk.LEFT, padx=(4, 0), fill=tk.X, expand=True)
        self.process_var.set("")

        self.select_proc_btn = _make_button(
            row2, "Browse", self._open_process_picker, style="ghost",
            font=FONT_UI_SM, padx=10, pady=4,
        )
        self.select_proc_btn.pack(side=tk.LEFT, padx=(6, 16))

        tk.Label(row2, text="Engine", font=FONT_UI_SM,
                 fg=FG_DIM, bg=BG_CARD).pack(side=tk.LEFT, padx=(0, 6))
        self.engine_var = tk.StringVar(value="ue")
        self.engine_combo = MinimalDropdown(
            row2, self.engine_var,
            values=["ue", "il2cpp", "mono", "source", "source2"],
            width=86, font=FONT_MONO_SM,
        )
        self.engine_combo.pack(side=tk.LEFT, padx=(0, 8))
        self.engine_combo.bind("<<ComboboxSelected>>", lambda _e: self._update_scan_btn_visibility())

        self.kernel_var = tk.BooleanVar(value=False)
        self.kernel_check = tk.Checkbutton(
            row2, text="Kernel", variable=self.kernel_var,
            command=self._on_kernel_toggled,
            bg=BG_CARD, fg=FG_DIM, font=FONT_UI_SM, selectcolor=BG_INPUT,
            activebackground=BG_CARD, cursor="hand2", bd=0, highlightthickness=0,
        )
        self.kernel_check.pack(side=tk.LEFT, padx=(10, 0))

        actions_shell = tk.Frame(setup_card, bg=BG_CARD)
        actions_shell.pack(fill=tk.X, pady=(6, 0))

        primary_actions = tk.Frame(actions_shell, bg=BG_CARD)
        primary_actions.pack(fill=tk.X)

        self.detect_btn = _make_button(
            primary_actions, "Detect", self._detect_process, style="primary",
            font=FONT_UI_BOLD, padx=14, pady=6,
        )
        self.detect_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.scan_btn = _make_button(
            primary_actions, "Find Offsets", self._start_offset_scan, style="secondary",
            font=FONT_UI_BOLD, padx=14, pady=6,
        )
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.sdk_btn = _make_button(
            primary_actions, "Full SDK Dump", self._start_full_dump, style="accent",
            font=FONT_UI_BOLD, padx=18, pady=6,
        )
        self.sdk_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.open_folder_btn = _make_button(
            primary_actions, "Open Folder", self._open_output_folder, style="ghost",
            font=FONT_UI, padx=12, pady=6,
        )
        self.open_folder_btn.pack(side=tk.LEFT, padx=(0, 6))

        utility_row = tk.Frame(actions_shell, bg=BG_CARD)
        utility_row.pack(fill=tk.X, pady=(8, 0))
        utility_actions = tk.Frame(utility_row, bg=BG_CARD)
        utility_actions.pack(fill=tk.X, expand=True)

        self.template_btn = _make_button(
            utility_actions, "Template", self._drop_cheat_template, style="ghost",
            font=FONT_UI_SM, padx=10, pady=5,
        )
        self.template_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.verify_btn = _make_button(
            utility_actions, "Check Dump", self._verify_dump, style="ghost",
            font=FONT_UI_SM, padx=10, pady=5,
        )
        self.verify_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.viewer_btn = _make_button(
            utility_actions, "Live Viewer", self._open_live_viewer, style="ghost",
            font=FONT_UI_SM, padx=10, pady=5,
        )
        self.viewer_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.library_verify_btn = _make_button(
            utility_actions, "Verify Library", self._verify_library, style="ghost",
            font=FONT_UI_SM, padx=10, pady=5,
        )
        self.library_verify_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.webhook_settings_btn = _make_button(
            utility_actions, "Webhook Settings", self._open_webhook_settings, style="ghost",
            font=FONT_UI_SM, padx=10, pady=5,
        )
        self.webhook_settings_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.share_pack_btn = _make_button(
            utility_actions, "Share Pack", self._create_share_pack, style="ghost",
            font=FONT_UI_SM, padx=10, pady=5,
        )
        self.share_pack_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.partner_pack_btn = _make_button(
            utility_actions, "Partner Pack", self._create_partner_share_pack, style="ghost",
            font=FONT_UI_SM, padx=10, pady=5,
        )
        self.partner_pack_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.settings_btn = _make_button(
            utility_actions, "Settings", self._open_app_settings, style="ghost",
            font=FONT_UI_SM, padx=10, pady=5,
        )
        self.settings_btn.pack(side=tk.LEFT, padx=(0, 6))

        info_card = _make_card(main, pady=12)
        info_card.pack(fill=tk.X, pady=(0, 10))

        info_header = tk.Frame(info_card, bg=BG_CARD)
        info_header.pack(fill=tk.X, pady=(0, 8))
        tk.Label(info_header, text="Session Details", font=FONT_UI_BOLD,
                 fg=FG, bg=BG_CARD).pack(side=tk.LEFT)
        tk.Label(info_header, text="Live scan state and resolved offsets",
                 font=FONT_UI_XS, fg=FG_SUBTLE, bg=BG_CARD).pack(side=tk.RIGHT)

        self.info_labels = {}
        self.info_rows = {}
        self.info_value_labels = {}
        self.info_name_labels = {}
        info_grid = tk.Frame(info_card, bg=BG_CARD)
        info_grid.pack(fill=tk.X)

        info_grid.columnconfigure(1, weight=1)
        info_grid.columnconfigure(3, weight=1)

        self._copyable_keys = {"gnames", "gobjects", "gworld", "base"}

        fields = [
            ("Process",     "process",  0, 0),
            ("Engine",      "engine",   0, 2),
            ("PID",         "pid",      1, 0),
            ("Base",        "base",     1, 2),
            ("GNames",      "gnames",   2, 0),
            ("GObjects",    "gobjects", 2, 2),
            ("GWorld",      "gworld",   3, 0),
            ("Objects",     "objects",  3, 2),
        ]

        for label_text, key, row, col in fields:
            lbl = tk.Label(info_grid, text=label_text, font=FONT_UI_SM,
                     fg=FG_SUBTLE, bg=BG_CARD, anchor="e", width=10)
            lbl.grid(row=row, column=col, sticky="e", padx=(4, 2), pady=1)
            val = tk.Label(info_grid, text="--", font=FONT_MONO,
                           fg=FG_DIM, bg=BG_CARD, anchor="w")
            val.grid(row=row, column=col + 1, sticky="w", padx=(4, 12), pady=1)
            self.info_labels[key] = val
            self.info_name_labels[key] = lbl
            self.info_value_labels[key] = val
            self.info_rows[key] = row

            if key in self._copyable_keys:
                val.configure(cursor="hand2")
                val.bind("<Button-1>", lambda e, k=key: self._copy_offset(k))

        self.copy_hint_label = tk.Label(
            info_card, text="Click offsets to copy to clipboard",
            font=FONT_UI_XS, fg=FG_SUBTLE, bg=BG_CARD,
        )
        self.copy_hint_label.pack(anchor="w", pady=(6, 0))

        trust_row = tk.Frame(info_card, bg=BG_CARD)
        trust_row.pack(fill=tk.X, pady=(6, 0))
        tk.Label(
            trust_row, text="Known Good", font=FONT_UI_XS, fg=FG_SUBTLE, bg=BG_CARD,
        ).pack(side=tk.LEFT, padx=(0, 6))
        self.trust_badge_label = tk.Label(
            trust_row,
            text="Unknown",
            font=FONT_UI_SM,
            fg=YELLOW,
            bg=BG_CARD,
        )
        self.trust_badge_label.pack(side=tk.LEFT)
        self.trust_reason_label = tk.Label(
            trust_row,
            text="Run Check Dump to verify health.",
            font=FONT_UI_XS,
            fg=FG_SUBTLE,
            bg=BG_CARD,
            anchor="w",
            justify=tk.LEFT,
        )
        self.trust_reason_label.pack(side=tk.LEFT, padx=(8, 0), fill=tk.X, expand=True)

        prog_frame = tk.Frame(main, bg=BG)
        prog_frame.pack(fill=tk.X, pady=(0, 6))

        prog_inner = tk.Frame(
            prog_frame, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1,
            padx=12, pady=10,
        )
        prog_inner.pack(fill=tk.X)

        self.step_label = tk.Label(prog_inner, text="", font=FONT_UI_SM,
                                   fg=FG_DIM, bg=SURFACE, anchor="w")
        self.step_label.pack(side=tk.LEFT, padx=(0, 8))

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            prog_inner, variable=self.progress_var, maximum=100,
        )
        self.progress_bar.pack(fill=tk.X, side=tk.LEFT, expand=True, padx=(0, 8))

        self.status_label = tk.Label(prog_inner, text="Ready", font=FONT_UI_SM,
                                     fg=FG_DIM, bg=SURFACE, anchor="e")
        self.status_label.pack(side=tk.RIGHT)

        out_frame = tk.Frame(main, bg=BG)
        out_frame.pack(fill=tk.X, pady=(0, 6))
        tk.Label(out_frame, text="Output", font=FONT_UI_XS,
                 fg=FG_SUBTLE, bg=BG).pack(side=tk.LEFT)
        self.output_var = tk.StringVar(value="")
        self.output_label = tk.Label(out_frame, textvariable=self.output_var,
                                     font=FONT_MONO_SM, fg=FG_DIM, bg=BG, anchor="w")
        self.output_label.pack(side=tk.LEFT, padx=(8, 0), fill=tk.X, expand=True)

        log_card = tk.Frame(main, bg=BG_CARD, bd=0,
                           highlightbackground=BORDER, highlightthickness=1)
        log_card.pack(fill=tk.BOTH, expand=True, pady=(0, 8))
        log_card.configure(height=self._ui_px(220, minimum=170))
        log_card.pack_propagate(False)

        log_header = tk.Frame(log_card, bg=BG_CARD)
        log_header.pack(fill=tk.X, padx=12, pady=(8, 0))
        tk.Label(log_header, text="Log", font=FONT_UI_BOLD,
                 fg=FG_DIM, bg=BG_CARD).pack(side=tk.LEFT)

        self.save_log_btn = _make_button(
            log_header, "Copy", self._copy_log, style="ghost",
            font=FONT_UI_XS, padx=8, pady=2,
        )
        self.save_log_btn.pack(side=tk.RIGHT, padx=(4, 0))

        clear_btn = _make_button(
            log_header, "Clear", self._clear_log, style="ghost",
            font=FONT_UI_XS, padx=8, pady=2,
        )
        clear_btn.pack(side=tk.RIGHT)

        log_body = tk.Frame(log_card, bg="#0a0a14", highlightbackground=BORDER, highlightthickness=1)
        log_body.pack(fill=tk.BOTH, expand=True, padx=8, pady=(4, 8))
        self.log_text = tk.Text(
            log_body, wrap=tk.WORD, font=FONT_MONO_SM,
            bg="#0a0a14", fg="#9399b2", insertbackground=FG,
            relief=tk.FLAT, bd=0, padx=12, pady=8, height=16,
        )
        log_scroll = make_scrollbar(log_body, self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 2), pady=2)
        self.log_text.configure(state=tk.DISABLED)

        self.log_text.tag_configure("ok",   foreground=GREEN)
        self.log_text.tag_configure("err",  foreground=RED)
        self.log_text.tag_configure("warn", foreground=YELLOW)
        self.log_text.tag_configure("info", foreground=ACCENT)
        self.log_text.tag_configure("dim",  foreground=FG_SUBTLE)

        self._show_workspace("main")

    def _init_combo_display(self):
        try:
            self.preset_combo.set("Custom")
            self.engine_combo.set("ue")
        except Exception:
            pass

    def _on_kernel_toggled(self):
        from src.core.memory import set_driver_mode
        if self.kernel_var.get():
            from src.core.driver import (
                init_driver, check_system_prerequisites, check_driver_health,
            )

            self._log("[Kernel] Checking system prerequisites...", "info")
            prereqs = check_system_prerequisites()
            has_fail = False
            for status, msg in prereqs:
                if status == "ok":
                    self._log(f"  [OK] {msg}", "ok")
                elif status == "warn":
                    self._log(f"  [!!] {msg}", "warn")
                else:
                    self._log(f"  [XX] {msg}", "err")
                    has_fail = True

            if has_fail:
                self._log(
                    "[Kernel] System prerequisites not met — fix the issues above "
                    "before loading the driver.", "err"
                )
                self.kernel_var.set(False)
                return

            self._log("[Kernel] Connecting to kernel driver...", "info")
            ok = init_driver()
            if not ok:
                ok = self._auto_load_driver()
                if ok:
                    ok = init_driver()

            if ok:
                health = check_driver_health()
                if health["alive"]:
                    set_driver_mode(True)
                    self._log(
                        f"[Kernel] Driver v{health['version']} connected!", "ok"
                    )
                    caps = health["capabilities"]
                    if caps.get("physical_read"):
                        self._log("  Physical read (MmCopyMemory): ENABLED", "ok")
                    if caps.get("tolerant_bulk_read"):
                        self._log("  Tolerant bulk scan reads: ENABLED", "ok")
                    else:
                        self._log(
                            "  Tolerant bulk scan reads: UNAVAILABLE (driver older than v2.2; brute scans fall back to strict reads)",
                            "warn",
                        )
                    if caps.get("dtb_validated"):
                        self._log(
                            f"  DTB offset: 0x{health['dtb_offset']:X} (validated)", "ok"
                        )
                    else:
                        self._log(
                            f"  DTB offset: 0x{health['dtb_offset']:X} (not yet validated — "
                            "will validate on first process attach)", "warn"
                        )
                    try:
                        from src.core.debug import get_log_path
                        log_path = get_log_path()
                        if log_path:
                            self._log(f"  Debug log: {log_path}", "dim")
                    except Exception:
                        pass
                else:
                    set_driver_mode(False)
                    self.kernel_var.set(False)
                    self._log(
                        "[Kernel] Driver section found but health check failed. "
                        "The driver thread may have crashed or is an incompatible version. "
                        "Driver mode disabled.", "err"
                    )
            else:
                self.kernel_var.set(False)
                self._log(
                    "[Kernel] Failed to connect to the kernel driver after the mapper attempt. "
                    "This usually means:", "err"
                )
                self._log(
                    "  1. Driver crashed during initialization (check Event Viewer)", "err"
                )
                self._log(
                    "  2. Driver version mismatch between Python and kernel code", "err"
                )
                self._log(
                    "  3. Another instance is already using the driver", "err"
                )
                self._log(
                    "[Kernel] Falling back to user-mode Win32 ReadProcessMemory.", "warn"
                )
                self._log(
                    "[Kernel] To fix driver issues, rebuild wdfsvc64.sys with Visual Studio.", "warn"
                )
                try:
                    from src.core.debug import get_log_path
                    _log_path = get_log_path()
                    if _log_path:
                        self._log(
                            f"[Kernel] See sdkkit_debug.log for section-enumeration "
                            f"diagnostics: {_log_path}", "dim"
                        )
                except Exception:
                    pass
        else:
            set_driver_mode(False)
            self._log("[Kernel] Driver mode disabled — using standard Win32 ReadProcessMemory.", "info")

    def _auto_load_driver(self) -> bool:
        import os, subprocess, sys

        if getattr(sys, "frozen", False):
            base = os.path.dirname(sys.executable)
        else:
            base = os.path.dirname(os.path.abspath(__file__))
            base = os.path.join(base, "..", "..")

        bin_dir  = os.path.normpath(os.path.join(base, "bin"))
        driver   = os.path.normpath(os.path.join(bin_dir, "wdfsvc64.sys"))

        if not os.path.isfile(driver):
            self._log(f"[Kernel] Driver not found at: {driver}", "err")
            return False

        mapper_candidates = ["gsd_mapper.exe", "kdmapper.exe"]
        mapper = None
        for cand in mapper_candidates:
            p = os.path.normpath(os.path.join(bin_dir, cand))
            if os.path.isfile(p):
                mapper = p
                break
        if not mapper:
            try:
                for f in os.listdir(bin_dir):
                    if f.lower().endswith(".exe") and f.lower() not in ("wdfsvc64.exe", "steamloginhelper.exe"):
                        alt = os.path.join(bin_dir, f)
                        self._log(f"[Mapper] Found alternative mapper: {f}", "info")
                        mapper = alt
                        break
            except OSError:
                pass

        if not mapper:
            self._log("[Kernel] No driver mapper found in bin/", "err")
            self._log("  Place gsd_mapper.exe (or another driver mapper) in the bin/ folder.", "err")
            self._log("  The mapper loads a vulnerable signed driver to map wdfsvc64.sys into kernel.", "warn")
            return False

        mapper_name = os.path.basename(mapper)
        self._log(f"[Mapper] Loading driver via {mapper_name}...", "info")
        try:
            result = subprocess.run(
                [mapper, driver],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                combined_stdout = (result.stdout or "") + (result.stderr or "")
                import re as _re
                m = _re.search(r"DriverEntry returned(?:\s+NTSTATUS)?\s+0x([0-9a-fA-F]+)", combined_stdout)
                if m:
                    entry_status = int(m.group(1), 16) & 0xFFFFFFFF
                    if entry_status != 0:
                        self._log(
                            f"[Mapper] {mapper_name} mapped the driver, but DriverEntry "
                            f"returned NTSTATUS 0x{entry_status:08X} — driver did not "
                            f"initialize.", "err"
                        )
                        _hint = {
                            0xC0000034: "STATUS_OBJECT_PATH_NOT_FOUND — the shared "
                                        "section path failed to resolve from kernel mode.",
                            0xC0000035: "STATUS_OBJECT_NAME_COLLISION — another "
                                        "driver instance may already be loaded.",
                            0xC0000022: "STATUS_ACCESS_DENIED — an anti-cheat / AV "
                                        "is blocking kernel-mode object creation.",
                            0xC000009A: "STATUS_INSUFFICIENT_RESOURCES — pool "
                                        "allocation failed inside DriverEntry.",
                        }.get(entry_status)
                        if _hint:
                            self._log(f"  {_hint}", "warn")
                        for line in combined_stdout.strip().splitlines()[-6:]:
                            self._log(f"  {line}", "dim")
                        return False
                    else:
                        self._log(
                            f"[Mapper] {mapper_name} finished successfully "
                            f"(DriverEntry -> 0x00000000).", "ok"
                        )
                else:
                    self._log(
                        f"[Mapper] {mapper_name} finished but did not report a "
                        f"DriverEntry status — assuming success.", "warn"
                    )
                import time
                time.sleep(1)
                return True
            else:
                self._log(f"[Mapper] {mapper_name} failed (exit code {result.returncode})", "err")
                combined = (result.stdout or "") + (result.stderr or "")

                if "CERT_REVOKED" in combined or "cert" in combined.lower():
                    self._log(
                        "  The embedded helper driver (iqvw64e.sys) is blocklisted by "
                        "Microsoft Driver Blocklist is active.", "err"
                    )
                    self._log(
                        "  Fix: Disable the blocklist via registry, or use a mapper that "
                        "targets an unblocklisted driver (e.g. LnvMSRIO.sys, AsrDrv106.sys).", "warn"
                    )
                    self._log(
                        "  Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config "
                        "-> VulnerableDriverBlocklistEnable = 0 (reboot required)", "warn"
                    )

                elif "access denied" in combined.lower() or "0xc0000022" in combined.lower():
                    self._log(
                        "  Access Denied — an anti-cheat or antivirus is blocking the "
                        "helper driver from loading. Close the game and AV, then retry.", "err"
                    )

                if result.stdout.strip():
                    for line in result.stdout.strip().splitlines()[-3:]:
                        self._log(f"  {line}", "dim")
                if result.stderr.strip():
                    for line in result.stderr.strip().splitlines()[-3:]:
                        self._log(f"  {line}", "err")
                return False
        except subprocess.TimeoutExpired:
            self._log(f"[Mapper] {mapper_name} timed out after 30s", "err")
            return False
        except Exception as e:
            self._log(f"[Mapper] Failed to run {mapper_name}: {e}", "err")
            return False

    def _on_preset_selected(self, event=None):
        name = self.preset_var.get()
        if name == "Custom":
            self.preset_desc.configure(text="")
            return
        if name in self.game_presets:
            p = self.game_presets[name]
            self.process_var.set(p["process"])
            self.engine_var.set(p["engine"])
            self.engine_combo.set(p["engine"])
            self.preset_desc.configure(text=p["description"])
            self._update_scan_btn_visibility()

            self._clear_log()
            self._log(f"Preset: {name}  ({p['description']})", "ok")

            if "kernel" in p.get("description", "").lower() and not self.kernel_var.get():
                self._log(
                    "[!!] This game uses kernel-level anti-cheat. "
                    "Enable the 'Kernel' checkbox for best results.",
                    "warn",
                )

            game_dir = p["process"].replace(".exe", "")
            dump_dir = os.path.join(self.games_root, game_dir, "Offsets")
            self.output_var.set(dump_dir)
            self._refresh_dump_buttons()

            offsets_json = os.path.join(dump_dir, "OffsetsInfo.json")
            if os.path.isfile(offsets_json):
                self._load_existing_offsets(dump_dir, offsets_json)
            else:
                self._log("No existing dump found — run Full SDK Dump to generate one", "warn")

    def _load_existing_offsets(self, dump_dir: str, offsets_json: str):
        import json as _json
        try:
            with open(offsets_json, "r", encoding="utf-8") as f:
                data = _json.load(f)
        except Exception as e:
            self._log(f"Could not read existing offsets: {e}", "err")
            return

        def _get_rva(key_new, key_legacy):
            globals_block = data.get("globals", {})
            if key_new in globals_block:
                entry = globals_block[key_new]
                if isinstance(entry, dict):
                    return entry.get("rva_dec") or entry.get("rva_hex")
                return entry
            v = data.get(key_legacy)
            if v is not None:
                return v
            for row in data.get("data", []):
                if isinstance(row, (list, tuple)) and len(row) >= 2 and row[0] == key_new:
                    return row[1]
            return None

        base_rva   = _get_rva("OFFSET_GNAMES",   "GNames")
        gobj_rva   = _get_rva("OFFSET_GOBJECTS",  "GObjects")
        gworld_rva = _get_rva("OFFSET_GWORLD",    "GWorld")

        game_block = data.get("game", {})
        ue_ver  = game_block.get("ue_version", data.get("ue_version", ""))
        unity_ver = game_block.get("unity_version", data.get("unity_version", ""))
        metadata_ver = game_block.get("metadata_version", data.get("metadata_version", ""))
        pe_ts   = game_block.get("pe_timestamp_human", data.get("pe_timestamp", ""))
        stale   = game_block.get("stale_detection", {}).get("redump_recommended", False)

        if base_rva is not None:
            self._set_info("gnames",   f"0x{int(base_rva):X}",  ACCENT)
        if gobj_rva is not None:
            self._set_info("gobjects", f"0x{int(gobj_rva):X}",  ACCENT)
        if gworld_rva is not None:
            self._set_info("gworld",   f"0x{int(gworld_rva):X}", ACCENT)
        if ue_ver:
            self._set_info("engine", f"UE {ue_ver}", FG)
        elif unity_ver:
            engine_text = f"Unity {unity_ver}"
            if metadata_ver:
                engine_text += f"  md {metadata_ver}"
            self._set_info("engine", engine_text, FG)

        num_structs = 0
        num_enums   = 0
        classes_json = os.path.join(dump_dir, "ClassesInfo.json")
        enums_json   = os.path.join(dump_dir, "EnumsInfo.json")
        if os.path.isfile(classes_json):
            try:
                with open(classes_json, "r", encoding="utf-8") as f:
                    num_structs = len(_json.load(f).get("data", []))
            except Exception:
                pass
        if os.path.isfile(enums_json):
            try:
                with open(enums_json, "r", encoding="utf-8") as f:
                    num_enums = len(_json.load(f).get("data", []))
            except Exception:
                pass

        if num_structs:
            self._set_info("objects", f"{num_structs:,} structs", FG)

        lines = []
        if pe_ts:                 lines.append(f"  Dumped    {pe_ts}")
        if ue_ver:                lines.append(f"  Engine    UE {ue_ver}")
        elif unity_ver:           lines.append(f"  Engine    Unity {unity_ver}")
        if metadata_ver:          lines.append(f"  Metadata  {metadata_ver}")
        if base_rva is not None:  lines.append(f"  GNames    0x{int(base_rva):X}")
        if gobj_rva is not None:  lines.append(f"  GObjects  0x{int(gobj_rva):X}")
        if gworld_rva is not None:lines.append(f"  GWorld    0x{int(gworld_rva):X}")
        if num_structs:           lines.append(f"  Structs   {num_structs:,}")
        if num_enums:             lines.append(f"  Enums     {num_enums:,}")
        sdk_dir = os.path.join(os.path.dirname(dump_dir), "SDK")
        if os.path.isdir(sdk_dir):
            sdk_files = len([f for f in os.listdir(sdk_dir) if f.endswith(".hpp")])
            if sdk_files: lines.append(f"  SDK       {sdk_files} packages")
        for line in lines:
            self._log(line, "info")
        self._log("", "")

        if stale:
            self._log("This dump is marked stale — game likely updated. Redump recommended.", "err")
        else:
            self._log("Redump if the game updates", "warn")

    def _log(self, msg: str, tag: str = ""):
        import datetime
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state=tk.NORMAL)
        prefix = f"[{ts}] " if msg.strip() else ""
        full = prefix + msg + "\n"
        if tag:
            self.log_text.insert(tk.END, full, tag)
        else:
            self.log_text.insert(tk.END, full)
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _log_diagnostics(self, diag):
        if diag is None:
            return
        self._log("", "")
        for line in diag.format_report():
            tag = "err" if "[!!]" in line else "warn" if "[??]" in line else "dim"
            self._log(line, tag)
        self._log("", "")

    def _log_confidence(self, diag):
        if diag is None:
            return
        for target in ("Version", "GObjects", "GNames", "GWorld"):
            conf = diag.get_confidence(target)
            reason = diag.get_confidence_reason(target)
            if conf <= 0:
                continue
            label = "HIGH" if conf >= 0.8 else "MEDIUM" if conf >= 0.5 else "LOW"
            tag = "ok" if conf >= 0.8 else "warn" if conf >= 0.5 else "err"
            msg = f"  {target}: {label}"
            if reason:
                msg += f" — {reason}"
            self._log(msg, tag)

    def _set_status(self, text: str, color: str = FG_DIM):
        self.status_label.configure(text=text, fg=color)

    def _set_step(self, text: str):
        if text == "Done!":
            color = GREEN
            self.step_label.configure(text=text, fg=color)
            self.root.update_idletasks()
            self.root.after(5000, lambda: self.step_label.configure(text="", fg=FG_DIM))
        else:
            self.step_label.configure(text=text, fg=ACCENT)
            self.root.update_idletasks()

    def _set_info(self, key: str, value: str, color: str = FG):
        if key in self.info_labels:
            self.info_labels[key].configure(text=value, fg=color)

    def _show_info_key(self, key: str, visible: bool):
        name_lbl = self.info_name_labels.get(key)
        value_lbl = self.info_value_labels.get(key)
        if not name_lbl or not value_lbl:
            return
        if visible:
            name_lbl.grid()
            value_lbl.grid()
        else:
            name_lbl.grid_remove()
            value_lbl.grid_remove()

    def _update_info_layout(self):
        engine = self.engine_var.get()
        is_ue = engine == "ue"

        for key in ("gnames", "gobjects", "gworld"):
            self._show_info_key(key, is_ue)

        objects_label = self.info_name_labels.get("objects")
        if objects_label:
            if engine == "il2cpp":
                objects_label.configure(text="Classes")
            elif engine == "mono":
                objects_label.configure(text="Types")
            elif engine == "r6s":
                objects_label.configure(text="Hits")
            else:
                objects_label.configure(text="Objects")

        if hasattr(self, "copy_hint_label"):
            self.copy_hint_label.configure(
                text="Click offsets to copy to clipboard" if is_ue else "Session metadata from the latest scan"
            )

    def _set_progress(self, pct: float):
        self.progress_var.set(pct)
        self.root.update_idletasks()

    def _persist_gui_settings(self):
        try:
            self._gui_settings = save_gui_settings(dict(self._gui_settings or {}))
        except Exception as exc:
            self._log(f"Settings save warning: {exc}", "warn")

    def _scan_stage_begin(self, stage_key: str, title: str):
        self._active_scan_stage = stage_key
        self._scan_stage_started_at = time.monotonic()
        self._set_step(title)

    def _scan_stage_finish(self, stage_key: str):
        if self._active_scan_stage != stage_key:
            return
        elapsed = max(0.0, time.monotonic() - float(self._scan_stage_started_at or 0.0))
        self._scan_stage_durations[stage_key] = elapsed
        self._active_scan_stage = ""
        self._scan_stage_started_at = 0.0

    def _scan_stage_clear(self):
        self._active_scan_stage = ""
        self._scan_stage_started_at = 0.0

    def _set_trust_badge(self, status: str, reason: str, source: str = "unknown"):
        clean_status = status if status in _KNOWN_GOOD_STATUS_COLORS else "Unknown"
        color = _KNOWN_GOOD_STATUS_COLORS.get(clean_status, YELLOW)
        if getattr(self, "trust_badge_label", None):
            self.trust_badge_label.configure(text=clean_status, fg=color)
        if getattr(self, "trust_reason_label", None):
            source_text = source.replace("_", " ").strip()
            prefix = f"{reason}" if reason else "No trust details available."
            if source_text:
                prefix = f"{prefix} (source: {source_text})"
            self.trust_reason_label.configure(text=prefix)
        self._latest_trust_snapshot = {
            "status": clean_status,
            "reason": reason,
            "source": source,
        }

    def _current_game_key(self) -> str:
        process = (self.process_name or self.process_var.get().strip() or "").strip()
        if not process:
            dump_dir = self.output_var.get().strip()
            if dump_dir:
                process = os.path.basename(os.path.dirname(os.path.normpath(dump_dir)))
        return normalize_game_key(process)

    def _current_steam_appid(self):
        key = self._current_game_key()
        if not key:
            return None
        for record in getattr(self, "_known_good_records", []):
            if record.game_key == key and record.steam_appid:
                return record.steam_appid
        process = (self.process_name or self.process_var.get().strip() or "").strip()
        if process:
            return infer_steam_appid(process_name=process, game_name=process.replace(".exe", ""))
        return None

    def _collect_known_good_records(self, *, force_refresh: bool = False):
        overrides = {}
        if isinstance(self._gui_settings, dict):
            raw = self._gui_settings.get("latest_update_overrides", {})
            if isinstance(raw, dict):
                overrides = dict(raw)
        records = collect_known_good_records(
            self.games_root,
            resolver=self._update_resolver,
            latest_update_overrides=overrides,
            force_refresh=force_refresh,
        )
        self._known_good_records = records
        return records

    def _refresh_current_trust_badge(self):
        game_key = self._current_game_key()
        if not game_key:
            self._set_trust_badge("Unknown", "Select a game to evaluate trust status.", "unknown")
            return
        try:
            records = self._collect_known_good_records(force_refresh=False)
        except Exception:
            records = []
        selected = None
        for record in records:
            if record.game_key == game_key:
                selected = record
                break
        if selected is None:
            self._set_trust_badge("Unknown", "No OffsetsInfo/health data found for this game.", "unknown")
            return
        self._set_trust_badge(selected.final_status, selected.final_reason, selected.source)

    def _record_dump_history(
        self,
        *,
        run_type: str,
        success: bool,
        engine: str = "",
        detail: str = "",
        verification_status: str = "",
        stage_durations: dict = None,
    ):
        finished_at = datetime.now(timezone.utc)
        started_at = (
            datetime.fromtimestamp(self._scan_started_at, tz=timezone.utc)
            if self._scan_started_at
            else finished_at
        )
        elapsed = max(0.0, (finished_at - started_at).total_seconds())
        entry = {
            "run_type": run_type,
            "success": bool(success),
            "mode": "kernel" if bool(self.kernel_var.get()) else "usermode",
            "engine": engine or self.engine_var.get(),
            "process": self.process_name or self.process_var.get().strip(),
            "game_key": self._current_game_key(),
            "started_at": started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "finished_at": finished_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "duration_seconds": round(elapsed, 3),
            "stage_durations": dict(stage_durations or {}),
            "verification_status": verification_status,
            "detail": detail,
        }
        try:
            append_dump_history(entry, retention=200)
        except Exception as exc:
            self._log(f"History write warning: {exc}", "warn")

    def _show_scan_failure_card(self, cause: str, action: str, detail: str = ""):
        popup = tk.Toplevel(self.root)
        popup.title("Scan Recovery")
        popup.configure(bg=BG)
        self._set_window_size(popup, 560, 300, min_width=520, min_height=260)
        popup.resizable(True, True)

        shell = tk.Frame(popup, bg=BG, padx=16, pady=14)
        shell.pack(fill=tk.BOTH, expand=True)
        card = tk.Frame(shell, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill=tk.BOTH, expand=True)

        tk.Label(card, text="Scan failed", font=FONT_UI_BOLD, fg=RED, bg=BG_CARD).pack(anchor="w", padx=12, pady=(12, 6))
        tk.Label(card, text=f"Cause: {cause}", font=FONT_UI_SM, fg=FG, bg=BG_CARD, justify=tk.LEFT).pack(anchor="w", padx=12)
        tk.Label(card, text=f"Next action: {action}", font=FONT_UI_SM, fg=ACCENT, bg=BG_CARD, justify=tk.LEFT, wraplength=500).pack(anchor="w", padx=12, pady=(6, 0))

        detail_box = tk.Text(
            card,
            height=7,
            wrap=tk.WORD,
            font=FONT_MONO_SM,
            bg="#0d1118",
            fg="#b7c3d9",
            relief=tk.FLAT,
            padx=10,
            pady=8,
        )
        detail_box.pack(fill=tk.BOTH, expand=True, padx=12, pady=(10, 8))
        detail_box.insert(tk.END, detail or "No extra diagnostics were captured.")
        detail_box.configure(state=tk.DISABLED)

        footer = tk.Frame(shell, bg=BG)
        footer.pack(fill=tk.X, pady=(10, 0))
        retry_btn = _make_button(
            footer,
            "Retry now",
            lambda: (popup.destroy(), self._start_offset_scan()),
            style="secondary",
            font=FONT_UI_BOLD,
            padx=16,
            pady=5,
        )
        retry_btn.pack(side=tk.RIGHT)
        close_btn = _make_button(
            footer,
            "Close",
            popup.destroy,
            style="ghost",
            font=FONT_UI,
            padx=16,
            pady=5,
        )
        close_btn.pack(side=tk.RIGHT, padx=(0, 8))

        popup.transient(self.root)
        popup.grab_set()

    def _open_app_settings(self):
        popup = tk.Toplevel(self.root)
        popup.title("Settings")
        popup.configure(bg=BG)
        self._set_window_size(popup, 620, 400, min_width=560, min_height=340)

        shell = tk.Frame(popup, bg=BG, padx=16, pady=16)
        shell.pack(fill=tk.BOTH, expand=True)
        card = tk.Frame(shell, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill=tk.BOTH, expand=True)

        tk.Label(card, text="Config Settings", font=FONT_UI_BOLD, fg=FG, bg=BG_CARD).pack(anchor="w", padx=12, pady=(12, 4))
        first_run_done = bool(self._gui_settings.get("first_run_completed", False))
        tk.Label(
            card,
            text=f"First-run wizard completed: {'Yes' if first_run_done else 'No'}",
            font=FONT_UI_SM,
            fg=FG_SUBTLE,
            bg=BG_CARD,
        ).pack(anchor="w", padx=12, pady=(0, 2))
        tk.Label(
            card,
            text="Webhook status delivery runs automatically when a URL is configured.",
            font=FONT_UI_SM,
            fg=FG_SUBTLE,
            bg=BG_CARD,
        ).pack(anchor="w", padx=12, pady=(0, 10))

        current_dpi_label = self._dpi_scale_label(self._gui_settings.get("dpi_scale", self._active_dpi_scale))
        dpi_options = [label for label, _value in _DPI_SCALE_PRESETS]
        if current_dpi_label not in dpi_options:
            dpi_options.append(current_dpi_label)
            dpi_options.sort(key=self._parse_dpi_scale_label)
        dpi_var = tk.StringVar(value=current_dpi_label)

        dpi_row = tk.Frame(card, bg=BG_CARD)
        dpi_row.pack(fill=tk.X, padx=12, pady=(0, 8))
        tk.Label(
            dpi_row,
            text="DPI Scale",
            font=FONT_UI_SM,
            fg=FG_DIM,
            bg=BG_CARD,
            width=12,
            anchor="w",
        ).pack(side=tk.LEFT)
        MinimalDropdown(
            dpi_row,
            dpi_var,
            values=dpi_options,
            width=110,
            font=FONT_MONO_SM,
        ).pack(side=tk.LEFT, padx=(4, 10))
        _make_button(
            dpi_row,
            "Reset",
            lambda: dpi_var.set("100%"),
            style="ghost",
            font=FONT_UI_XS,
            padx=8,
            pady=3,
        ).pack(side=tk.LEFT, padx=(0, 10))
        tk.Label(
            dpi_row,
            text="Saved for the next launch so the whole menu layout resizes cleanly.",
            font=FONT_UI_XS,
            fg=FG_SUBTLE,
            bg=BG_CARD,
            wraplength=280,
            justify=tk.LEFT,
        ).pack(side=tk.LEFT, fill=tk.X, expand=True)

        actions = tk.Frame(card, bg=BG_CARD)
        actions.pack(fill=tk.X, padx=12, pady=(0, 10))
        _make_button(
            actions,
            "Reopen First-Run Wizard",
            lambda: (popup.destroy(), self._open_first_run_wizard(force=True)),
            style="ghost",
            font=FONT_UI_SM,
            padx=10,
            pady=4,
        ).pack(side=tk.LEFT, padx=(0, 8))
        _make_button(
            actions,
            "Open Data Folder",
            lambda: os.startfile(os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "GameSDKKit")), 
            style="ghost",
            font=FONT_UI_SM,
            padx=10,
            pady=4,
        ).pack(side=tk.LEFT)

        def _apply_settings():
            selected_scale = self._parse_dpi_scale_label(dpi_var.get())
            previous_scale = self._sanitize_dpi_scale(self._gui_settings.get("dpi_scale", 1.0))
            self._gui_settings["dpi_scale"] = selected_scale
            self._persist_gui_settings()
            if abs(selected_scale - previous_scale) > 0.001:
                self._log(
                    f"DPI scale saved at {self._dpi_scale_label(selected_scale)}. Reopen Toolkit to apply the full menu resize.",
                    "ok",
                )
                messagebox.showinfo(
                    "GameSDK-Kit",
                    "DPI scale saved.\n\nRestart or reopen the toolkit to resize the full menu cleanly.",
                )
            else:
                self._log(
                    f"DPI scale remains {self._dpi_scale_label(selected_scale)}.",
                    "dim",
                )
            popup.destroy()

        footer = tk.Frame(shell, bg=BG)
        footer.pack(fill=tk.X, pady=(10, 0))
        _make_button(
            footer,
            "Apply",
            _apply_settings,
            style="ghost",
            font=FONT_UI_BOLD,
            padx=18,
            pady=6,
        ).pack(side=tk.RIGHT, padx=(0, 8))
        _make_button(
            footer,
            "Close",
            popup.destroy,
            style="secondary",
            font=FONT_UI_BOLD,
            padx=18,
            pady=6,
        ).pack(side=tk.RIGHT)

        popup.transient(self.root)
        popup.grab_set()

    def _maybe_show_first_run_wizard(self):
        if not bool(self._gui_settings.get("first_run_completed", False)):
            self._open_first_run_wizard(force=False)

    def _open_first_run_wizard(self, *, force: bool = False):
        popup = tk.Toplevel(self.root)
        popup.title("Welcome to GameSDK-Kit")
        popup.configure(bg=BG)
        self._set_window_size(popup, 700, 420, min_width=640, min_height=380)
        popup.resizable(True, True)

        shell = tk.Frame(popup, bg=BG, padx=16, pady=16)
        shell.pack(fill=tk.BOTH, expand=True)
        card = tk.Frame(shell, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill=tk.BOTH, expand=True)

        tk.Label(card, text="First-Run Setup", font=FONT_UI_BOLD, fg=FG, bg=BG_CARD).pack(anchor="w", padx=12, pady=(12, 6))
        intro = (
            "Usermode is the default path and works without system-level changes.\n"
            "Kernel mode is optional and can help when reads are restricted, but it requires system prerequisites."
        )
        tk.Label(
            card,
            text=intro,
            font=FONT_UI_SM,
            fg=FG_SUBTLE,
            bg=BG_CARD,
            justify=tk.LEFT,
            wraplength=640,
        ).pack(anchor="w", padx=12, pady=(0, 8))

        output_default = os.path.join(self.games_root, "<GameName>", "Offsets")
        tk.Label(
            card,
            text=f"Default output: {output_default}",
            font=FONT_MONO_SM,
            fg=ACCENT,
            bg=BG_CARD,
            wraplength=640,
            justify=tk.LEFT,
        ).pack(anchor="w", padx=12, pady=(0, 8))

        open_webhook_var = tk.BooleanVar(value=False)
        webhook_chk = tk.Checkbutton(
            card,
            text="Open webhook quick setup after finishing",
            variable=open_webhook_var,
            bg=BG_CARD,
            fg=FG,
            font=FONT_UI_SM,
            selectcolor=BG_INPUT,
            activebackground=BG_CARD,
            cursor="hand2",
            bd=0,
            highlightthickness=0,
        )
        webhook_chk.pack(anchor="w", padx=12, pady=(0, 8))

        tips = (
            "Tip: run 'Check Dump' after each full dump so health.txt is generated.\n"
            "Webhook status boards use health.txt to mark whether a dump is verified."
        )
        tk.Label(
            card,
            text=tips,
            font=FONT_UI_XS,
            fg=FG_SUBTLE,
            bg=BG_CARD,
            justify=tk.LEFT,
            wraplength=640,
        ).pack(anchor="w", padx=12, pady=(0, 8))

        footer = tk.Frame(shell, bg=BG)
        footer.pack(fill=tk.X, pady=(10, 0))

        def _finish():
            self._gui_settings["first_run_completed"] = True
            self._persist_gui_settings()
            popup.destroy()
            if open_webhook_var.get():
                self._open_webhook_settings()

        def _dismiss():
            self._gui_settings["first_run_completed"] = True
            self._persist_gui_settings()
            popup.destroy()

        if not force:
            _make_button(
                footer,
                "Skip for now",
                _dismiss,
                style="ghost",
                font=FONT_UI,
                padx=14,
                pady=6,
            ).pack(side=tk.RIGHT, padx=(8, 0))

        _make_button(
            footer,
            "Finish",
            _finish,
            style="secondary",
            font=FONT_UI_BOLD,
            padx=18,
            pady=6,
        ).pack(side=tk.RIGHT)

        popup.transient(self.root)
        popup.grab_set()

    def _create_partner_share_pack(self):
        self._create_share_pack(export_profile="partner")

    def _create_share_pack(self, export_profile: str = "standard"):
        dump_dir = self.output_var.get().strip()
        if not dump_dir or not os.path.isfile(os.path.join(dump_dir, "OffsetsInfo.json")):
            messagebox.showwarning("GameSDK-Kit", "No dump found. Run Full SDK Dump first.")
            return

        game_name = self.process_name.replace(".exe", "").replace(".dll", "") if self.process_name else os.path.basename(os.path.dirname(os.path.normpath(dump_dir)))
        record = None
        try:
            for item in self._collect_known_good_records(force_refresh=False):
                if item.game_key == normalize_game_key(game_name):
                    record = item
                    break
        except Exception:
            record = None

        if record is None:
            status = self._latest_trust_snapshot.get("status", "Unknown")
            reason = self._latest_trust_snapshot.get("reason", "Trust status not resolved yet.")
            source = self._latest_trust_snapshot.get("source", "unknown")
            latest_update = ""
            health_state = ""
        else:
            status = record.final_status
            reason = record.final_reason
            source = record.source
            latest_update = record.latest_update_date.isoformat() if record.latest_update_date else ""
            health_state = record.health_state

        build_fingerprints = []
        if export_profile == "partner" and self.pid and self.process_name:
            try:
                from src.core.memory import attach, detach, get_module_info, get_pe_fingerprint

                fp_handle = attach(self.pid)
                if fp_handle:
                    try:
                        mod_base, mod_size = get_module_info(self.pid, self.process_name)
                        fingerprint = get_pe_fingerprint(fp_handle, mod_base) if mod_base else {}
                        if fingerprint:
                            fingerprint.update(
                                {
                                    "module": self.process_name,
                                    "base": mod_base,
                                    "size": mod_size,
                                }
                            )
                            build_fingerprints.append(fingerprint)
                    finally:
                        detach(fp_handle)
            except Exception:
                build_fingerprints = []

        try:
            pack_creator = create_partner_share_pack if export_profile == "partner" else create_share_pack
            zip_path, manifest = pack_creator(
                dump_dir,
                game_name=game_name or "dump",
                trust_status=status,
                trust_reason=reason,
                latest_update_date=latest_update,
                health_state=health_state,
                source=source,
                extra_metadata={
                    "engine": self.engine_var.get(),
                    "kernel_mode": bool(self.kernel_var.get()),
                    "output_dir": os.path.abspath(dump_dir),
                },
                build_fingerprints=build_fingerprints if export_profile == "partner" else None,
            )
            label = "Partner pack" if export_profile == "partner" else "Share pack"
            self._log(f"[OK] {label} created: {os.path.abspath(zip_path)}", "ok")
            self._log(f"  Trust: {manifest.get('trust', {}).get('status', 'Unknown')} - {manifest.get('trust', {}).get('reason', '')}", "dim")
            os.startfile(os.path.dirname(zip_path))
        except Exception as exc:
            self._log(f"Share pack failed: {exc}", "err")

    def _open_known_good_workspace(self):
        if "known_good" not in self._workspace_views:
            self._build_known_good_workspace()
        self._show_workspace("known_good")
        self._refresh_known_good_workspace(force_refresh=False)

    def _build_known_good_workspace(self):
        panel = tk.Frame(self._workspace_host, bg=BG)
        self._workspace_views["known_good"] = panel

        hero = _make_card(panel, pady=10)
        hero.pack(fill=tk.X, pady=(0, 8))
        top = tk.Frame(hero, bg=BG_CARD)
        top.pack(fill=tk.X)
        tk.Label(top, text="Known Good", font=FONT_UI_LG, fg=FG, bg=BG_CARD).pack(side=tk.LEFT)
        tk.Label(
            top,
            text="Strict trust matrix from health.txt + update recency",
            font=FONT_UI_XS,
            fg=FG_SUBTLE,
            bg=BG_CARD,
        ).pack(side=tk.LEFT, padx=(10, 0))
        _make_button(
            top,
            "Back to Toolkit",
            lambda: self._show_workspace("main"),
            style="ghost",
            font=FONT_UI_SM,
            padx=10,
            pady=4,
        ).pack(side=tk.RIGHT)

        controls = _make_card(panel, pady=10)
        controls.pack(fill=tk.X, pady=(0, 8))
        actions = tk.Frame(controls, bg=BG_CARD)
        actions.pack(fill=tk.X)

        state = {
            "rows_by_id": {},
            "tree": None,
            "detail_var": tk.StringVar(value="Select a game to view trust details."),
            "busy_var": tk.StringVar(value="Ready"),
        }
        self._known_good_state = state

        _make_button(
            actions,
            "Refresh Dates",
            lambda: self._refresh_known_good_workspace(force_refresh=True),
            style="secondary",
            font=FONT_UI_SM,
            padx=10,
            pady=4,
        ).pack(side=tk.LEFT, padx=(0, 6))
        _make_button(
            actions,
            "Edit Override",
            self._edit_known_good_override,
            style="ghost",
            font=FONT_UI_SM,
            padx=10,
            pady=4,
        ).pack(side=tk.LEFT, padx=(0, 6))
        _make_button(
            actions,
            "Clear Override",
            self._clear_known_good_override,
            style="ghost",
            font=FONT_UI_SM,
            padx=10,
            pady=4,
        ).pack(side=tk.LEFT, padx=(0, 6))
        _make_button(
            actions,
            "Use Selected Game",
            self._use_known_good_selection,
            style="ghost",
            font=FONT_UI_SM,
            padx=10,
            pady=4,
        ).pack(side=tk.LEFT)

        tk.Label(
            controls,
            textvariable=state["busy_var"],
            font=FONT_UI_XS,
            fg=FG_SUBTLE,
            bg=BG_CARD,
            anchor="w",
        ).pack(fill=tk.X, pady=(8, 0))

        table_card = _make_card(panel, pady=10)
        table_card.pack(fill=tk.BOTH, expand=True)

        columns = ("game", "dump_date", "latest_update", "health", "status", "source")
        shell = tk.Frame(table_card, bg=BG_INPUT, highlightbackground=BORDER, highlightthickness=1)
        shell.pack(fill=tk.BOTH, expand=True)
        tree = ttk.Treeview(shell, columns=columns, show="headings", selectmode="browse", height=14)
        tree.heading("game", text="Game")
        tree.heading("dump_date", text="Dump Date")
        tree.heading("latest_update", text="Latest Update")
        tree.heading("health", text="Health")
        tree.heading("status", text="Final Status")
        tree.heading("source", text="Source")
        tree.column("game", width=220, anchor="w")
        tree.column("dump_date", width=110, anchor="center")
        tree.column("latest_update", width=110, anchor="center")
        tree.column("health", width=120, anchor="center")
        tree.column("status", width=120, anchor="center")
        tree.column("source", width=120, anchor="center")
        tree.tag_configure("verified", foreground=GREEN)
        tree.tag_configure("not_verified", foreground=RED)
        tree.tag_configure("unknown", foreground=YELLOW)
        scroll = make_scrollbar(shell, tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 2), pady=2)
        state["tree"] = tree
        tree.bind("<<TreeviewSelect>>", lambda _event: self._update_known_good_details())

        detail = tk.Label(
            panel,
            textvariable=state["detail_var"],
            font=FONT_UI_XS,
            fg=FG_SUBTLE,
            bg=BG,
            justify=tk.LEFT,
            anchor="w",
            wraplength=920,
        )
        detail.pack(fill=tk.X, pady=(8, 0))

    def _known_good_selected_record(self):
        state = self._known_good_state or {}
        tree = state.get("tree")
        if not tree or not tree.winfo_exists():
            return None
        selected = tree.selection()
        if not selected:
            return None
        return state.get("rows_by_id", {}).get(selected[0])

    def _update_known_good_details(self):
        state = self._known_good_state or {}
        detail_var = state.get("detail_var")
        if not detail_var:
            return
        record = self._known_good_selected_record()
        if not record:
            detail_var.set("Select a game to view trust details.")
            return
        detail_var.set(
            f"{record.game}: {record.final_status}. "
            f"Health={record.health_state} ({record.health_reason}); "
            f"Dump={_format_short_date(record.dump_date)}; "
            f"Latest update={_format_short_date(record.latest_update_date)}; "
            f"Source={record.source}."
        )

    def _refresh_known_good_workspace(self, *, force_refresh: bool):
        if self._known_good_busy:
            return
        state = self._known_good_state or {}
        busy_var = state.get("busy_var")
        if busy_var:
            busy_var.set("Refreshing update dates..." if force_refresh else "Refreshing status table...")
        self._known_good_busy = True

        def _worker():
            error = ""
            records = []
            try:
                records = self._collect_known_good_records(force_refresh=force_refresh)
            except Exception as exc:
                error = str(exc)
            self.root.after(0, lambda: self._apply_known_good_rows(records, error=error))

        threading.Thread(target=_worker, daemon=True).start()

    def _apply_known_good_rows(self, records, *, error: str = ""):
        self._known_good_busy = False
        state = self._known_good_state or {}
        busy_var = state.get("busy_var")
        tree = state.get("tree")
        if busy_var:
            busy_var.set("Ready" if not error else f"Refresh failed: {error}")
        if not tree or not tree.winfo_exists():
            return
        for iid in tree.get_children():
            tree.delete(iid)
        rows_by_id = {}
        for index, record in enumerate(records):
            tag = "unknown"
            if record.final_status == "Verified":
                tag = "verified"
            elif record.final_status == "Not Verified":
                tag = "not_verified"
            iid = f"kg_{index}"
            tree.insert(
                "",
                tk.END,
                iid=iid,
                values=(
                    record.game,
                    _format_short_date(record.dump_date),
                    _format_short_date(record.latest_update_date),
                    record.health_state,
                    record.final_status,
                    record.source,
                ),
                tags=(tag,),
            )
            rows_by_id[iid] = record
        state["rows_by_id"] = rows_by_id
        self._update_known_good_details()
        self._refresh_current_trust_badge()

    def _edit_known_good_override(self):
        record = self._known_good_selected_record()
        if not record:
            messagebox.showinfo("GameSDK-Kit", "Select a game in Known Good first.")
            return

        popup = tk.Toplevel(self.root)
        popup.title("Latest Update Override")
        popup.configure(bg=BG)
        self._set_window_size(popup, 460, 220, min_width=420, min_height=200)

        shell = tk.Frame(popup, bg=BG, padx=14, pady=14)
        shell.pack(fill=tk.BOTH, expand=True)
        card = tk.Frame(shell, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill=tk.BOTH, expand=True)
        tk.Label(card, text=f"{record.game}", font=FONT_UI_BOLD, fg=FG, bg=BG_CARD).pack(anchor="w", padx=12, pady=(12, 6))
        tk.Label(
            card,
            text="Enter latest update date (YYYY-MM-DD or M/D/YY):",
            font=FONT_UI_SM,
            fg=FG_SUBTLE,
            bg=BG_CARD,
        ).pack(anchor="w", padx=12)

        current_overrides = self._gui_settings.get("latest_update_overrides", {})
        prefill = ""
        if isinstance(current_overrides, dict):
            prefill = str(current_overrides.get(record.game_key, "") or "")
        value_var = tk.StringVar(value=prefill)
        entry = make_entry(card, value_var, font=FONT_MONO_SM)
        entry.pack(fill=tk.X, padx=12, pady=(6, 10))

        def _save_override():
            parsed = parse_user_date(value_var.get().strip())
            if parsed is None:
                messagebox.showerror("GameSDK-Kit", "Invalid date. Use YYYY-MM-DD or M/D/YY.")
                return
            overrides = self._gui_settings.get("latest_update_overrides", {})
            if not isinstance(overrides, dict):
                overrides = {}
            overrides[record.game_key] = parsed.isoformat()
            self._gui_settings["latest_update_overrides"] = overrides
            self._persist_gui_settings()
            popup.destroy()
            self._refresh_known_good_workspace(force_refresh=False)

        footer = tk.Frame(shell, bg=BG)
        footer.pack(fill=tk.X, pady=(10, 0))
        _make_button(footer, "Cancel", popup.destroy, style="ghost", font=FONT_UI, padx=14, pady=5).pack(side=tk.RIGHT, padx=(8, 0))
        _make_button(footer, "Save", _save_override, style="secondary", font=FONT_UI_BOLD, padx=16, pady=5).pack(side=tk.RIGHT)
        popup.transient(self.root)
        popup.grab_set()
        entry.focus_set()

    def _clear_known_good_override(self):
        record = self._known_good_selected_record()
        if not record:
            messagebox.showinfo("GameSDK-Kit", "Select a game in Known Good first.")
            return
        overrides = self._gui_settings.get("latest_update_overrides", {})
        if not isinstance(overrides, dict):
            return
        changed = False
        if record.game_key in overrides:
            overrides.pop(record.game_key, None)
            changed = True
        if record.steam_appid is not None and str(record.steam_appid) in overrides:
            overrides.pop(str(record.steam_appid), None)
            changed = True
        if changed:
            self._gui_settings["latest_update_overrides"] = overrides
            self._persist_gui_settings()
            self._refresh_known_good_workspace(force_refresh=False)

    def _use_known_good_selection(self):
        record = self._known_good_selected_record()
        if not record:
            return
        if record.process:
            self.process_var.set(record.process)
        self._show_workspace("main")
        self._refresh_dump_buttons()
        self._update_scan_btn_visibility()

    def _open_output_folder(self):
        folder = self.output_var.get()
        if folder and os.path.isdir(folder):
            parent_folder = os.path.dirname(os.path.normpath(folder))
            if os.path.isdir(parent_folder):
                os.startfile(parent_folder)
            else:
                os.startfile(folder)

    def _install_window_identity(self):
        if os.name == "nt":
            try:
                import ctypes
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                    "UEUnitySDKKit"
                )
            except Exception:
                pass

        try:
            small = tk.PhotoImage(width=16, height=16)
            large = tk.PhotoImage(width=32, height=32)

            def _paint_icon(img, scale):
                img.put("#0f1420", to=(0, 0, 16 * scale, 16 * scale))
                img.put("#67a3ff", to=(2 * scale, 2 * scale, 6 * scale, 14 * scale))
                img.put("#8bc1ff", to=(10 * scale, 2 * scale, 14 * scale, 14 * scale))
                img.put("#8bc1ff", to=(6 * scale, 4 * scale, 10 * scale, 8 * scale))
                img.put("#8bc1ff", to=(6 * scale, 8 * scale, 10 * scale, 12 * scale))
                img.put("#1b2435", to=(3 * scale, 3 * scale, 5 * scale, 13 * scale))
                img.put("#1b2435", to=(11 * scale, 3 * scale, 13 * scale, 13 * scale))

            _paint_icon(small, 1)
            _paint_icon(large, 2)
            self._taskbar_icons = [small, large]
            self.root.iconphoto(True, *self._taskbar_icons)
        except Exception:
            self._taskbar_icons = []

    def _close_window(self):
        if self._closing:
            return
        self._closing = True
        steam_state = getattr(self, "_steam_audit_state", None)
        if isinstance(steam_state, dict):
            steam_state["busy"] = False
            steam_state["login_busy"] = False

        def _force_exit():
            time.sleep(0.8)
            os._exit(0)

        threading.Thread(target=_force_exit, daemon=True).start()
        try:
            for child in list(self.root.winfo_children()):
                if isinstance(child, tk.Toplevel):
                    child.destroy()
        except Exception:
            pass
        try:
            self.root.overrideredirect(False)
        except Exception:
            pass
        try:
            self.root.quit()
        except Exception:
            pass
        try:
            self.root.destroy()
        except Exception:
            pass

    def _start_window_drag(self, event):
        if self._window_maximized:
            return
        self._drag_origin = (event.x_root - self.root.winfo_x(), event.y_root - self.root.winfo_y())

    def _drag_window(self, event):
        if not self._drag_origin or self._window_maximized:
            return
        dx, dy = self._drag_origin
        self.root.geometry(f"+{event.x_root - dx}+{event.y_root - dy}")

    def _toggle_maximize(self, _event=None):
        if self._window_maximized:
            if self._restore_geometry:
                self.root.geometry(self._restore_geometry)
            self._window_maximized = False
            self.root.after(30, self._sync_custom_chrome)
            return

        self._restore_geometry = self.root.geometry()
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        self.root.geometry(f"{screen_w}x{screen_h}+0+0")
        self._window_maximized = True

    def _minimize_window(self):
        self._window_minimized = True
        if self._use_custom_chrome:
            self.root.overrideredirect(False)
        self.root.iconify()

    def _present_main_window(self):
        try:
            if not self.root.winfo_exists():
                return
            self.root.update_idletasks()
            self.root.deiconify()
            self.root.lift()
        except Exception:
            return

        if os.name == "nt":
            try:
                self.root.attributes("-topmost", True)
                self.root.after(
                    80,
                    lambda: self.root.winfo_exists() and self.root.attributes("-topmost", False),
                )
            except Exception:
                pass
        try:
            self.root.focus_force()
        except Exception:
            pass

    def _show_workspace(self, workspace: str):
        target = self._workspace_views.get(workspace)
        if not target:
            return
        for name, frame in self._workspace_views.items():
            if not frame.winfo_exists():
                continue
            if name == workspace:
                frame.pack(fill=tk.BOTH, expand=True)
            else:
                frame.pack_forget()
        self._active_workspace = workspace
        for name, button in self._workspace_nav_buttons.items():
            if not button:
                continue
            button.configure(style="secondary" if name == workspace else "ghost")

    def _finalize_window_chrome(self):
        try:
            self.root.update_idletasks()
            self.root.withdraw()
            self.root.overrideredirect(False)
            self.root.deiconify()
            self.root.update_idletasks()
            self._sync_custom_chrome()
            self.root.overrideredirect(True)
            self._present_main_window()
        except Exception:
            self._sync_custom_chrome()

    def _fade_in_window(self, window, duration_ms: int = 160, target_alpha: float = 1.0, steps: int = 8):
        try:
            if not window or not window.winfo_exists():
                return
            start_alpha = float(window.attributes("-alpha"))
        except Exception:
            try:
                window.attributes("-alpha", target_alpha)
            except Exception:
                pass
            return

        step_alpha = (target_alpha - start_alpha) / max(1, steps)
        delay = max(12, duration_ms // max(1, steps))

        def _tick(index=0):
            if not window.winfo_exists():
                return
            try:
                next_alpha = target_alpha if index >= steps else min(target_alpha, start_alpha + step_alpha * (index + 1))
                window.attributes("-alpha", next_alpha)
            except Exception:
                return
            if index < steps:
                window.after(delay, lambda: _tick(index + 1))

        _tick()

    def _restore_custom_chrome(self, _event=None):
        if not self._use_custom_chrome:
            return
        if self.root.state() != "normal":
            return

        def _restore():
            self.root.overrideredirect(True)
            self._window_minimized = False
            self._sync_custom_chrome()
            self._present_main_window()

        self.root.after(30, _restore)

    def _sync_custom_chrome(self):
        if not self._use_custom_chrome:
            return
        if os.name != "nt":
            return
        try:
            import ctypes

            GWL_EXSTYLE = -20
            WS_EX_APPWINDOW = 0x00040000
            WS_EX_TOOLWINDOW = 0x00000080
            GA_ROOT = 2
            SWP_NOMOVE = 0x0002
            SWP_NOSIZE = 0x0001
            SWP_NOZORDER = 0x0004
            SWP_FRAMECHANGED = 0x0020

            base_hwnd = self.root.winfo_id()
            handles = []
            for hwnd in (
                base_hwnd,
                ctypes.windll.user32.GetParent(base_hwnd),
                ctypes.windll.user32.GetAncestor(base_hwnd, GA_ROOT),
            ):
                if hwnd and hwnd not in handles:
                    handles.append(hwnd)

            for hwnd in handles:
                style = ctypes.windll.user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
                style = (style & ~WS_EX_TOOLWINDOW) | WS_EX_APPWINDOW
                ctypes.windll.user32.SetWindowLongW(hwnd, GWL_EXSTYLE, style)
                ctypes.windll.user32.SetWindowPos(
                    hwnd, 0, 0, 0, 0, 0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED,
                )
        except Exception:
            pass

    def _show_report_popup(self, title: str, report_text: str, size: str = "660x420"):
        popup = tk.Toplevel(self.root)
        popup.title(title)
        popup.configure(bg=BG)
        base_width, base_height = (int(part) for part in str(size).lower().split("x", 1))
        self._set_window_size(popup, base_width, base_height, min_width=520, min_height=320)
        popup.resizable(True, True)

        shell = tk.Frame(popup, bg=BG, padx=16, pady=16)
        shell.pack(fill=tk.BOTH, expand=True)

        card = tk.Frame(shell, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill=tk.BOTH, expand=True)

        header = tk.Frame(card, bg=BG_CARD)
        header.pack(fill=tk.X, padx=14, pady=(12, 4))
        tk.Label(header, text=title, font=FONT_UI_BOLD, fg=FG, bg=BG_CARD).pack(side=tk.LEFT)
        tk.Label(header, text="Offline validation report", font=FONT_UI_XS, fg=FG_SUBTLE, bg=BG_CARD).pack(side=tk.RIGHT)

        text_shell = tk.Frame(card, bg="#0d1118", highlightbackground=BORDER, highlightthickness=1)
        text_shell.pack(fill=tk.BOTH, expand=True, padx=10, pady=(4, 10))
        txt = tk.Text(
            text_shell, wrap=tk.WORD, font=FONT_MONO_SM,
            bg="#0d1118", fg="#b7c3d9", relief=tk.FLAT, padx=12, pady=10,
            insertbackground=FG,
        )
        txt_scroll = make_scrollbar(text_shell, txt.yview)
        txt.configure(yscrollcommand=txt_scroll.set)
        txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        txt_scroll.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 2), pady=2)
        txt.insert(tk.END, report_text)
        txt.configure(state=tk.DISABLED)

        footer = tk.Frame(shell, bg=BG)
        footer.pack(fill=tk.X, pady=(10, 0))
        close_btn = _make_button(
            footer, "Close", popup.destroy, style="secondary",
            font=FONT_UI, padx=20, pady=6,
        )
        close_btn.pack(side=tk.RIGHT)

    def _open_webhook_settings(self):
        current = dict(getattr(self, "_webhook_settings", {}) or {})

        popup = tk.Toplevel(self.root)
        popup.title("Webhook Settings")
        popup.configure(bg=BG)
        self._set_window_size(popup, 680, 360, min_width=560, min_height=320)
        popup.resizable(True, True)

        shell = tk.Frame(popup, bg=BG, padx=16, pady=16)
        shell.pack(fill=tk.BOTH, expand=True)

        card = tk.Frame(shell, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill=tk.BOTH, expand=True)

        header = tk.Frame(card, bg=BG_CARD)
        header.pack(fill=tk.X, padx=14, pady=(12, 8))
        tk.Label(header, text="Webhook Settings", font=FONT_UI_BOLD, fg=FG, bg=BG_CARD).pack(side=tk.LEFT)
        tk.Label(
            header,
            text="Deliver dump status boards to your server",
            font=FONT_UI_XS,
            fg=FG_SUBTLE,
            bg=BG_CARD,
        ).pack(side=tk.RIGHT)

        form = tk.Frame(card, bg=BG_CARD)
        form.pack(fill=tk.BOTH, expand=True, padx=12, pady=(2, 8))
        form.columnconfigure(1, weight=1)

        url_var = tk.StringVar(value=str(current.get("url", "") or ""))
        timeout_value = float(current.get("timeout", 6.0) or 6.0)
        message_state = {
            "id": str(current.get("discord_message_id", "") or "").strip(),
        }
        mode_value = str(current.get("mode", "simple") or "simple").strip().lower()
        if mode_value not in {"simple", "detailed"}:
            mode_value = "simple"
        mode_var = tk.StringVar(value="Simple" if mode_value == "simple" else "Detailed")

        tk.Label(form, text="Webhook URL", font=FONT_UI_SM, fg=FG_DIM, bg=BG_CARD).grid(
            row=0, column=0, sticky="w", padx=(0, 10), pady=(2, 8)
        )
        url_entry = make_entry(form, url_var, font=FONT_MONO_SM)
        url_entry.grid(row=0, column=1, sticky="ew", pady=(2, 8))

        tk.Label(form, text="Display Mode", font=FONT_UI_SM, fg=FG_DIM, bg=BG_CARD).grid(
            row=1, column=0, sticky="w", padx=(0, 10), pady=(2, 8)
        )
        mode_dropdown = MinimalDropdown(
            form,
            mode_var,
            values=["Simple", "Detailed"],
            width=180,
            font=FONT_UI_SM,
        )
        mode_dropdown.grid(row=1, column=1, sticky="w", pady=(2, 8))

        tk.Label(
            form,
            text="Simple keeps Discord readable with Verified / Not Verified sections. Detailed shows freshness groups and dump-age context.",
            font=FONT_UI_XS,
            fg=FG_SUBTLE,
            bg=BG_CARD,
            anchor="w",
            justify=tk.LEFT,
            wraplength=620,
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))

        tk.Label(
            form,
            text="Automatic mode stays the same: once URL is saved, the tool posts after each dump and edits the existing Discord status message instead of spamming new ones.",
            font=FONT_UI_XS,
            fg=FG_SUBTLE,
            bg=BG_CARD,
            anchor="w",
            justify=tk.LEFT,
            wraplength=620,
        ).grid(row=3, column=0, columnspan=2, sticky="w", pady=(6, 0))

        test_result_var = tk.StringVar(value="")
        test_result_label = tk.Label(
            form,
            textvariable=test_result_var,
            font=FONT_UI_XS,
            fg=FG_SUBTLE,
            bg=BG_CARD,
            anchor="w",
            justify=tk.LEFT,
            wraplength=620,
        )
        test_result_label.grid(row=4, column=0, columnspan=2, sticky="w", pady=(8, 0))

        footer = tk.Frame(shell, bg=BG)
        footer.pack(fill=tk.X, pady=(10, 0))

        def _save_settings():
            url = url_var.get().strip()
            mode = mode_var.get().strip().lower()

            try:
                save_webhook_settings(
                    url=url,
                    timeout=timeout_value,
                    discord_message_id=message_state["id"],
                    mode=mode,
                )
                self._webhook_settings = load_webhook_settings()
                if url:
                    self._log(f"Webhook URL saved ({mode.title()} mode, auto delivery enabled).", "ok")
                else:
                    self._log("Webhook URL cleared (auto delivery disabled).", "warn")
                popup.destroy()
            except Exception as exc:
                messagebox.showerror("GameSDK-Kit", f"Failed to save webhook settings: {exc}")

        def _test_delivery():
            url = url_var.get().strip()
            mode = mode_var.get().strip().lower()
            if not url:
                messagebox.showerror("GameSDK-Kit", "Webhook URL is required for test delivery.")
                url_entry.focus_set()
                return

            try:
                from src.output.webhook import (
                    collect_offset_statuses,
                    format_offset_status_board,
                    send_or_update_webhook_status,
                )

                overrides = {}
                raw_overrides = self._gui_settings.get("latest_update_overrides", {})
                if isinstance(raw_overrides, dict):
                    overrides.update(raw_overrides)

                statuses = collect_offset_statuses(
                    self.games_root,
                    latest_update_overrides=overrides,
                    resolver=self._update_resolver,
                    force_refresh=True,
                )
                board = format_offset_status_board(statuses)
                payload = {
                    "event": "webhook_test",
                    "tool": "GameSDK-Kit",
                    "source": "gui",
                    "sent_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "status_board": board,
                    "statuses": statuses,
                    "metadata": {
                        "process": self.process_name or self.process_var.get().strip(),
                        "engine": self.engine_var.get(),
                        "kernel_mode": bool(self.kernel_var.get()),
                        "output_dir": os.path.abspath(self.output_var.get()) if self.output_var.get() else "",
                        "webhook_mode": mode,
                    },
                }
                ok, detail, msg_id = send_or_update_webhook_status(
                    url,
                    payload,
                    status_board=board,
                    timeout=timeout_value,
                    previous_message_id=message_state["id"],
                    mode=mode,
                )
                if ok:
                    test_result_var.set(f"Test delivery: OK ({detail})")
                    test_result_label.configure(fg=GREEN)
                    if msg_id:
                        message_state["id"] = msg_id
                        save_webhook_settings(
                            url=url,
                            timeout=timeout_value,
                            discord_message_id=msg_id,
                            mode=mode,
                        )
                        self._webhook_settings = load_webhook_settings()
                    self._log(
                        f"  [OK] Webhook test delivered [{mode} msg:{msg_id or message_state['id'] or 'n/a'}] ({detail})",
                        "ok",
                    )
                else:
                    test_result_var.set(f"Test delivery failed: {detail}")
                    test_result_label.configure(fg=YELLOW)
                    self._log(f"  [--] Webhook test failed: {detail}", "warn")
            except Exception as exc:
                test_result_var.set(f"Test delivery error: {exc}")
                test_result_label.configure(fg=RED)
                self._log(f"  [--] Webhook test error: {exc}", "warn")

        test_btn = _make_button(
            footer, "Test Delivery", _test_delivery, style="ghost",
            font=FONT_UI_SM, padx=14, pady=6,
        )
        test_btn.pack(side=tk.LEFT)

        cancel_btn = _make_button(
            footer, "Cancel", popup.destroy, style="ghost",
            font=FONT_UI, padx=18, pady=6,
        )
        cancel_btn.pack(side=tk.RIGHT, padx=(8, 0))

        save_btn = _make_button(
            footer, "Save", _save_settings, style="secondary",
            font=FONT_UI_BOLD, padx=20, pady=6,
        )
        save_btn.pack(side=tk.RIGHT)

        popup.transient(self.root)
        popup.grab_set()
        url_entry.focus_set()

    def _maybe_send_webhook_gui(
        self,
        *,
        process_name: str,
        engine: str,
        output_dir: str,
        structs_count: int = 0,
        enums_count: int = 0,
        pe_timestamp: int = 0,
    ) -> None:
        settings = dict(getattr(self, "_webhook_settings", {}) or {})

        webhook_url = str(settings.get("url", "") or "").strip()
        if not webhook_url:
            return

        try:
            timeout_value = float(settings.get("timeout", 6.0))
        except (TypeError, ValueError):
            timeout_value = 6.0
        timeout_value = max(1.0, min(60.0, timeout_value))
        webhook_mode = str(settings.get("mode", "simple") or "simple").strip().lower()
        if webhook_mode not in {"simple", "detailed"}:
            webhook_mode = "simple"

        previous_message_id = str(settings.get("discord_message_id", "") or "").strip()

        try:
            from datetime import datetime, timezone
            from src.output.webhook import (
                collect_offset_statuses,
                format_offset_status_board,
                send_or_update_webhook_status,
            )

            overrides = {}
            raw_overrides = self._gui_settings.get("latest_update_overrides", {})
            if isinstance(raw_overrides, dict):
                overrides.update(raw_overrides)

            statuses = collect_offset_statuses(
                self.games_root,
                latest_update_overrides=overrides,
                resolver=self._update_resolver,
                force_refresh=False,
            )
            status_board = format_offset_status_board(statuses)

            payload = {
                "event": "dump_complete",
                "tool": "GameSDK-Kit",
                "source": "gui",
                "engine": engine,
                "process": process_name,
                "output_dir": os.path.abspath(output_dir) if output_dir else "",
                "structs_count": int(structs_count),
                "enums_count": int(enums_count),
                "pe_timestamp": int(pe_timestamp or 0),
                "sent_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "status_board": status_board,
                "statuses": statuses,
                "metadata": {
                    "webhook_mode": webhook_mode,
                },
            }

            ok, detail, msg_id = send_or_update_webhook_status(
                webhook_url,
                payload,
                status_board=status_board,
                timeout=timeout_value,
                previous_message_id=previous_message_id,
                mode=webhook_mode,
            )
            if ok:
                if msg_id and msg_id != previous_message_id:
                    save_webhook_settings(
                        url=webhook_url,
                        timeout=timeout_value,
                        discord_message_id=msg_id,
                        mode=webhook_mode,
                    )
                    self._webhook_settings = load_webhook_settings()
                active_message_id = msg_id or previous_message_id
                if previous_message_id:
                    self._log(
                        f"  [OK] Webhook status updated [{webhook_mode} msg:{active_message_id or 'n/a'}] ({detail})",
                        "ok",
                    )
                else:
                    self._log(
                        f"  [OK] Webhook status posted [{webhook_mode} msg:{active_message_id or 'n/a'}] ({detail})",
                        "ok",
                    )
            else:
                self._log(f"  [--] Webhook failed: {detail}", "warn")
        except Exception as exc:
            self._log(f"  [--] Webhook error: {exc}", "warn")

    def _format_steam_engine_label(self, engine: str, version: str = "") -> str:
        labels = {
            "ue3": "UE3",
            "ue4": "UE4",
            "ue5": "UE5",
            "ue_unknown": "Unreal",
            "il2cpp": "Unity IL2CPP",
            "mono": "Unity Mono",
            "unity_unknown": "Unity",
            "avm2": "AVM2 / Adobe AIR",
            "anvil": "Anvil",
            "source_2": "Source 2",
            "forzatech": "ForzaTech",
            "iw_engine": "IW engine",
            "re_engine": "RE Engine",
            "redengine": "REDengine",
            "fox_engine": "FOX Engine",
            "fromsoftware_engine": "FromSoftware proprietary engine",
            "proprietary_engine": "Proprietary engine",
            "rpg_maker": "RPG Maker",
            "mt_framework": "MT Framework",
            "unknown": "Unknown",
        }
        base = labels.get(engine, engine.replace("_", " ").title())
        return f"{base} {version}".strip() if version else base

    def _format_steam_support_label(self, game) -> str:
        labels = {
            "usermode_ready": "User mode ready",
            "kernel_recommended": "Kernel required",
            "install_then_scan": "Install to verify",
            "install_then_kernel": "Kernel likely",
            "engine_identified": "Engine identified",
            "install_engine_identified": "Owned only, engine identified",
            "manual_review": "Manual review",
        }
        return labels.get(game.support_tier, "Manual review")

    def _format_steam_scope_label(self, game) -> str:
        return "Installed" if game.installed else "Owned only"

    def _format_steam_source_label(self, game) -> str:
        if game.scan_source == "steam_desktop+installed_disk":
            return "Disk + desktop"
        if game.scan_source in {"installed_disk", "installed_disk_only"}:
            return "Installed disk"
        if game.scan_source == "steam_desktop_metadata":
            return "Desktop metadata"
        if game.scan_source == "steam_desktop_metadata+pcgw":
            return "Desktop + PCGW"
        if game.scan_source == "steam_desktop_metadata+awacy":
            return "Desktop + AWACY"
        if game.scan_source == "steam_desktop_metadata+local":
            return "Desktop + manifest"
        if game.scan_source == "steam_desktop_metadata+local+pcgw":
            return "Manifest + PCGW"
        if game.scan_source == "steam_desktop_metadata+pcgw+awacy":
            return "PCGW + AWACY"
        if game.scan_source == "steam_desktop_metadata+local+pcgw+awacy":
            return "Manifest + PCGW + AWACY"
        if game.scan_source == "steam_desktop_metadata+override+awacy":
            return "Override + AWACY"
        if game.scan_source == "steam_desktop_metadata+pcgw+override+awacy":
            return "PCGW + override + AWACY"
        if game.scan_source == "steam_desktop_metadata+override":
            return "Curated override"
        if game.scan_source == "steam_desktop_ownership":
            return "Desktop metadata"
        return game.scan_source.replace("_", " ").title()

    def _steam_row_tag(self, game) -> str:
        if game.support_tier == "usermode_ready":
            return "ready"
        if game.support_tier in {"kernel_recommended", "install_then_kernel"}:
            return "kernel"
        if game.support_tier in {"install_then_scan", "engine_identified", "install_engine_identified"}:
            return "likely"
        return "unknown"

    def _steam_audit_heading_text(self, state: dict, column: str, label: str) -> str:
        active_column = state.get("sort_column")
        if active_column != column:
            return label
        return f"{label} {'v' if state.get('sort_desc') else '^'}"

    def _steam_audit_sort_key(self, game, column: str):
        anti_cheat_text = ", ".join(game.anti_cheats).lower()
        engine_label = self._format_steam_engine_label(game.engine, game.version).lower()
        support_priority = {
            "usermode_ready": 0,
            "kernel_recommended": 1,
            "install_then_scan": 2,
            "install_then_kernel": 3,
            "engine_identified": 4,
            "install_engine_identified": 5,
            "manual_review": 6,
        }
        if column == "name":
            return (game.name or "").lower()
        if column == "scope":
            return (0 if game.installed else 1, (game.name or "").lower())
        if column == "source":
            return (self._format_steam_source_label(game).lower(), (game.name or "").lower())
        if column == "engine":
            return (0 if game.engine != "unknown" else 1, engine_label, (game.name or "").lower())
        if column == "anti_cheat":
            return (0 if game.anti_cheats else 1, anti_cheat_text or "~", (game.name or "").lower())
        return (
            support_priority.get(game.support_tier, 99),
            not game.installed,
            bool(game.kernel_recommended),
            (game.name or "").lower(),
        )

    def _update_steam_audit_headings(self, state: dict):
        tree = state.get("tree")
        if not tree or not tree.winfo_exists():
            return
        heading_labels = {
            "name": "Game",
            "scope": "Scope",
            "source": "Source",
            "engine": "Engine",
            "support": "Support",
            "anti_cheat": "Anti-cheat",
        }
        for column, label in heading_labels.items():
            tree.heading(
                column,
                text=self._steam_audit_heading_text(state, column, label),
                command=lambda c=column: self._sort_steam_audit_results(state, c),
            )

    def _sort_steam_audit_results(self, state: dict, column: str):
        current = state.get("sort_column")
        if current == column:
            state["sort_desc"] = not state.get("sort_desc", False)
        else:
            state["sort_column"] = column
            state["sort_desc"] = False
        self._update_steam_audit_headings(state)
        self._refresh_steam_audit_tree(state)

    def _refresh_steam_audit_tree(self, state: dict):
        tree = state.get("tree")
        report = state.get("report")
        if not tree or not tree.winfo_exists():
            return
        tree.delete(*tree.get_children())

        if not report:
            state["row_lookup"] = {}
            state["section_lookup"] = {}
            return

        column = state.get("sort_column") or "support"
        reverse = bool(state.get("sort_desc"))
        games = sorted(
            list(report.games),
            key=lambda game: self._steam_audit_sort_key(game, column),
            reverse=reverse,
        )

        row_lookup = {}
        section_lookup = {}
        group_by_support = column == "support"
        section_index = 0
        game_index = 0

        if group_by_support:
            grouped_games = {}
            for game in games:
                label = self._format_steam_support_label(game)
                grouped_games.setdefault(label, []).append(game)

            for section_title, games_in_section in grouped_games.items():
                section_iid = f"steam_section_{section_index}"
                tree.insert(
                    "",
                    tk.END,
                    iid=section_iid,
                    values=(f"{section_title} ({len(games_in_section):,})", "", "", "", "", ""),
                    tags=("group",),
                )
                section_lookup[section_iid] = section_title
                section_index += 1

                for game in games_in_section:
                    iid = f"steam_game_{game_index}"
                    anti_cheat_text = ", ".join(game.anti_cheats[:2])
                    if len(game.anti_cheats) > 2:
                        anti_cheat_text += ", +"
                    tree.insert(
                        "",
                        tk.END,
                        iid=iid,
                        values=(
                            "  " + game.name,
                            self._format_steam_scope_label(game),
                            self._format_steam_source_label(game),
                            self._format_steam_engine_label(game.engine, game.version),
                            self._format_steam_support_label(game),
                            anti_cheat_text or "-",
                        ),
                        tags=(self._steam_row_tag(game),),
                    )
                    row_lookup[iid] = game
                    game_index += 1
        else:
            for game in games:
                iid = f"steam_game_{game_index}"
                anti_cheat_text = ", ".join(game.anti_cheats[:2])
                if len(game.anti_cheats) > 2:
                    anti_cheat_text += ", +"
                tree.insert(
                    "",
                    tk.END,
                    iid=iid,
                    values=(
                        game.name,
                        self._format_steam_scope_label(game),
                        self._format_steam_source_label(game),
                        self._format_steam_engine_label(game.engine, game.version),
                        self._format_steam_support_label(game),
                        anti_cheat_text or "-",
                    ),
                    tags=(self._steam_row_tag(game),),
                )
                row_lookup[iid] = game
                game_index += 1

        state["row_lookup"] = row_lookup
        state["section_lookup"] = section_lookup
        if row_lookup:
            first = next(iter(row_lookup))
            tree.selection_set(first)
            tree.focus(first)

    def _render_steam_game_details(self, game) -> str:
        w = 18
        sep = "\u2500" * 44
        ac_text = ", ".join(game.anti_cheats) if game.anti_cheats else "None found"
        lines = [
            f"  {game.name}",
            f"  {sep}",
            f"  {'Engine':<{w}} {self._format_steam_engine_label(game.engine, game.version)}",
            f"  {'Support':<{w}} {self._format_steam_support_label(game)}",
            f"  {'Anti-cheat':<{w}} {ac_text}",
            f"  {'Confidence':<{w}} {game.confidence.upper()}  ({game.support_score}/100)",
            f"  {'Kernel':<{w}} {'Yes' if game.kernel_recommended else 'No'}",
            f"  {'Scope':<{w}} {self._format_steam_scope_label(game)}",
            f"  {'Source':<{w}} {self._format_steam_source_label(game)}",
            f"  {'Detection':<{w}} {game.detection_method}",
            f"  {sep}",
            f"  {game.diagnostic_summary or 'No summary available'}",
            f"  {game.next_step or ''}",
            f"  {sep}",
            f"  {'Executable':<{w}} {game.executable_path or 'N/A'}",
            f"  {'Install dir':<{w}} {game.install_dir}",
            f"  {'Store':<{w}} {game.store_url or 'N/A'}",
        ]
        if game.evidence:
            lines.append(f"  {sep}")
            lines.append("  Evidence:")
            lines.extend(f"    \u00b7 {item}" for item in game.evidence)
        return "\n".join(lines)

    def _set_steam_audit_status(self, state: dict, text: str, color: str = FG_DIM):
        label = state.get("status_label")
        if label and label.winfo_exists():
            label.configure(text=text, fg=color)

    def _set_steam_audit_detail_text(self, state: dict, text: str):
        detail_text = state.get("detail_text")
        if not detail_text or not detail_text.winfo_exists():
            return
        detail_text.configure(state=tk.NORMAL)
        detail_text.delete("1.0", tk.END)
        detail_text.insert(tk.END, text)
        detail_text.configure(state=tk.DISABLED)

    def _update_steam_audit_details(self, state: dict):
        tree = state.get("tree")
        if not tree or not tree.winfo_exists():
            return
        selection = tree.selection()
        row_lookup = state.get("row_lookup", {})
        section_lookup = state.get("section_lookup", {})
        game = row_lookup.get(selection[0]) if selection else None
        state["selected_game"] = game

        open_game_btn = state.get("open_game_btn")
        use_game_btn = state.get("use_game_btn")
        if open_game_btn:
            open_game_btn.configure(
                state=tk.NORMAL if game and game.installed and game.install_dir else tk.DISABLED
            )
        if use_game_btn:
            use_game_btn.configure(
                state=tk.NORMAL if game and game.installed and game.executable_path else tk.DISABLED
            )

        if game:
            self._set_steam_audit_detail_text(state, self._render_steam_game_details(game))
        else:
            section_title = section_lookup.get(selection[0]) if selection else None
            if section_title:
                self._set_steam_audit_detail_text(
                    state,
                    f"{section_title}\n\nThese rows are grouped together in the results table so the switch into lower-confidence titles is easier to see.",
                )
                return
            report = state.get("report")
            if report:
                self._set_steam_audit_detail_text(state, format_steam_audit_report(report))
            else:
                self._set_steam_audit_detail_text(
                    state,
                    "Run a scan, then select a game to inspect details.",
                )

    def _apply_steam_audit_report(self, state: dict, report, report_path: str):
        state["busy"] = False
        state["login_busy"] = False
        state["report"] = report
        state["report_path"] = report_path

        progress = state.get("progress")
        if progress and progress.winfo_exists():
            progress.stop()

        for key in ("scan_btn", "browse_btn", "open_report_btn", "open_report_folder_btn", "refresh_accounts_btn", "start_steam_btn"):
            widget = state.get(key)
            if widget and widget.winfo_exists():
                widget.configure(state=tk.NORMAL)

        self._refresh_steam_audit_context(state)

        summary_values = state.get("summary_values", {})
        ready_usermode = sum(1 for game in report.games if game.support_tier == "usermode_ready")
        ready_kernel = sum(1 for game in report.games if game.support_tier == "kernel_recommended")
        install_count = sum(
            1 for game in report.games
            if game.support_tier in {"install_then_scan", "install_then_kernel"}
        )
        manual_count = sum(1 for game in report.games if game.support_tier == "manual_review")
        for key, value in (
            ("total", f"{len(report.games):,}"),
            ("usermode", f"{ready_usermode:,}"),
            ("kernel", f"{ready_kernel:,}"),
            ("install", f"{install_count:,}"),
            ("manual", f"{manual_count:,}"),
        ):
            var = summary_values.get(key)
            if var is not None:
                var.set(value)

        account_label = state.get("account_label")
        if account_label and account_label.winfo_exists():
            loggedin = next((a for a in report.accounts if a.most_recent), None)
            if loggedin and state.get("steam_running"):
                account_text = loggedin.persona_name or loggedin.account_name or loggedin.steamid
                account_label.configure(text=f"Logged in: {account_text}", fg=GREEN)
            elif report.accounts:
                selected_steamid = state["account_var"].get().strip()
                active = next((a for a in report.accounts if a.steamid == selected_steamid), None) \
                    or next((a for a in report.accounts if a.most_recent), report.accounts[0])
                account_text = active.persona_name or active.account_name or active.steamid
                account_label.configure(text=f"Selected local account: {account_text}", fg=FG)
            else:
                account_label.configure(text="Local Steam account: not discovered", fg=FG_SUBTLE)

        tree = state.get("tree")
        if tree and tree.winfo_exists():
            self._refresh_steam_audit_tree(state)

        installed_count = sum(1 for game in report.games if game.installed)
        owned_only_count = sum(1 for game in report.games if not game.installed)
        self._set_steam_audit_status(
            state,
            (
                f"Scanned {len(report.games):,} Steam games "
                f"({installed_count:,} installed, {owned_only_count:,} owned-only)."
            ),
            GREEN if report.games else YELLOW,
        )
        self._update_steam_audit_details(state)

        owned_scan_notice = state.get("owned_scan_notice", "")
        if owned_scan_notice == "steam_not_running":
            selected_name = account_text if 'account_text' in locals() else "the selected account"
            self._set_steam_audit_status(
                state,
                f"Installed scan complete. Start Steam to append owned-account titles for {selected_name}.",
                YELLOW,
            )
            self._log(
                "Steam Audit: owned-account titles were skipped because Steam was not running.",
                "warn",
            )
        elif owned_scan_notice == "account_mismatch":
            self._set_steam_audit_status(
                state,
                "Installed scan complete. Ownership scan skipped -- selected account is not the one logged into Steam.",
                YELLOW,
            )
            self._log(
                "Steam Audit: owned-account titles were skipped because the selected account does not match the logged-in Steam account.",
                "warn",
            )

        self._log(
            f"Steam Audit: {ready_usermode} user-mode ready, {ready_kernel} kernel suggested, {install_count} install-to-verify",
            "ok" if ready_usermode else "info",
        )
        self._log(f"Steam Audit report saved: {os.path.abspath(report_path)}", "dim")

    def _handle_steam_audit_error(self, state: dict, error_message: str):
        state["busy"] = False
        state["login_busy"] = False
        progress = state.get("progress")
        if progress and progress.winfo_exists():
            progress.stop()
        for key in ("scan_btn", "browse_btn", "refresh_accounts_btn", "start_steam_btn"):
            widget = state.get(key)
            if widget and widget.winfo_exists():
                widget.configure(state=tk.NORMAL)
        self._update_steam_audit_controls(state)
        self._set_steam_audit_status(state, error_message, RED)
        self._set_steam_audit_detail_text(state, error_message)
        self._log(f"Steam Audit failed: {error_message}", "err")

    def _steam_is_running(self) -> bool:
        try:
            return bool(get_pid_by_name("steam.exe"))
        except Exception:
            return False

    def _resolve_steam_executable(self, steam_path: str) -> str:
        resolved_path = get_steam_install_path(steam_path or None)
        if not resolved_path:
            return ""
        steam_exe = os.path.join(resolved_path, "steam.exe")
        return steam_exe if os.path.isfile(steam_exe) else ""

    def _steam_account_name(self, account) -> str:
        return account.persona_name or account.account_name or account.steamid

    def _steam_account_subtitle(self, account) -> str:
        if account.most_recent:
            return "Most recent local Steam account"
        if account.account_name and account.account_name != account.persona_name:
            return account.account_name
        return f"SteamID {account.steamid}"

    def _steam_cookie_steamid(self, steam_cookie: str) -> str:
        if not steam_cookie:
            return ""
        if "%7C%7C" in steam_cookie:
            return steam_cookie.split("%7C%7C", 1)[0]
        if "||" in steam_cookie:
            return steam_cookie.split("||", 1)[0]
        return ""

    def _select_steam_account(self, state: dict, steamid: str):
        state["account_var"].set(steamid or "")
        save_steam_audit_settings(state["account_var"].get().strip(), "")
        self._render_steam_account_cards(state)
        self._refresh_steam_audit_context(state)

    def _render_steam_account_cards(self, state: dict):
        container = state.get("accounts_container")
        if not container or not container.winfo_exists():
            return

        state["accounts_layout_job"] = None

        layout_width = max(
            int(state.get("accounts_viewport_width", 0) or 0),
            container.winfo_width(),
            container.winfo_reqwidth(),
        )
        if layout_width <= 1:
            pending_job = state.get("accounts_layout_job")
            if pending_job:
                try:
                    container.after_cancel(pending_job)
                except Exception:
                    pass
            state["accounts_layout_job"] = container.after(60, lambda: self._render_steam_account_cards(state))
            return

        state["accounts_layout_width"] = layout_width

        for child in container.winfo_children():
            child.destroy()

        accounts = state.get("accounts", [])
        selected_steamid = state["account_var"].get().strip()
        if not accounts:
            tk.Label(
                container,
                text="No local Steam accounts were found in loginusers.vdf yet.",
                font=FONT_UI_SM,
                fg=FG_SUBTLE,
                bg=BG_CARD,
            ).pack(anchor="w")
            return

        card_gap = self._ui_px(8, minimum=4)
        card_min_width = self._ui_px(220, minimum=150)
        column_count = max(1, min(len(accounts), layout_width // (card_min_width + card_gap)))
        if column_count == 1 and len(accounts) > 1 and layout_width >= (card_min_width * 2):
            column_count = 2
        previous_columns = int(state.get("accounts_column_count", 0) or 0)
        for column in range(max(previous_columns, column_count)):
            active_column = column < column_count
            container.grid_columnconfigure(
                column,
                weight=1 if active_column else 0,
                uniform="steam_accounts" if active_column else "",
            )
        state["accounts_column_count"] = column_count

        for index, account in enumerate(accounts):
            selected = account.steamid == selected_steamid
            card_bg = BG_INPUT if selected else BG_CARD
            border_color = ACCENT if selected else BORDER
            accent_bg = ACCENT if selected else OVERLAY
            hover_bg = BG_HOVER if not selected else BG_INPUT
            hover_border = ACCENT if selected else "#5d6a64"
            name_text = self._steam_account_name(account)
            subtitle_text = self._steam_account_subtitle(account)
            short_id = account.steamid[-6:] if len(account.steamid) >= 6 else account.steamid
            initials = "".join(ch for ch in name_text if ch.isalnum())[:2].upper() or "ST"

            card = tk.Frame(
                container,
                bg=card_bg,
                highlightbackground=border_color,
                highlightthickness=1,
                padx=self._ui_px(10, minimum=4),
                pady=self._ui_px(8, minimum=3),
                cursor="hand2",
            )
            row = index // column_count
            column = index % column_count
            card.grid(
                row=row,
                column=column,
                sticky="nsew",
                padx=(0, card_gap if column < column_count - 1 else 0),
                pady=(0, card_gap),
            )

            avatar = tk.Label(
                card,
                text=initials,
                font=FONT_UI_BOLD,
                fg=FG,
                bg=accent_bg,
                padx=self._ui_px(8, minimum=4),
                pady=self._ui_px(5, minimum=2),
            )
            avatar.pack(anchor="w")

            name_label = tk.Label(
                card,
                text=name_text,
                font=FONT_UI_BOLD,
                fg=FG,
                bg=card_bg,
                anchor="w",
                justify=tk.LEFT,
                wraplength=max(self._ui_px(180, minimum=120), (layout_width // max(1, column_count)) - self._ui_px(40, minimum=20)),
            )
            name_label.pack(anchor="w", pady=(self._ui_px(8, minimum=2), self._ui_px(2, minimum=1)))

            subtitle_label = tk.Label(
                card,
                text=subtitle_text,
                font=FONT_UI_XS,
                fg=FG_SUBTLE,
                bg=card_bg,
                anchor="w",
                justify=tk.LEFT,
                wraplength=max(self._ui_px(180, minimum=120), (layout_width // max(1, column_count)) - self._ui_px(40, minimum=20)),
            )
            subtitle_label.pack(anchor="w")

            steamid_label = tk.Label(
                card,
                text=f"...{short_id}",
                font=FONT_MONO_SM,
                fg=FG_DIM,
                bg=card_bg,
                anchor="w",
            )
            steamid_label.pack(anchor="w", pady=(self._ui_px(6, minimum=2), 0))
            make_gradient_rule(
                card,
                (accent_bg if selected else BORDER, ACCENT if selected else OVERLAY, BORDER),
                height=2,
            ).pack(fill=tk.X, pady=(self._ui_px(10, minimum=3), 0))

            def _bind_click(widget, target_steamid: str = account.steamid):
                widget.bind("<Button-1>", lambda _event, sid=target_steamid: self._select_steam_account(state, sid))

            def _set_card_state(active: bool, *, card=card, avatar=avatar, name_label=name_label,
                                subtitle_label=subtitle_label, steamid_label=steamid_label,
                                default_bg=card_bg, default_border=border_color,
                                default_accent=accent_bg):
                bg = hover_bg if active else default_bg
                border = hover_border if active else default_border
                accent = ACCENT if active or selected else default_accent
                card.configure(bg=bg, highlightbackground=border)
                for widget in (name_label, subtitle_label, steamid_label):
                    widget.configure(bg=bg)
                avatar.configure(bg=accent)

            for widget in (card, avatar, name_label, subtitle_label, steamid_label):
                _bind_click(widget)
                widget.bind("<Enter>", lambda _event, fn=_set_card_state: fn(True))
                widget.bind("<Leave>", lambda _event, fn=_set_card_state: fn(False))

    def _queue_steam_account_card_render(self, state: dict, width: int | None = None):
        container = state.get("accounts_container")
        if not container or not container.winfo_exists():
            return

        target_width = max(0, int(width or container.winfo_width()))
        last_width = int(state.get("accounts_layout_width", 0) or 0)
        if target_width and abs(target_width - last_width) < 12:
            return

        pending_job = state.get("accounts_layout_job")
        if pending_job:
            try:
                container.after_cancel(pending_job)
            except Exception:
                pass
        state["accounts_layout_job"] = container.after(60, lambda: self._render_steam_account_cards(state))

    def _refresh_steam_audit_context(self, state: dict):
        path_value = state["path_var"].get().strip()
        resolved_path = get_steam_install_path(path_value or None) or ""
        accounts = get_steam_accounts(resolved_path) if resolved_path else []
        running = self._steam_is_running()
        steam_exe = self._resolve_steam_executable(resolved_path)

        state["resolved_steam_path"] = resolved_path
        state["steam_running"] = running
        state["steam_exe"] = steam_exe

        if not path_value and resolved_path:
            state["path_var"].set(resolved_path)

        selected_steamid = state["account_var"].get().strip()
        if not selected_steamid:
            preferred = next((account.steamid for account in accounts if account.most_recent), "")
            if not preferred and accounts:
                preferred = accounts[0].steamid
            if preferred != selected_steamid:
                state["account_var"].set(preferred)
                selected_steamid = preferred

        signature = tuple(
            (account.steamid, account.persona_name, account.account_name, account.most_recent)
            for account in accounts
        )
        if signature != state.get("accounts_signature") or selected_steamid != state.get("rendered_selected_steamid", ""):
            state["accounts_signature"] = signature
            state["accounts"] = accounts
            state["rendered_selected_steamid"] = selected_steamid
            self._render_steam_account_cards(state)
        else:
            state["accounts"] = accounts

        selected_account = next((account for account in accounts if account.steamid == selected_steamid), None)
        store_status_label = state.get("store_status_label")
        runtime_label = state.get("runtime_label")
        if runtime_label and runtime_label.winfo_exists():
            if resolved_path and running:
                runtime_label.configure(
                    text="Steam client detected. Owned-library scanning can use the running Steam desktop account with no browser login.",
                    fg=GREEN,
                )
            elif resolved_path:
                runtime_label.configure(
                    text="Steam client is not running. You can still scan installed games, or start Steam to append the running account's full Steam library.",
                    fg=YELLOW,
                )
            else:
                runtime_label.configure(
                    text="Steam install not detected yet. Browse to your Steam folder or refresh.",
                    fg=RED,
                )

        if store_status_label and store_status_label.winfo_exists():
            owned_enabled = bool(state["owned_var"].get())
            if not owned_enabled:
                store_status_label.configure(
                    text="Owned-account mode is off. Scanning installed games only.",
                    fg=FG_SUBTLE,
                )
            elif not running:
                store_status_label.configure(
                    text="Steam is not running yet. Start Steam to append owned-account titles automatically, or keep scanning installed games only.",
                    fg=YELLOW,
                )
            else:
                store_status_label.configure(
                    text="Owned-account mode is ready. Scan Library will query the running Steam desktop client directly with no visible sign-in.",
                    fg=GREEN,
                )

        loggedin_account = next((a for a in accounts if a.most_recent), None)
        account_label = state.get("account_label")
        if account_label and account_label.winfo_exists() and not state.get("report"):
            if loggedin_account and running:
                account_label.configure(
                    text=f"Logged in: {self._steam_account_name(loggedin_account)}",
                    fg=GREEN,
                )
            elif selected_account is not None:
                account_label.configure(
                    text=f"Selected local account: {self._steam_account_name(selected_account)}",
                    fg=FG,
                )
            elif accounts:
                account_label.configure(
                    text=f"Detected {len(accounts)} local Steam account(s). The running Steam desktop client provides owned-account titles.",
                    fg=FG_SUBTLE,
                )
            else:
                account_label.configure(text="Local Steam account: not discovered", fg=FG_SUBTLE)

        self._update_steam_audit_controls(state)

    def _update_steam_audit_controls(self, state: dict):
        owned_enabled = bool(state["owned_var"].get())
        login_busy = bool(state.get("login_busy"))
        scan_busy = bool(state.get("busy"))
        action_busy = login_busy or scan_busy
        running = bool(state.get("steam_running"))
        has_steam_exe = bool(state.get("steam_exe"))
        report_path = state.get("report_path", "")
        has_report = bool(report_path and os.path.isfile(report_path))

        for key in ("scan_btn", "browse_btn", "refresh_accounts_btn"):
            widget = state.get(key)
            if widget and widget.winfo_exists():
                widget.configure(state=tk.DISABLED if action_busy else tk.NORMAL)

        start_btn = state.get("start_steam_btn")
        if start_btn and start_btn.winfo_exists():
            start_btn.configure(
                text="Steam Running" if running else "Start Steam",
                state=tk.NORMAL if (has_steam_exe and not running and not action_busy) else tk.DISABLED,
            )

        for key in ("open_report_btn", "open_report_folder_btn"):
            widget = state.get(key)
            if widget and widget.winfo_exists():
                widget.configure(state=tk.NORMAL if (has_report and not action_busy) else tk.DISABLED)

    def _start_steam_client(self, state: dict):
        steam_exe = state.get("steam_exe") or self._resolve_steam_executable(state["path_var"].get().strip())
        if not steam_exe:
            self._handle_steam_audit_error(state, "Steam executable was not found. Browse to your Steam install first.")
            return
        try:
            os.startfile(steam_exe)
            self._log(f"Steam Audit: launched Steam client ({steam_exe})", "info")
            self._set_steam_audit_status(state, "Starting Steam client...", ACCENT)
        except Exception as exc:
            self._handle_steam_audit_error(state, f"Could not start Steam: {exc}")
            return

        def _refresh_after_launch():
            if state.get("window") and state["window"].winfo_exists():
                self._refresh_steam_audit_context(state)

        self.root.after(2000, _refresh_after_launch)

    def _steam_login_subprocess_cmd(self, *, import_only: bool = False) -> list[str]:
        _ = import_only
        return []

    def _prompt_steam_login(self, state: dict, *, start_scan_after: bool = False, import_only: bool = False):
        _ = (start_scan_after, import_only)
        state["login_busy"] = False
        self._refresh_steam_audit_context(state)
        self._set_steam_audit_status(
            state,
            "Steam browser authentication is no longer used for owned-account scans.",
            YELLOW,
        )
        self._set_steam_audit_detail_text(
            state,
            "Start Steam and click Scan Library. The tool reads owned titles directly from the running Steam desktop client.",
        )
        self._log(
            "Steam Audit: browser-based Steam session sync is deprecated. The audit now uses the running Steam desktop client directly.",
            "warn",
        )

    def _run_steam_audit_scan(
        self,
        state: dict,
        steam_path: str,
        include_owned: bool,
        steam_account: str,
    ):
        def _on_progress(msg: str):
            self.root.after(0, lambda m=msg: self._set_steam_audit_detail_text(state, m))

        try:
            report = scan_steam_library(
                steam_path or None,
                include_owned_games=include_owned,
                steam_account=steam_account or None,
                progress_fn=_on_progress,
            )
            report_path = write_steam_audit_report(
                report,
                self._steam_audit_default_report_path,
            )
            self.root.after(
                0,
                lambda r=report, p=report_path: self._apply_steam_audit_report(state, r, p),
            )
        except Exception as exc:
            self.root.after(0, lambda e=str(exc): self._handle_steam_audit_error(state, e))

    def _start_steam_audit(self, state: dict):
        if state.get("busy") or state.get("login_busy"):
            return

        self._refresh_steam_audit_context(state)
        steam_path = state["path_var"].get().strip()
        include_owned_requested = bool(state["owned_var"].get())
        include_owned = include_owned_requested
        steam_account = state["account_var"].get().strip()
        state["owned_scan_notice"] = ""
        if include_owned_requested and not state.get("steam_running"):
            include_owned = False
            state["owned_scan_notice"] = "steam_not_running"
            self._log(
                "Steam Audit: Steam is not running, scanning installed games only until the desktop client is started.",
                "warn",
            )

        if include_owned and steam_account:
            accounts = state.get("accounts", [])
            active_account = next((a for a in accounts if a.most_recent), None)
            if active_account and active_account.steamid != steam_account:
                selected_name = next(
                    (self._steam_account_name(a) for a in accounts if a.steamid == steam_account),
                    steam_account,
                )
                active_name = self._steam_account_name(active_account)
                include_owned = False
                state["owned_scan_notice"] = "account_mismatch"
                self._log(
                    f"Steam Audit: Selected account '{selected_name}' does not match the currently logged-in Steam account '{active_name}'. "
                    f"Ownership scan disabled -- log into '{selected_name}' on Steam or select '{active_name}' to use owned-account mode.",
                    "warn",
                )

        save_steam_audit_settings(steam_account, "")
        state["busy"] = True
        state["report"] = None
        state["report_path"] = ""
        self._update_steam_audit_controls(state)

        for key in ("scan_btn", "browse_btn", "open_report_btn", "open_report_folder_btn", "open_game_btn", "use_game_btn", "refresh_accounts_btn", "start_steam_btn"):
            widget = state.get(key)
            if widget and widget.winfo_exists():
                widget.configure(state=tk.DISABLED)

        progress = state.get("progress")
        if progress and progress.winfo_exists():
            progress.start(10)

        summary_values = state.get("summary_values", {})
        for var in summary_values.values():
            var.set("--")

        tree = state.get("tree")
        if tree and tree.winfo_exists():
            tree.delete(*tree.get_children())
        state["row_lookup"] = {}
        state["section_lookup"] = {}
        state["selected_game"] = None

        mode_label = "installed + owned-account" if include_owned else "installed-only"
        self._set_steam_audit_status(state, f"Scanning {mode_label} Steam audit...", ACCENT)
        self._set_steam_audit_detail_text(state, "Scanning Steam library...")
        self._log(
            "Steam Audit: scanning installed Steam libraries..."
            if not include_owned else
            "Steam Audit: scanning installed + owned-account Steam games from the running desktop client...",
            "info",
        )

        threading.Thread(
            target=self._run_steam_audit_scan,
            args=(state, steam_path, include_owned, steam_account),
            daemon=True,
        ).start()

    def _open_steam_audit_folder(self, state: dict):
        game = state.get("selected_game")
        if not game:
            return
        try:
            os.startfile(game.install_dir)
        except Exception as exc:
            self._log(f"Could not open game folder: {exc}", "err")

    def _open_steam_audit_report(self, state: dict):
        report_path = state.get("report_path", "")
        if not report_path:
            return
        try:
            os.startfile(os.path.abspath(report_path))
        except Exception as exc:
            self._log(f"Could not open Steam report: {exc}", "err")

    def _open_steam_audit_report_folder(self, state: dict):
        report_path = state.get("report_path", "")
        if not report_path:
            return
        try:
            os.startfile(os.path.dirname(os.path.abspath(report_path)))
        except Exception as exc:
            self._log(f"Could not open Steam audit folder: {exc}", "err")

    def _use_steam_audit_selection(self, state: dict):
        game = state.get("selected_game")
        if not game:
            return
        exe_name = os.path.basename(game.executable_path) if game.executable_path else ""
        if exe_name:
            self.process_var.set(exe_name)
        if game.engine in {"ue4", "ue5", "ue_unknown"}:
            self.engine_var.set("ue")
            self.engine_combo.set("ue")
        elif game.engine == "il2cpp":
            self.engine_var.set("il2cpp")
            self.engine_combo.set("il2cpp")
        elif game.engine == "mono":
            self.engine_var.set("mono")
            self.engine_combo.set("mono")
        self.kernel_var.set(bool(game.kernel_recommended))
        self._refresh_dump_buttons()
        self._update_scan_btn_visibility()
        self._set_steam_audit_status(
            state,
            f"Prepared {game.name} for the main scan flow.",
            ACCENT,
        )
        self._log(
            f"Steam Audit: staged {game.name} ({self._format_steam_support_label(game)})",
            "info",
        )

    def _open_steam_audit(self):
        if not self._steam_audit_state:
            self._build_steam_audit_workspace()
        self._show_workspace("steam_audit")
        state = self._steam_audit_state
        if state:
            self._update_steam_audit_headings(state)
            tree = state.get("tree")
            if tree and tree.winfo_exists():
                tree.focus_set()
            state["accounts_layout_width"] = 0
            self.root.after(80, lambda: self._render_steam_account_cards(state))
        return

        if self._steam_audit_window and self._steam_audit_window.winfo_exists():
            self._steam_audit_window.deiconify()
            self._steam_audit_window.lift()
            self._steam_audit_window.focus_force()
            return

        popup = tk.Toplevel(self.root)
        popup.title("Steam Library Audit")
        popup.configure(bg=BG)
        popup.geometry("1080x760")
        popup.minsize(900, 620)
        popup.transient(self.root)
        popup.overrideredirect(True)
        try:
            popup.attributes("-alpha", 0.0)
        except Exception:
            pass

        x = self.root.winfo_x() + max((self.root.winfo_width() - 1080) // 2, 30)
        y = self.root.winfo_y() + max((self.root.winfo_height() - 760) // 2, 30)
        popup.geometry(f"+{x}+{y}")

        def _on_close():
            self._steam_audit_window = None
            self._steam_audit_state = None
            popup.destroy()

        popup.protocol("WM_DELETE_WINDOW", _on_close)
        popup.bind("<Escape>", lambda _event: _on_close())
        self._steam_audit_window = popup
        popup.after(70, lambda: self._fade_in_window(popup, duration_ms=140))

        drag_state = {"x": 0, "y": 0}

        def _start_popup_drag(event):
            drag_state["x"] = event.x_root - popup.winfo_x()
            drag_state["y"] = event.y_root - popup.winfo_y()

        def _drag_popup(event):
            popup.geometry(f"+{event.x_root - drag_state['x']}+{event.y_root - drag_state['y']}")

        def _restore_popup_chrome(_event=None):
            if popup.winfo_exists():
                popup.after(10, lambda: popup.winfo_exists() and popup.overrideredirect(True))

        popup.bind("<Map>", _restore_popup_chrome)

        titlebar = tk.Frame(popup, bg=BG_CARD, highlightbackground=BORDER, highlightthickness=1)
        titlebar.pack(fill=tk.X)
        titlebar.bind("<ButtonPress-1>", _start_popup_drag)
        titlebar.bind("<B1-Motion>", _drag_popup)

        title_wrap = tk.Frame(titlebar, bg=BG_CARD)
        title_wrap.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=12, pady=7)
        title_wrap.bind("<ButtonPress-1>", _start_popup_drag)
        title_wrap.bind("<B1-Motion>", _drag_popup)
        title_label = tk.Label(title_wrap, text="Steam Library Audit", font=FONT_UI_BOLD, fg=FG, bg=BG_CARD)
        title_label.pack(anchor="w")
        title_label.bind("<ButtonPress-1>", _start_popup_drag)
        title_label.bind("<B1-Motion>", _drag_popup)

        close_btn = tk.Label(
            titlebar,
            text="✕",
            width=3,
            cursor="hand2",
            bg=BG_CARD,
            fg=FG_DIM,
            font=FONT_UI_SM,
            padx=4,
            pady=3,
        )
        close_btn.pack(side=tk.RIGHT, padx=6, pady=6)
        close_btn.bind("<Button-1>", lambda _event: _on_close())
        close_btn.bind("<Enter>", lambda _event: close_btn.configure(bg=BG_HOVER, fg=FG))
        close_btn.bind("<Leave>", lambda _event: close_btn.configure(bg=BG_CARD, fg=FG_DIM))

        make_gradient_rule(popup, ("#59462e", "#7a6850", "#496159"), height=2).pack(fill=tk.X)

        shell = tk.Frame(popup, bg=BG, padx=16, pady=16)
        shell.pack(fill=tk.BOTH, expand=True)

        header = tk.Frame(shell, bg=BG)
        header.pack(fill=tk.X, pady=(0, 12))
        tk.Label(header, text="Steam Library Audit", font=FONT_UI_LG, fg=FG, bg=BG).pack(side=tk.LEFT)

        controls_card = _make_card(shell, pady=12)
        controls_card.pack(fill=tk.X, pady=(0, 10))

        path_var = tk.StringVar(value=get_steam_install_path() or "")
        path_row = tk.Frame(controls_card, bg=BG_CARD)
        path_row.pack(fill=tk.X)
        tk.Label(path_row, text="Steam Path", font=FONT_UI_SM, fg=FG_DIM, bg=BG_CARD).pack(side=tk.LEFT)
        path_entry = make_entry(path_row, path_var, font=FONT_MONO_SM)
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 8))

        saved_settings = load_steam_audit_settings()
        owned_var = tk.BooleanVar(value=True)
        account_var = tk.StringVar(value=saved_settings.get("steam_account", ""))

        owned_row = tk.Frame(controls_card, bg=BG_CARD)
        owned_row.pack(fill=tk.X, pady=(10, 0))
        owned_check = tk.Checkbutton(
            owned_row,
            text="Append owned-account games from the running Steam desktop client",
            variable=owned_var,
            bg=BG_CARD,
            fg=FG_DIM,
            font=FONT_UI_SM,
            selectcolor=BG_INPUT,
            activebackground=BG_CARD,
            cursor="hand2",
            bd=0,
            highlightthickness=0,
        )
        owned_check.pack(side=tk.LEFT)

        context_header = tk.Frame(controls_card, bg=BG_CARD)
        context_header.pack(fill=tk.X, pady=(8, 0))
        tk.Label(
            context_header,
            text="Detected Local Steam Accounts",
            font=FONT_UI_SM,
            fg=FG_DIM,
            bg=BG_CARD,
        ).pack(side=tk.LEFT)

        accounts_container = tk.Frame(controls_card, bg=BG_CARD)
        accounts_container.pack(fill=tk.X, pady=(8, 0))

        config_row = tk.Frame(controls_card, bg=BG_CARD)
        config_row.pack(fill=tk.X, pady=(10, 0))
        config_actions = tk.Frame(config_row, bg=BG_CARD)
        config_actions.pack(side=tk.LEFT)
        report_actions = tk.Frame(config_row, bg=BG_CARD)
        report_actions.pack(side=tk.RIGHT)

        refresh_btn = _make_button(
            config_actions, "Refresh", lambda: self._refresh_steam_audit_context(state), style="ghost",
            font=FONT_UI_SM, padx=10, pady=4,
        )
        refresh_btn.pack(side=tk.LEFT, padx=(0, 8))

        start_steam_btn = _make_button(
            config_actions, "Start Steam", lambda: self._start_steam_client(state), style="ghost",
            font=FONT_UI_SM, padx=10, pady=4,
        )
        start_steam_btn.pack(side=tk.LEFT, padx=(0, 8))

        open_report_folder_btn = _make_button(
            report_actions, "Open Audit Folder", lambda: self._open_steam_audit_report_folder(state), style="ghost",
            font=FONT_UI_SM, padx=10, pady=4,
        )
        open_report_folder_btn.configure(state=tk.DISABLED)
        open_report_folder_btn.pack(side=tk.LEFT, padx=(0, 8))

        open_report_btn = _make_button(
            report_actions, "Open Report", lambda: self._open_steam_audit_report(state), style="ghost",
            font=FONT_UI_SM, padx=10, pady=4,
        )
        open_report_btn.configure(state=tk.DISABLED)
        open_report_btn.pack(side=tk.LEFT)

        summary_row = tk.Frame(shell, bg=BG)
        summary_row.pack(fill=tk.X, pady=(0, 10))

        state = {
            "window": popup,
            "path_var": path_var,
            "owned_var": owned_var,
            "account_var": account_var,
            "busy": False,
            "login_busy": False,
            "report": None,
            "report_path": self._steam_audit_default_report_path if os.path.isfile(self._steam_audit_default_report_path) else "",
            "row_lookup": {},
            "section_lookup": {},
            "selected_game": None,
            "summary_values": {},
            "refresh_accounts_btn": refresh_btn,
            "start_steam_btn": start_steam_btn,
            "open_report_folder_btn": open_report_folder_btn,
            "open_report_btn": open_report_btn,
            "accounts_container": accounts_container,
            "accounts": [],
            "accounts_signature": (),
            "steam_running": False,
            "steam_exe": "",
            "resolved_steam_path": "",
            "owned_scan_notice": "",
        }
        self._steam_audit_state = state
        self._update_steam_audit_controls(state)

        def update_owned_controls():
            state["report"] = None
            self._update_steam_audit_controls(state)
            self._refresh_steam_audit_context(state)

        owned_check.configure(command=update_owned_controls)

        def browse_steam_dir():
            initial_dir = path_var.get().strip() or os.path.expanduser("~")
            selected = filedialog.askdirectory(
                title="Choose your Steam install folder",
                parent=popup,
                initialdir=initial_dir,
            )
            if selected:
                path_var.set(selected)
                state["report"] = None
                self._refresh_steam_audit_context(state)

        browse_btn = _make_button(
            path_row, "Browse", browse_steam_dir, style="ghost",
            font=FONT_UI_SM, padx=10, pady=5,
        )
        browse_btn.pack(side=tk.LEFT, padx=(0, 6))

        scan_btn = _make_button(
            path_row, "Scan Library", lambda: self._start_steam_audit(state), style="accent",
            font=FONT_UI_BOLD, padx=16, pady=5,
        )
        scan_btn.pack(side=tk.LEFT)

        state["browse_btn"] = browse_btn
        state["scan_btn"] = scan_btn

        progress = ttk.Progressbar(controls_card, mode="indeterminate")
        progress.pack(fill=tk.X, pady=(10, 8))
        state["progress"] = progress

        meta_row = tk.Frame(controls_card, bg=BG_CARD)
        meta_row.pack(fill=tk.X)
        account_label = tk.Label(
            meta_row,
            text="Local Steam account: waiting for scan",
            font=FONT_UI_SM,
            fg=FG_SUBTLE,
            bg=BG_CARD,
        )
        account_label.pack(side=tk.LEFT)
        status_label = tk.Label(
            meta_row,
            text="Ready to scan installed Steam libraries.",
            font=FONT_UI_SM,
            fg=FG_SUBTLE,
            bg=BG_CARD,
        )
        status_label.pack(side=tk.RIGHT)
        state["account_label"] = account_label
        state["status_label"] = status_label
        update_owned_controls()

        summary_specs = [
            ("Total Games", "total", FG),
            ("User Mode Ready", "usermode", GREEN),
            ("Kernel Suggested", "kernel", YELLOW),
            ("Install To Verify", "install", ACCENT),
            ("Manual Review", "manual", FG_DIM),
        ]
        for column, (title, key, accent_color) in enumerate(summary_specs):
            card = _make_card(summary_row, pady=10)
            card.grid(row=0, column=column, sticky="nsew", padx=(0, 8 if column < len(summary_specs) - 1 else 0))
            summary_row.grid_columnconfigure(column, weight=1)
            tk.Label(card, text=title, font=FONT_UI_XS, fg=FG_SUBTLE, bg=BG_CARD).pack(anchor="w")
            value_var = tk.StringVar(value="--")
            tk.Label(card, textvariable=value_var, font=FONT_MONO_SM_BOLD, fg=accent_color, bg=BG_CARD).pack(anchor="w", pady=(4, 0))
            state["summary_values"][key] = value_var

        results_card = _make_card(shell, pady=12)
        results_card.pack(fill=tk.BOTH, expand=True)

        results_header = tk.Frame(results_card, bg=BG_CARD)
        results_header.pack(fill=tk.X, pady=(0, 8))
        tk.Label(results_header, text="Steam Games", font=FONT_UI_BOLD, fg=FG, bg=BG_CARD).pack(side=tk.LEFT)

        tree_shell = tk.Frame(results_card, bg=BG_INPUT, highlightbackground=BORDER, highlightthickness=1)
        tree_shell.pack(fill=tk.BOTH, expand=True)

        columns = ("name", "scope", "source", "engine", "support", "anti_cheat")
        tree = ttk.Treeview(
            tree_shell,
            columns=columns,
            show="headings",
            selectmode="browse",
            height=14,
        )
        tree.heading("name", text="Game")
        tree.heading("scope", text="Scope")
        tree.heading("source", text="Source")
        tree.heading("engine", text="Engine")
        tree.heading("support", text="Support")
        tree.heading("anti_cheat", text="Anti-cheat")
        tree.column("name", width=240, anchor="w")
        tree.column("scope", width=95, anchor="center")
        tree.column("source", width=120, anchor="center")
        tree.column("engine", width=165, anchor="w")
        tree.column("support", width=165, anchor="w")
        tree.column("anti_cheat", width=200, anchor="w")

        tree_scroll = make_scrollbar(tree_shell, tree.yview)
        tree.configure(yscrollcommand=tree_scroll.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 2), pady=2)
        tree.tag_configure("group", foreground=FG, background=BG_CARD)
        tree.tag_configure("ready", foreground=GREEN)
        tree.tag_configure("kernel", foreground=YELLOW)
        tree.tag_configure("likely", foreground=ACCENT)
        tree.tag_configure("unknown", foreground=FG_DIM)
        state["tree"] = tree

        detail_card = _make_card(shell, pady=12)
        detail_card.pack(fill=tk.BOTH, expand=False, pady=(10, 0))

        detail_header = tk.Frame(detail_card, bg=BG_CARD)
        detail_header.pack(fill=tk.X, pady=(0, 8))
        tk.Label(detail_header, text="Selection Details", font=FONT_UI_BOLD, fg=FG, bg=BG_CARD).pack(side=tk.LEFT)

        action_row = tk.Frame(detail_header, bg=BG_CARD)
        action_row.pack(side=tk.RIGHT)
        open_game_btn = _make_button(
            action_row, "Open Game Folder", lambda: self._open_steam_audit_folder(state), style="ghost",
            font=FONT_UI_SM, padx=10, pady=4,
        )
        open_game_btn.configure(state=tk.DISABLED)
        open_game_btn.pack(side=tk.LEFT, padx=(0, 6))
        use_game_btn = _make_button(
            action_row, "Use In Main View", lambda: self._use_steam_audit_selection(state), style="secondary",
            font=FONT_UI_SM, padx=12, pady=4,
        )
        use_game_btn.configure(state=tk.DISABLED)
        use_game_btn.pack(side=tk.LEFT)
        state["open_game_btn"] = open_game_btn
        state["use_game_btn"] = use_game_btn

        detail_shell = tk.Frame(detail_card, bg="#0d1118", highlightbackground=BORDER, highlightthickness=1)
        detail_shell.pack(fill=tk.BOTH, expand=True)
        detail_text = tk.Text(
            detail_shell,
            wrap=tk.WORD,
            height=11,
            font=FONT_MONO_SM,
            bg="#0d1118",
            fg="#b7c3d9",
            relief=tk.FLAT,
            padx=12,
            pady=10,
            insertbackground=FG,
        )
        detail_scroll = make_scrollbar(detail_shell, detail_text.yview)
        detail_text.configure(yscrollcommand=detail_scroll.set)
        detail_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        detail_scroll.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 2), pady=2)
        state["detail_text"] = detail_text

        tree.bind("<<TreeviewSelect>>", lambda _event: self._update_steam_audit_details(state))
        self._set_steam_audit_detail_text(
            state,
            "Run a scan, then select a game to inspect details.",
        )

        footer = tk.Frame(shell, bg=BG)
        footer.pack(fill=tk.X, pady=(10, 0))
        close_btn = _make_button(
            footer, "Close", _on_close, style="secondary",
            font=FONT_UI, padx=20, pady=6,
        )
        close_btn.pack(side=tk.RIGHT)

    def _build_steam_audit_workspace(self):
        if "steam_audit" in self._workspace_views:
            return

        panel = tk.Frame(self._workspace_host, bg=BG)
        self._workspace_views["steam_audit"] = panel

        hero_card = _make_card(panel, pady=10)
        hero_card.pack(fill=tk.X, pady=(0, 6))

        hero_top = tk.Frame(hero_card, bg=BG_CARD)
        hero_top.pack(fill=tk.X)
        title_wrap = tk.Frame(hero_top, bg=BG_CARD)
        title_wrap.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Label(title_wrap, text="Steam Library Audit", font=FONT_UI_LG, fg=FG, bg=BG_CARD).pack(anchor="w")
        tk.Label(
            title_wrap,
            text="Engine, anti-cheat, and support triage for your Steam library",
            font=FONT_UI_XS,
            fg=FG_SUBTLE,
            bg=BG_CARD,
        ).pack(anchor="w", pady=(1, 0))
        _make_button(
            hero_top,
            "Back to Toolkit",
            lambda: self._show_workspace("main"),
            style="ghost",
            font=FONT_UI_SM,
            padx=12,
            pady=4,
        ).pack(side=tk.RIGHT)
        make_gradient_rule(hero_card, ("#4a3a24", "#d4b06f", "#3d5c54"), height=2).pack(fill=tk.X, pady=(8, 0))

        shell = tk.Frame(panel, bg=BG)
        shell.pack(fill=tk.BOTH, expand=True)

        controls_card = _make_card(shell, pady=10)
        controls_card.pack(fill=tk.X, pady=(0, 6))

        path_var = tk.StringVar(value=get_steam_install_path() or "")
        path_row = tk.Frame(controls_card, bg=BG_CARD)
        path_row.pack(fill=tk.X)
        tk.Label(path_row, text="Steam Path", font=FONT_UI_XS, fg=FG_SUBTLE, bg=BG_CARD).pack(side=tk.LEFT)
        path_entry = make_entry(path_row, path_var, font=FONT_MONO_SM)
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 6))

        saved_settings = load_steam_audit_settings()
        owned_var = tk.BooleanVar(value=True)
        account_var = tk.StringVar(value=saved_settings.get("steam_account", ""))

        owned_row = tk.Frame(controls_card, bg=BG_CARD)
        owned_row.pack(fill=tk.X, pady=(8, 0))
        owned_check = tk.Checkbutton(
            owned_row,
            text="Include owned-account games from running Steam client",
            variable=owned_var,
            bg=BG_CARD,
            fg=FG_DIM,
            font=FONT_UI_XS,
            selectcolor=BG_INPUT,
            activebackground=BG_CARD,
            cursor="hand2",
            bd=0,
            highlightthickness=0,
        )
        owned_check.pack(side=tk.LEFT)

        context_header = tk.Frame(controls_card, bg=BG_CARD)
        context_header.pack(fill=tk.X, pady=(6, 0))
        tk.Label(
            context_header,
            text="Local Steam Accounts",
            font=FONT_UI_XS,
            fg=FG_SUBTLE,
            bg=BG_CARD,
        ).pack(side=tk.LEFT)

        accounts_shell = tk.Frame(
            controls_card,
            bg="#141c28",
            highlightbackground="#1e2a36",
            highlightthickness=1,
            height=self._ui_px(208, minimum=148),
        )
        accounts_shell.pack(fill=tk.X, pady=(6, 0))
        accounts_shell.pack_propagate(False)

        accounts_canvas = tk.Canvas(
            accounts_shell,
            bg=BG_CARD,
            bd=0,
            highlightthickness=0,
            relief=tk.FLAT,
        )
        accounts_scroll = make_scrollbar(accounts_shell, accounts_canvas.yview, width=10, min_thumb=36)
        accounts_canvas.configure(yscrollcommand=accounts_scroll.set)
        accounts_canvas.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True,
            padx=(self._ui_px(4, minimum=2), 0),
            pady=self._ui_px(4, minimum=2),
        )
        accounts_scroll.pack(
            side=tk.RIGHT,
            fill=tk.Y,
            padx=(0, self._ui_px(4, minimum=2)),
            pady=self._ui_px(4, minimum=2),
        )

        accounts_container = tk.Frame(accounts_canvas, bg=BG_CARD)
        accounts_window = accounts_canvas.create_window((0, 0), window=accounts_container, anchor="nw")

        config_row = tk.Frame(controls_card, bg=BG_CARD)
        config_row.pack(fill=tk.X, pady=(8, 0))
        config_actions = tk.Frame(config_row, bg=BG_CARD)
        config_actions.pack(side=tk.LEFT)
        report_actions = tk.Frame(config_row, bg=BG_CARD)
        report_actions.pack(side=tk.RIGHT)

        state = {
            "window": panel,
            "path_var": path_var,
            "owned_var": owned_var,
            "account_var": account_var,
            "busy": False,
            "login_busy": False,
            "report": None,
            "report_path": self._steam_audit_default_report_path if os.path.isfile(self._steam_audit_default_report_path) else "",
            "row_lookup": {},
            "section_lookup": {},
            "selected_game": None,
            "summary_values": {},
            "accounts_container": accounts_container,
            "accounts_canvas": accounts_canvas,
            "accounts": [],
            "accounts_signature": (),
            "steam_running": False,
            "steam_exe": "",
            "resolved_steam_path": "",
            "owned_scan_notice": "",
            "sort_column": "support",
            "sort_desc": False,
        }

        def _sync_accounts_scrollregion(_event=None):
            if not accounts_canvas.winfo_exists():
                return
            bbox = accounts_canvas.bbox("all")
            accounts_canvas.configure(scrollregion=bbox or (0, 0, 0, 0))

        def _sync_accounts_width(event):
            viewport_width = max(1, int(event.width))
            accounts_canvas.itemconfigure(accounts_window, width=viewport_width)
            state["accounts_viewport_width"] = viewport_width
            _sync_accounts_scrollregion()
            self._queue_steam_account_card_render(state, viewport_width)

        refresh_btn = _make_button(
            config_actions, "Refresh", lambda: self._refresh_steam_audit_context(state), style="ghost",
            font=FONT_UI_XS, padx=8, pady=3,
        )
        refresh_btn.pack(side=tk.LEFT, padx=(0, 6))

        start_steam_btn = _make_button(
            config_actions, "Start Steam", lambda: self._start_steam_client(state), style="ghost",
            font=FONT_UI_XS, padx=8, pady=3,
        )
        start_steam_btn.pack(side=tk.LEFT, padx=(0, 6))

        open_report_folder_btn = _make_button(
            report_actions, "Audit Folder", lambda: self._open_steam_audit_report_folder(state), style="ghost",
            font=FONT_UI_XS, padx=8, pady=3,
        )
        open_report_folder_btn.configure(state=tk.DISABLED)
        open_report_folder_btn.pack(side=tk.LEFT, padx=(0, 6))

        open_report_btn = _make_button(
            report_actions, "Open Report", lambda: self._open_steam_audit_report(state), style="ghost",
            font=FONT_UI_XS, padx=8, pady=3,
        )
        open_report_btn.configure(state=tk.DISABLED)
        open_report_btn.pack(side=tk.LEFT)

        state["refresh_accounts_btn"] = refresh_btn
        state["start_steam_btn"] = start_steam_btn
        state["open_report_folder_btn"] = open_report_folder_btn
        state["open_report_btn"] = open_report_btn
        self._steam_audit_state = state
        accounts_container.bind(
            "<Configure>",
            _sync_accounts_scrollregion,
            add="+",
        )
        accounts_canvas.bind(
            "<Configure>",
            _sync_accounts_width,
            add="+",
        )
        self._update_steam_audit_controls(state)

        def update_owned_controls():
            state["report"] = None
            self._update_steam_audit_controls(state)
            self._refresh_steam_audit_context(state)

        owned_check.configure(command=update_owned_controls)

        def browse_steam_dir():
            initial_dir = path_var.get().strip() or os.path.expanduser("~")
            selected = filedialog.askdirectory(
                title="Choose your Steam install folder",
                parent=self.root,
                initialdir=initial_dir,
            )
            if selected:
                path_var.set(selected)
                state["report"] = None
                self._refresh_steam_audit_context(state)

        browse_btn = _make_button(
            path_row, "Browse", browse_steam_dir, style="ghost",
            font=FONT_UI_XS, padx=8, pady=4,
        )
        browse_btn.pack(side=tk.LEFT, padx=(0, 4))

        scan_btn = _make_button(
            path_row, "Scan Library", lambda: self._start_steam_audit(state), style="accent",
            font=FONT_UI_BOLD, padx=14, pady=4,
        )
        scan_btn.pack(side=tk.LEFT)

        state["browse_btn"] = browse_btn
        state["scan_btn"] = scan_btn

        progress = ttk.Progressbar(controls_card, mode="indeterminate")
        progress.pack(fill=tk.X, pady=(8, 4))
        state["progress"] = progress

        meta_row = tk.Frame(controls_card, bg=BG_CARD)
        meta_row.pack(fill=tk.X)
        account_label = tk.Label(
            meta_row,
            text="Local Steam account: waiting for scan",
            font=FONT_UI_XS,
            fg=FG_SUBTLE,
            bg=BG_CARD,
        )
        account_label.pack(side=tk.LEFT)
        status_label = tk.Label(
            meta_row,
            text="Ready to scan installed Steam libraries.",
            font=FONT_UI_XS,
            fg=FG_SUBTLE,
            bg=BG_CARD,
        )
        status_label.pack(side=tk.RIGHT)
        state["account_label"] = account_label
        state["status_label"] = status_label
        update_owned_controls()

        summary_row = tk.Frame(shell, bg=BG)
        summary_row.pack(fill=tk.X, pady=(0, 6))
        summary_specs = [
            ("TOTAL", "total", FG, "#1e2a36"),
            ("USER MODE", "usermode", GREEN, "#162420"),
            ("KERNEL", "kernel", YELLOW, "#26201a"),
            ("INSTALL", "install", ACCENT, "#231e16"),
            ("REVIEW", "manual", FG_DIM, "#1a1e22"),
        ]
        for column, (title, key, accent_color, pill_bg) in enumerate(summary_specs):
            pill = tk.Frame(
                summary_row,
                bg=pill_bg,
                highlightbackground="#222c38",
                highlightthickness=1,
                padx=self._ui_px(12, minimum=4),
                pady=self._ui_px(8, minimum=3),
            )
            pill.grid(
                row=0,
                column=column,
                sticky="nsew",
                padx=(0, self._ui_px(4, minimum=2) if column < len(summary_specs) - 1 else 0),
            )
            summary_row.grid_columnconfigure(column, weight=1)
            value_var = tk.StringVar(value="--")
            tk.Label(
                pill, textvariable=value_var,
                font=("Cascadia Mono", 12, "bold"), fg=accent_color, bg=pill_bg,
            ).pack(anchor="center")
            tk.Label(
                pill, text=title,
                font=("Bahnschrift", 7), fg=FG_SUBTLE, bg=pill_bg,
            ).pack(anchor="center", pady=(2, 0))
            state["summary_values"][key] = value_var

        results_card = _make_card(shell, pady=10)
        results_card.pack(fill=tk.BOTH, expand=True, pady=(0, 6))

        results_header = tk.Frame(results_card, bg=BG_CARD)
        results_header.pack(fill=tk.X, pady=(0, 6))
        tk.Label(results_header, text="Games", font=FONT_UI_BOLD, fg=FG, bg=BG_CARD).pack(side=tk.LEFT)
        tk.Label(
            results_header,
            text="Click column headers to sort",
            font=("Bahnschrift", 7),
            fg=FG_SUBTLE,
            bg=BG_CARD,
        ).pack(side=tk.RIGHT, padx=(0, 4))

        tree_shell = tk.Frame(
            results_card, bg="#141c28",
            highlightbackground="#1e2a36", highlightthickness=1,
        )
        tree_shell.pack(fill=tk.BOTH, expand=True)

        columns = ("name", "scope", "source", "engine", "support", "anti_cheat")
        tree = ttk.Treeview(
            tree_shell,
            columns=columns,
            show="headings",
            selectmode="browse",
            style="SteamAudit.Treeview",
            height=16,
        )
        tree.column("name", width=self._ui_px(240, minimum=180), minwidth=self._ui_px(180, minimum=120), anchor="w", stretch=True)
        tree.column("scope", width=self._ui_px(80, minimum=70), minwidth=self._ui_px(70, minimum=60), anchor="center", stretch=False)
        tree.column("source", width=self._ui_px(110, minimum=90), minwidth=self._ui_px(90, minimum=70), anchor="center", stretch=False)
        tree.column("engine", width=self._ui_px(150, minimum=120), minwidth=self._ui_px(120, minimum=90), anchor="w", stretch=False)
        tree.column("support", width=self._ui_px(155, minimum=130), minwidth=self._ui_px(130, minimum=100), anchor="w", stretch=False)
        tree.column("anti_cheat", width=self._ui_px(180, minimum=140), minwidth=self._ui_px(140, minimum=110), anchor="w", stretch=True)

        tree_scroll = make_scrollbar(tree_shell, tree.yview, width=12, min_thumb=48)
        tree.configure(yscrollcommand=tree_scroll.set)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y, padx=(4, 3), pady=3)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(3, 0), pady=3)
        tree.tag_configure("group", foreground=FG, background="#1a2636")
        tree.tag_configure("ready", foreground=GREEN)
        tree.tag_configure("kernel", foreground=YELLOW)
        tree.tag_configure("likely", foreground=ACCENT)
        tree.tag_configure("unknown", foreground=FG_DIM)
        state["tree"] = tree
        self._update_steam_audit_headings(state)

        detail_card = _make_card(shell, pady=10)
        detail_card.pack(fill=tk.BOTH, expand=False, pady=(0, 0))
        detail_card.configure(height=self._ui_px(220, minimum=160))
        detail_card.pack_propagate(False)

        detail_header = tk.Frame(detail_card, bg=BG_CARD)
        detail_header.pack(fill=tk.X, pady=(0, 6))
        tk.Label(detail_header, text="Details", font=FONT_UI_BOLD, fg=FG, bg=BG_CARD).pack(side=tk.LEFT)

        action_row = tk.Frame(detail_header, bg=BG_CARD)
        action_row.pack(side=tk.RIGHT)
        open_game_btn = _make_button(
            action_row, "Open Folder", lambda: self._open_steam_audit_folder(state), style="ghost",
            font=FONT_UI_XS, padx=8, pady=3,
        )
        open_game_btn.configure(state=tk.DISABLED)
        open_game_btn.pack(side=tk.LEFT, padx=(0, 4))
        use_game_btn = _make_button(
            action_row, "Use In Main View", lambda: self._use_steam_audit_selection(state), style="secondary",
            font=FONT_UI_XS, padx=10, pady=3,
        )
        use_game_btn.configure(state=tk.DISABLED)
        use_game_btn.pack(side=tk.LEFT)
        state["open_game_btn"] = open_game_btn
        state["use_game_btn"] = use_game_btn
        make_gradient_rule(detail_card, ("#3d5c54", "#d8ae67", "#31404d"), height=1).pack(fill=tk.X, pady=(0, 8))

        detail_shell = tk.Frame(detail_card, bg="#0e1420", highlightbackground="#1e2a36", highlightthickness=1)
        detail_shell.pack(fill=tk.BOTH, expand=True)
        detail_text = tk.Text(
            detail_shell,
            wrap=tk.WORD,
            height=8,
            font=FONT_MONO_SM,
            bg="#0e1420",
            fg="#b0bfd0",
            relief=tk.FLAT,
            padx=14,
            pady=10,
            insertbackground=FG,
            spacing1=2,
            spacing3=2,
        )
        detail_scroll = make_scrollbar(detail_shell, detail_text.yview, width=10, min_thumb=36)
        detail_text.configure(yscrollcommand=detail_scroll.set)
        detail_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        detail_scroll.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 4), pady=4)
        state["detail_text"] = detail_text

        tree.bind("<<TreeviewSelect>>", lambda _event: self._update_steam_audit_details(state))
        self._set_steam_audit_detail_text(
            state,
            "Run a scan, then select a game to inspect details.",
        )

    def _load_dump_for_verification(self, dump_dir: str):
        from src.core.models import SDKDump, StructInfo, EnumInfo, MemberInfo

        dump = SDKDump()
        for fname, is_class in [("ClassesInfo.json", True), ("StructsInfo.json", False)]:
            fpath = os.path.join(dump_dir, fname)
            if not os.path.exists(fpath):
                continue
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f).get("data", [])
            for entry in data:
                for full_name, details in entry.items():
                    if full_name.startswith("__"):
                        continue
                    name = full_name.split(".")[-1] if "." in full_name else full_name
                    size = 0
                    members = []
                    for item in details:
                        if not isinstance(item, dict):
                            continue
                        if "__MDKClassSize" in item:
                            size = item["__MDKClassSize"]
                        elif not any(k.startswith("__") for k in item):
                            for fn, fv in item.items():
                                if isinstance(fv, list) and len(fv) == 3:
                                    members.append(MemberInfo(
                                        name=fn,
                                        offset=fv[1],
                                        size=fv[2],
                                        type_name=fv[0][0] if fv[0] else "?",
                                    ))
                    si = StructInfo(
                        name=name, full_name=full_name,
                        address=0, size=size, is_class=is_class,
                    )
                    si.members = members
                    dump.structs.append(si)

        enums_path = os.path.join(dump_dir, "EnumsInfo.json")
        if os.path.exists(enums_path):
            with open(enums_path, "r", encoding="utf-8") as f:
                data = json.load(f).get("data", [])
            for entry in data:
                for full_name, vals in entry.items():
                    if full_name.startswith("__"):
                        continue
                    name = full_name.split(".")[-1] if "." in full_name else full_name
                    ei = EnumInfo(name=name, full_name=full_name, address=0)
                    if isinstance(vals, list):
                        for v in vals:
                            if isinstance(v, list) and len(v) == 2:
                                ei.values.append((str(v[0]), v[1]))
                    dump.enums.append(ei)

        static_fields = set()
        fields_csv = os.path.join(dump_dir, "Fields.csv")
        if os.path.exists(fields_csv):
            try:
                with open(fields_csv, "r", encoding="utf-8") as f:
                    for line in f:
                        parts = line.strip().split(",")
                        if len(parts) >= 5 and parts[4].strip().lower() == "true":
                            static_fields.add((parts[0].strip(), parts[1].strip()))
            except Exception:
                pass
        if static_fields:
            for s in dump.structs:
                for m in s.members:
                    if (s.name, m.name) in static_fields:
                        m.is_static = True

        ue_ver = ""
        offsets_path = os.path.join(dump_dir, "OffsetsInfo.json")
        if os.path.exists(offsets_path):
            try:
                with open(offsets_path, "r", encoding="utf-8") as f:
                    oi = json.load(f)
                ue_ver = oi.get("game", {}).get("ue_version", "")
            except Exception:
                pass

        return dump, ue_ver

    def _summarize_sdk_dir(self, sdk_dir: str):
        if not os.path.isdir(sdk_dir):
            return False, "SDK folder missing"

        headers = [name for name in os.listdir(sdk_dir) if name.lower().endswith(".hpp")]
        if not headers:
            return False, "SDK folder has no .hpp files"

        key_files = ("SDK.hpp", "Offsets.hpp", "il2cpp_types.hpp")
        has_anchor = any(os.path.exists(os.path.join(sdk_dir, name)) for name in key_files)
        total_size = 0
        for name in headers[:]:
            try:
                total_size += os.path.getsize(os.path.join(sdk_dir, name))
            except OSError:
                pass

        if not has_anchor and len(headers) < 3:
            return False, f"Only {len(headers)} headers found"

        size_mb = total_size / (1024 * 1024) if total_size else 0
        return True, f"{len(headers)} headers, {size_mb:.1f} MB"

    def _refresh_dump_buttons(self):
        dump_dir = self.output_var.get()
        has_dump = bool(dump_dir) and os.path.exists(
            os.path.join(dump_dir, "ClassesInfo.json")
        )
        for btn in (self.viewer_btn, self.verify_btn):
            btn.configure(state=tk.NORMAL if has_dump else tk.DISABLED)
        if hasattr(self, "share_pack_btn"):
            self.share_pack_btn.configure(state=tk.NORMAL if has_dump else tk.DISABLED)
        if hasattr(self, "partner_pack_btn"):
            self.partner_pack_btn.configure(state=tk.NORMAL if has_dump else tk.DISABLED)
        self.library_verify_btn.configure(
            state=tk.NORMAL if os.path.isdir(self.games_root) else tk.DISABLED
        )
        self.open_folder_btn.configure(
            state=tk.NORMAL if bool(dump_dir) and os.path.isdir(dump_dir) else tk.DISABLED
        )

    def _update_scan_btn_visibility(self):
        engine = self.engine_var.get()
        self._update_info_layout()
        self.scan_btn.pack_forget()
        self.sdk_btn.pack_forget()
        
        if engine in ("ue", "source", "source2"):
            self.scan_btn.pack(side=tk.LEFT, padx=(0, 6))
            
        if engine not in ("source", "source2"):
            self.sdk_btn.pack(side=tk.LEFT, padx=(0, 6))

    def _copy_offset(self, key: str):
        lbl = self.info_labels.get(key)
        if not lbl:
            return
        value = lbl.cget("text")
        if value in ("--", "NOT FOUND", "Not found", "FAILED", ""):
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.root.update()

        original_color = lbl.cget("fg")
        lbl.configure(fg=COPY_FLASH)
        self.root.after(600, lambda: lbl.configure(fg=original_color))

    def _copy_log(self):
        self.log_text.configure(state=tk.NORMAL)
        content = self.log_text.get("1.0", tk.END).strip()
        self.log_text.configure(state=tk.DISABLED)
        if not content:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self.root.update()
        orig_bg = self.save_log_btn.cget("bg")
        self.save_log_btn.configure(bg=GREEN, fg=BG)
        self.root.after(1200, lambda: self.save_log_btn.configure(bg=orig_bg, fg=FG_DIM))

    def _clear_log(self):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _drop_cheat_template(self):
        from tkinter import filedialog
        from src.output.template_gen import generate_imgui_template

        dump_dir = self.output_var.get()
        if not dump_dir or not os.path.exists(os.path.join(dump_dir, "ClassesInfo.json")):
            messagebox.showwarning("GameSDK-Kit", "Run a dump first so the template can seed itself from real output.")
            return

        mode_result = [None]

        picker = tk.Toplevel(self.root)
        picker.title("Template Mode")
        picker.configure(bg=BG)
        picker.transient(self.root)
        picker.grab_set()
        self._center_popup(picker, 420, 300)

        tk.Label(
            picker, text="Choose Template Mode",
            font=FONT_UI_BOLD, fg=FG, bg=BG,
        ).pack(pady=(20, 6))
        tk.Label(
            picker, text="Select the type of project to generate.",
            font=FONT_UI_XS, fg=FG_DIM, bg=BG,
        ).pack(pady=(0, 16))

        def pick(m):
            mode_result[0] = m
            picker.destroy()

        trainer_frame = tk.Frame(picker, bg=BG_CARD, padx=16, pady=12,
                                 highlightbackground=BORDER, highlightthickness=1)
        trainer_frame.pack(fill=tk.X, padx=24, pady=(0, 8))
        _make_button(
            trainer_frame, "  Trainer  ", lambda: pick("trainer"), style="accent",
            font=FONT_UI_BOLD, padx=16, pady=6,
        ).pack(side=tk.LEFT)
        tk.Label(
            trainer_frame,
            text="Offline trainer — health, ammo, speed\ntoggles with feature card UI",
            font=FONT_UI_XS, fg=FG_SUBTLE, bg=BG_CARD, justify=tk.LEFT,
        ).pack(side=tk.LEFT, padx=(12, 0))

        admin_frame = tk.Frame(picker, bg=BG_CARD, padx=16, pady=12,
                               highlightbackground=BORDER, highlightthickness=1)
        admin_frame.pack(fill=tk.X, padx=24, pady=(0, 8))
        _make_button(
            admin_frame, " Admin-Mode ", lambda: pick("admin"), style="secondary",
            font=FONT_UI_BOLD, padx=16, pady=6,
        ).pack(side=tk.LEFT)
        tk.Label(
            admin_frame,
            text="Professional overlay — ESP, tabbed menu,\nkernel driver, external rendering",
            font=FONT_UI_XS, fg=FG_SUBTLE, bg=BG_CARD, justify=tk.LEFT,
        ).pack(side=tk.LEFT, padx=(12, 0))

        _make_button(
            picker, "Cancel", picker.destroy, style="ghost",
            font=FONT_UI_XS, padx=12, pady=4,
        ).pack(pady=(8, 0))

        picker.wait_window()

        selected_mode = mode_result[0]
        if not selected_mode:
            return

        base_game_dir = os.path.dirname(os.path.normpath(dump_dir))
        sdk_dir = os.path.join(base_game_dir, "SDK")
        game_name = os.path.basename(base_game_dir) or "dump"
        dest = filedialog.askdirectory(
            title="Choose where to create the template project",
            parent=self.root,
            initialdir=base_game_dir,
        )
        if not dest:
            return

        try:
            root_dir = generate_imgui_template(
                dump_dir,
                sdk_dir,
                dest,
                game_name=game_name,
                mode=selected_mode,
            )
            mode_label = "Admin-Mode" if selected_mode == "admin" else "Trainer"
            self._log(f"Template dropped ({mode_label}): {os.path.abspath(root_dir)}", "ok")
            self._log("  src/main.cpp                 - Win32 + D3D11 host shell", "info")
            self._log("  src/driver.h/.cpp            - kernel driver IPC client", "info")
            self._log("  src/generated_feature_catalog.hpp - seeded feature cards", "info")
            if selected_mode == "admin":
                self._log("  src/overlay.hpp/.cpp         - external transparent overlay", "info")
                self._log("  src/esp.hpp/.cpp             - ESP framework (box/name/hp/dist)", "info")
                self._log("  src/menu.hpp/.cpp            - tabbed menu (Visuals/Combat/Misc/Config)", "info")
                self._log("  src/math.hpp                 - WorldToScreen + 3D math", "info")
            else:
                self._log("  src/trainer_ui.cpp           - ImGui workbench (driver-wired)", "info")
                self._log("  data/trainer_manifest.json   - dump-driven manifest", "info")
            self._log("  bin/wdfsvc64.sys             - kernel driver", "info")
            self._log("  bin/gsd_mapper.exe           - driver loader (in-house)", "info")
            self._log("  Launch.bat                   - load driver (run as admin)", "info")
            self._log("  Build.bat                    - auto-build (clones ImGui + CMake)", "info")
            self._log("  snapshot/Offsets             - copied dump snapshot", "info")
            self._log("  snapshot/SDK                 - copied SDK snapshot", "info")
            os.startfile(root_dir)

        except Exception as e:
            self._log(f"Failed to create template: {e}", "err")

    def _open_live_viewer(self):
        dump_dir = self.output_var.get()
        if not dump_dir or not os.path.exists(os.path.join(dump_dir, "ClassesInfo.json")):
            messagebox.showwarning("GameSDK-Kit", "No dump found. Run Full SDK Dump first.")
            return
        try:
            from src.ui.live_viewer import LiveViewerApp, load_dump_data
            viewer_win = tk.Toplevel(self.root)
            dump_data = load_dump_data(dump_dir)
            LiveViewerApp(viewer_win, dump_data,
                          process_name=self.process_name or "")
            self._log("Live Viewer opened", "ok")
        except Exception as e:
            self._log(f"Could not open Live Viewer: {e}", "err")

    def _verify_dump_legacy(self):
        dump_dir = self.output_var.get()
        if not dump_dir or not os.path.exists(os.path.join(dump_dir, "ClassesInfo.json")):
            messagebox.showwarning("GameSDK-Kit", "No dump found. Run Full SDK Dump first.")
            return

        self._log("Verifying dump...", "info")
        try:
            import json
            from src.core.models import SDKDump, StructInfo, EnumInfo, MemberInfo
            from src.output.health_check import run_health_check, format_health_report

            dump = SDKDump()
            for fname, is_class in [("ClassesInfo.json", True), ("StructsInfo.json", False)]:
                fpath = os.path.join(dump_dir, fname)
                if not os.path.exists(fpath):
                    continue
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f).get("data", [])
                for entry in data:
                    for full_name, details in entry.items():
                        if full_name.startswith("__"):
                            continue
                        name = full_name.split(".")[-1] if "." in full_name else full_name
                        size = 0
                        members = []
                        for item in details:
                            if not isinstance(item, dict):
                                continue
                            if "__MDKClassSize" in item:
                                size = item["__MDKClassSize"]
                            elif not any(k.startswith("__") for k in item):
                                for fn, fv in item.items():
                                    if isinstance(fv, list) and len(fv) == 3:
                                        members.append(MemberInfo(
                                            name=fn,
                                            offset=fv[1],
                                            size=fv[2],
                                            type_name=fv[0][0] if fv[0] else "?",
                                        ))
                        si = StructInfo(
                            name=name, full_name=full_name,
                            address=0, size=size, is_class=is_class,
                        )
                        si.members = members
                        dump.structs.append(si)

            for fname in ["EnumsInfo.json"]:
                fpath = os.path.join(dump_dir, fname)
                if not os.path.exists(fpath):
                    continue
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f).get("data", [])
                for entry in data:
                    for full_name, vals in entry.items():
                        if full_name.startswith("__"):
                            continue
                        name = full_name.split(".")[-1] if "." in full_name else full_name
                        ei = EnumInfo(name=name, full_name=full_name, address=0)
                        if isinstance(vals, list):
                            for v in vals:
                                if isinstance(v, list) and len(v) == 2:
                                    ei.values.append((str(v[0]), v[1]))
                        dump.enums.append(ei)

            static_fields = set()
            fields_csv = os.path.join(dump_dir, "Fields.csv")
            if os.path.exists(fields_csv):
                try:
                    with open(fields_csv, "r", encoding="utf-8") as f:
                        for line in f:
                            parts = line.strip().split(",")
                            if len(parts) >= 5 and parts[4].strip().lower() == "true":
                                static_fields.add((parts[0].strip(), parts[1].strip()))
                except Exception:
                    pass
            if static_fields:
                for s in dump.structs:
                    for m in s.members:
                        if (s.name, m.name) in static_fields:
                            m.is_static = True

            ue_ver = ""
            try:
                with open(os.path.join(dump_dir, "OffsetsInfo.json"), "r") as f:
                    oi = json.load(f)
                    ue_ver = oi.get("game", {}).get("ue_version", "")
            except Exception:
                pass

            report = run_health_check(dump, ue_version=ue_ver)
            text = format_health_report(report, ue_version=ue_ver)

            popup = tk.Toplevel(self.root)
            popup.title("Health Report")
            popup.configure(bg=BG)
            self._set_window_size(popup, 580, 360)
            popup.resizable(True, True)

            txt = scrolledtext.ScrolledText(
                popup, wrap=tk.WORD, font=("Consolas", 9),
                bg="#0a0a14", fg="#9399b2", relief=tk.FLAT, padx=12, pady=10,
            )
            txt.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)
            txt.insert(tk.END, text)
            txt.configure(state=tk.DISABLED)

            close_btn = _make_button(
                popup, "Close", popup.destroy, style="secondary",
                font=("Segoe UI", 10), padx=20, pady=6,
            )
            close_btn.pack(pady=(0, 12))

            violations = len(report.structs_with_size_violations)
            status = "clean" if violations == 0 else f"{violations} size violations"
            self._log(
                f"Verify: {report.total_structs} structs, {report.total_enums} enums — {status}",
                "ok" if violations == 0 else "warn",
            )

        except Exception as e:
            self._log(f"Verify failed: {e}", "err")

    def _open_process_picker(self):
        from src.core.memory import get_running_processes

        procs = get_running_processes()
        if not procs:
            messagebox.showwarning("GameSDK-Kit", "Could not enumerate processes (need admin?).")
            return

        picker = tk.Toplevel(self.root)
        picker.title("Select Running Game")
        picker.configure(bg=BG)
        picker.transient(self.root)
        picker.grab_set()
        self._center_popup(picker, 380, 480)

        search_var = tk.StringVar()

        def update_list(*args):
            query = search_var.get().lower()
            lb.delete(0, tk.END)
            for pid, name in procs:
                if query in name.lower() or query in str(pid):
                    lb.insert(tk.END, f"{name}  [{pid}]")

        def on_select(event=None):
            selection = lb.curselection()
            if selection:
                item = lb.get(selection[0])
                exe_name = item.split("  [")[0].strip()
                self.process_var.set(exe_name)
                self.preset_combo.set("Custom")
                picker.destroy()

        search_frame = tk.Frame(picker, bg=BG, padx=14, pady=12)
        search_frame.pack(fill=tk.X)
        tk.Label(search_frame, text="Search", font=("Segoe UI", 9), fg=FG_DIM, bg=BG).pack(side=tk.LEFT)
        search_entry = make_entry(search_frame, search_var, font=("Consolas", 10))
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 0))
        search_entry.focus_set()
        search_var.trace_add("write", update_list)

        list_frame = tk.Frame(picker, bg=BG_CARD, padx=14, pady=5)
        list_frame.pack(fill=tk.BOTH, expand=True)

        scrollbar = make_scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        lb = tk.Listbox(
            list_frame, yscrollcommand=scrollbar.set,
            bg=BG_INPUT, fg=FG, selectbackground=OVERLAY, selectforeground=FG,
            font=("Consolas", 10), bd=0, highlightthickness=1, highlightcolor=BORDER,
        )
        lb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=lb.yview)

        lb.bind("<Double-Button-1>", on_select)
        lb.bind("<Return>", on_select)
        search_entry.bind("<Return>", lambda e: lb.focus_set() or lb.selection_set(0) or on_select())
        search_entry.bind("<Down>", lambda e: lb.focus_set() or lb.selection_set(0))

        update_list()

        btn_frame = tk.Frame(picker, bg=BG, padx=14, pady=12)
        btn_frame.pack(fill=tk.X)
        _make_button(btn_frame, "Cancel", picker.destroy, style="ghost",
                     font=("Segoe UI", 9), padx=12, pady=5).pack(side=tk.RIGHT)
        _make_button(btn_frame, "Select", on_select, style="accent",
                     font=("Segoe UI", 9, "bold"), padx=16, pady=5).pack(side=tk.RIGHT, padx=(0, 8))

    def _detect_process(self):
        name = self.process_var.get().strip()
        if not name:
            messagebox.showwarning("GameSDK-Kit", "Enter a process name first.")
            return

        self._log(f"Looking for {name}...", "info")
        pid = get_pid_by_name(name)
        if not pid:
            self._log(f"Process not found: {name}", "err")
            self._set_info("process", "NOT FOUND", RED)
            return

        base = get_module_base(pid, name)
        size_val = get_module_size(pid, name)

        if not base and self.kernel_var.get():
            from src.core.driver import get_module_base_kernel, get_module_size_kernel
            from src.core.memory import USE_DRIVER, TARGET_PID
            self._log("  Toolhelp32 blocked — falling back to kernel driver...", "warn")
            from src.core.memory import set_driver_mode
            set_driver_mode(True, pid)
            base = get_module_base_kernel(pid)
            if base:
                size_val = get_module_size_kernel(pid, base)
                if not size_val:
                    size_val = 256 * 1024 * 1024
                    self._log(f"  PE header unreadable — using 256 MB scan window", "warn")
                self._log(f"  [OK] Kernel GETBASE: 0x{base:X}, size {size_val // (1024*1024)} MB", "ok")
            else:
                self._log("  Kernel GETBASE also failed — is the game running?", "err")

        self.pid = pid
        self.base = base
        self.size = size_val
        self.process_name = name

        game_dir = name.replace(".exe", "")
        self.output_var.set(os.path.join(self.games_root, game_dir, "Offsets"))
        self._refresh_dump_buttons()
        self._refresh_current_trust_badge()

        self._set_info("process", name, GREEN)
        self._set_info("pid", str(pid), FG)
        self._set_info("base", f"0x{base:X}" if base else "FAILED", GREEN if base else RED)
        self._log(f"[OK] PID {pid}, Base 0x{base:X}, Size {size_val // (1024*1024)} MB", "ok")

        if self.kernel_var.get() and base:
            from src.core.driver import diagnose_kernel_reads
            from src.core.memory import TARGET_PID
            diagnose_kernel_reads(TARGET_PID or pid, base)

        det = detect_engine_full(name)
        self.ue_version = det.get("version", "")
        self.case_preserving = det.get("case_preserving", False) or False
        self.item_size = det.get("item_size", 24)

        detected_engine = det.get("engine", "unknown")
        self.detected_engine = detected_engine

        _R6S_PROCESS_NAMES = {"rainbowsix.exe", "rainbowsix_vulkan.exe"}
        if name.lower() in _R6S_PROCESS_NAMES:
            detected_engine = "r6s"

        if detected_engine == "r6s":
            self.engine_var.set("r6s")
            self.engine_combo.set("r6s")
        elif detected_engine == "source2":
            self.engine_var.set("source2")
            self.engine_combo.set("source2")
        elif detected_engine == "source":
            self.engine_var.set("source")
            self.engine_combo.set("source")
        elif detected_engine == "il2cpp":
            self.engine_var.set("il2cpp")
            self.engine_combo.set("il2cpp")
        elif detected_engine == "mono":
            self.engine_var.set("mono")
            self.engine_combo.set("mono")
        elif detected_engine in ("ue4", "ue5", "ue_unknown"):
            self.engine_var.set("ue")
            self.engine_combo.set("ue")

        engine_str = (
            f"{detected_engine.upper()} {self.ue_version}"
            if detected_engine != "unknown"
            else "Unknown"
        ).strip()
        self._set_info("engine", engine_str, GREEN if detected_engine != "unknown" else YELLOW)
        self._log(f"[OK] Engine: {engine_str}  (confidence: {det['confidence']})", "ok")
        det_details = det.get("details") or {}
        det_method = det.get("method", "")
        det_hint = det_details.get("hint", "")
        if det_method and det_method != "none":
            suffix = f" - {det_hint}" if det_hint else ""
            self._log(f"  Engine detector: {det_method}{suffix}", "dim")
        self.root.after(0, self._update_scan_btn_visibility)

    def _start_offset_scan(self):
        if self.scanning:
            return
        engine = self.engine_var.get()
        if engine not in ("ue", "source", "source2"):
            self._log("Offset scanning is only applicable to Unreal Engine, Source, or Source 2.", "warn")
            return
        if not self.pid:
            self._detect_process()
        if not self.pid:
            return
        self._scan_started_at = time.time()
        self.scanning = True
        self.scan_btn.configure(state=tk.DISABLED)
        self.sdk_btn.configure(state=tk.DISABLED)
        if engine == "source2":
            threading.Thread(target=self._run_source2_scan, daemon=True).start()
        elif engine == "source":
            threading.Thread(target=self._run_source_scan, daemon=True).start()
        else:
            threading.Thread(target=self._run_offset_scan, daemon=True).start()

    def _run_source2_scan(self):
        try:
            self._set_status("Source 2 schema scan...", ACCENT)
            self._set_progress(10)
            self._log("[Source2] Starting schema dump...", "info")

            handle = attach(self.pid)
            if not handle:
                self._log("Could not attach to process.", "err")
                self._set_status("Attach failed", RED)
                return

            self.handle = handle
            try:
                from src.engines.source2.dumper import dump_source2

                output_dir = self.output_var.get()
                os.makedirs(output_dir, exist_ok=True)

                def _progress(msg):
                    self._log(f"  {msg}", "dim")

                self._set_progress(30)
                sdk_dump = dump_source2(
                    handle=handle,
                    process_name=self.process_name,
                    progress_callback=_progress,
                    log_fn=lambda m: self._log(m, "info"),
                )
                self._set_progress(80)

                from src.output.json_writer import write_all as s2_write_all
                s2_write_all(
                    output_dir,
                    sdk_dump,
                    0, 0, 0,
                    process_name=self.process_name,
                    engine="source2",
                    pe_timestamp=0,
                )

                from src.output.source2_writer import (
                    write_source2_header, write_source2_sdk,
                )
                header_path = os.path.join(output_dir, "source2_schemas.hpp")
                write_source2_header(
                    header_path,
                    sdk_dump,
                    process_name=self.process_name,
                )

                sdk_output_dir = (
                    os.path.join(os.path.dirname(output_dir), "SDK")
                    if os.path.basename(output_dir).lower() == "offsets"
                    else os.path.join(output_dir, "SDK")
                )
                write_source2_sdk(
                    sdk_output_dir,
                    sdk_dump,
                    process_name=self.process_name,
                )

                self._set_progress(90)
                self._log("[Source2] Scanning engine globals...", "info")
                from src.engines.source2.globals import find_cs2_globals
                from src.output.source2_globals_writer import (
                    write_cs2_globals_header, write_cs2_globals_json,
                )
                globals_results = find_cs2_globals(
                    handle=handle,
                    pid=self.pid,
                    progress_callback=_progress,
                    log_fn=lambda m: self._log(m, "info"),
                )
                globals_header_path = os.path.join(output_dir, "source2_offsets.hpp")
                globals_json_path = os.path.join(output_dir, "source2_offsets.json")
                write_cs2_globals_header(
                    globals_header_path, globals_results, process_name=self.process_name,
                )
                write_cs2_globals_json(
                    globals_json_path, globals_results, process_name=self.process_name,
                )
                globals_ok = sum(1 for r in globals_results if r.found)

                self._set_progress(92)
                self._log("[Source2] Scanning key buttons and interfaces...", "info")
                from src.core.memory import enumerate_modules, get_module_info, read_uint32
                from src.engines.source2.buttons import find_cs2_buttons
                from src.engines.source2.interfaces import find_cs2_interfaces
                from src.output.source2_runtime_writer import (
                    write_cs2_buttons_header,
                    write_cs2_buttons_json,
                    write_cs2_info_json,
                    write_cs2_interfaces_header,
                    write_cs2_interfaces_json,
                )

                buttons_results = find_cs2_buttons(
                    handle=handle,
                    process_name=self.process_name,
                    progress_callback=_progress,
                    log_fn=lambda m: self._log(m, "info"),
                )
                interfaces_results = find_cs2_interfaces(
                    handle=handle,
                    process_name=self.process_name,
                    progress_callback=_progress,
                    log_fn=lambda m: self._log(m, "info"),
                )
                buttons_header_path = os.path.join(output_dir, "source2_buttons.hpp")
                buttons_json_path = os.path.join(output_dir, "source2_buttons.json")
                interfaces_header_path = os.path.join(output_dir, "source2_interfaces.hpp")
                interfaces_json_path = os.path.join(output_dir, "source2_interfaces.json")
                write_cs2_buttons_header(
                    buttons_header_path,
                    buttons_results,
                    process_name=self.process_name,
                )
                write_cs2_buttons_json(
                    buttons_json_path,
                    buttons_results,
                    process_name=self.process_name,
                )
                write_cs2_interfaces_header(
                    interfaces_header_path,
                    interfaces_results,
                    process_name=self.process_name,
                )
                write_cs2_interfaces_json(
                    interfaces_json_path,
                    interfaces_results,
                    process_name=self.process_name,
                )
                buttons_ok = sum(1 for r in buttons_results if r.found and r.name)
                interfaces_ok = sum(len(r.interfaces) for r in interfaces_results)

                self._log("[Source2] Scanning prediction offsets...", "info")
                from src.engines.source2.prediction_dumper import dump_prediction
                from src.output.prediction_writer import (
                    write_prediction_header, write_prediction_json,
                )
                pred_dump = dump_prediction(
                    handle=handle, pid=self.pid,
                    progress_callback=_progress,
                    log_fn=lambda m: self._log(m, "info"),
                )
                pred_header_path = os.path.join(output_dir, "source2_prediction.hpp")
                pred_json_path = os.path.join(output_dir, "source2_prediction.json")
                write_prediction_header(
                    pred_header_path,
                    pred_dump.functions, pred_dump.struct_offsets,
                    process_name=self.process_name,
                )
                write_prediction_json(
                    pred_json_path,
                    pred_dump.functions, pred_dump.struct_offsets,
                    process_name=self.process_name,
                )
                pred_ok = sum(1 for r in pred_dump.all_results if r.found)

                build_number = 0
                build_result = next(
                    (r for r in globals_results if r.found and r.name == "dwBuildNumber"),
                    None,
                )
                if build_result:
                    module_base, _ = get_module_info(self.pid, build_result.module)
                    if module_base:
                        build_number = read_uint32(handle, module_base + build_result.rva)

                module_inventory = [
                    {
                        "name": name,
                        "base": f"0x{base:X}",
                        "base_int": base,
                        "size": size,
                        "path": path,
                    }
                    for name, base, size, path in enumerate_modules(self.pid)
                ]
                info_path = os.path.join(output_dir, "source2_info.json")
                elapsed_seconds = max(0.0, time.time() - getattr(self, "_scan_started_at", time.time()))
                write_cs2_info_json(
                    info_path,
                    process_name=self.process_name,
                    sdk_dump=sdk_dump,
                    globals_results=globals_results,
                    buttons_results=buttons_results,
                    interfaces_results=interfaces_results,
                    prediction_dump=pred_dump,
                    build_number=build_number,
                    modules=module_inventory,
                    elapsed_seconds=elapsed_seconds,
                )

                self._set_progress(100)
                total_structs = len(sdk_dump.structs)
                total_enums = len(sdk_dump.enums)
                total_props = sum(len(s.members) for s in sdk_dump.structs)
                self._log(f"[Source2] Done \u2014 {total_structs} structs, {total_enums} enums, {total_props} fields", "ok")
                self._log(f"[Source2] Engine globals: {globals_ok}/{len(globals_results)} resolved", "ok")
                self._log(f"[Source2] Key buttons: {buttons_ok} resolved", "ok" if buttons_ok else "warn")
                self._log(f"[Source2] Interfaces: {interfaces_ok} resolved", "ok" if interfaces_ok else "warn")
                self._log(f"[Source2] Prediction offsets: {pred_ok}/{len(pred_dump.all_results)} resolved", "ok")
                self._log(f"  Saved: {output_dir}", "ok")
                self._log(f"  Saved: {header_path}", "ok")
                self._log(f"  Saved: {globals_header_path}", "ok")
                self._log(f"  Saved: {buttons_header_path}", "ok")
                self._log(f"  Saved: {interfaces_header_path}", "ok")
                self._log(f"  Saved: {pred_header_path}", "ok")
                self._log(f"  Saved: {info_path}", "ok")
                self._log(f"  Saved: {sdk_output_dir}", "ok")
                self._set_status("Source 2 dump complete!", GREEN)
                self._set_info("objects", f"{total_structs:,} structs / {total_enums:,} enums", FG)

                self._maybe_send_webhook_gui(
                    process_name=self.process_name,
                    engine="source2",
                    output_dir=output_dir,
                    structs_count=total_structs,
                )

            finally:
                detach(handle)
                if self.handle == handle:
                    self.handle = None

        except Exception as e:
            self._log(f"Source 2 scan error: {e}", "err")
            self._set_status("Error", RED)
        finally:
            self.scanning = False
            self.root.after(0, lambda: self.scan_btn.configure(state=tk.NORMAL))
            self.root.after(0, lambda: self.sdk_btn.configure(state=tk.NORMAL))
            self.root.after(0, self._refresh_dump_buttons)

    def _run_source_scan(self):
        try:
            self._set_status("Source scan...", ACCENT)
            self._set_progress(10)
            self._log("[Source] Starting netvar dump...", "info")

            handle = attach(self.pid)
            if not handle:
                self._log("Could not attach to process.", "err")
                self._set_status("Attach failed", RED)
                return

            self.handle = handle
            try:
                from src.engines.source.dumper import dump_source

                output_dir = self.output_var.get()
                os.makedirs(output_dir, exist_ok=True)

                def _progress(msg):
                    self._log(f"  {msg}", "dim")

                self._set_progress(30)
                sdk_dump = dump_source(
                    handle=handle,
                    process_name=self.process_name,
                    progress_callback=_progress,
                    log_fn=lambda m: self._log(m, "info"),
                )
                self._set_progress(80)

                from src.output.json_writer import write_source_dump_json
                from src.output.source_writer import write_source_header, write_source_sdk
                write_source_dump_json(
                    os.path.join(output_dir, "SourceNetvars.json"),
                    sdk_dump,
                    process_name=self.process_name,
                )

                header_path = os.path.join(output_dir, "source_netvars.hpp")
                write_source_header(
                    header_path,
                    sdk_dump,
                    process_name=self.process_name,
                )

                sdk_output_dir = (
                    os.path.join(os.path.dirname(output_dir), "SDK")
                    if os.path.basename(output_dir).lower() == "offsets"
                    else os.path.join(output_dir, "SDK")
                )
                write_source_sdk(
                    sdk_output_dir,
                    sdk_dump,
                    process_name=self.process_name,
                )

                self._set_progress(100)
                total_tables = len(sdk_dump.structs)
                total_props = sum(len(s.members) for s in sdk_dump.structs)
                self._log(f"[Source] Done — {total_tables} tables, {total_props} netvars", "ok")
                self._log(f"  Saved: {output_dir}/SourceNetvars.json", "ok")
                self._log(f"  Saved: {output_dir}/source_netvars.hpp", "ok")
                self._log(f"  Saved: {sdk_output_dir}", "ok")
                self._set_status("Source dump complete!", GREEN)

            finally:
                detach(handle)
                if self.handle == handle:
                    self.handle = None

        except Exception as e:
            self._log(f"Source scan error: {e}", "err")
            self._set_status("Error", RED)
        finally:
            self.scanning = False
            self.root.after(0, lambda: self.scan_btn.configure(state=tk.NORMAL))
            self.root.after(0, lambda: self.sdk_btn.configure(state=tk.NORMAL))
            self.root.after(0, self._refresh_dump_buttons)

    def _write_source_header(self, path, sdk_dump):
        lines = [
            "// Auto-generated by GameSDK-Kit — Source Engine Netvars",
            "// Paste into your project or #include directly.",
            f"// Process: {self.process_name}",
            f"// Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "#pragma once",
            "",
            "namespace Netvars {",
        ]
        for struct in sdk_dump.structs:
            lines.append(f"")
            lines.append(f"    namespace {struct.name} {{")
            for member in struct.members:
                lines.append(f"        constexpr int {member.name} = 0x{member.offset:X};")
            lines.append(f"    }}")
        lines.append("")
        lines.append("} // namespace Netvars")
        lines.append("")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def _offset_scan_retry_profiles(self):
        kernel_mode = bool(self.kernel_var.get())
        base_timeout = self._gworld_timeout_seconds if kernel_mode else 0.0
        return [
            {
                "label": "baseline",
                "cache_reset": False,
                "gworld_timeout": base_timeout,
            },
            {
                "label": "recovery",
                "cache_reset": True,
                "gworld_timeout": max(base_timeout * 1.6, 180.0 if kernel_mode else 90.0),
            },
            {
                "label": "max-timeout",
                "cache_reset": True,
                "gworld_timeout": max(base_timeout * 2.3, 300.0 if kernel_mode else 150.0),
            },
        ]

    @staticmethod
    def _should_continue_offset_scan_retries(result: dict) -> bool:
        return result.get("code") != "gobjects_not_found"

    @staticmethod
    def _format_gobjects_resolution_summary(meta: dict) -> str:
        if not meta:
            return ""
        method = meta.get("method")
        if method:
            return f"resolved via {method}"
        failure_kind = meta.get("failure_kind") or "live_recovery_failed"
        hit_count = int(meta.get("signature_hit_count", 0) or 0)
        normalized = int(meta.get("normalized_candidate_attempts", 0) or 0)
        structural = meta.get("structural") or {}
        shapes = int(structural.get("candidate_count", 0) or 0)
        heap_shapes = int(structural.get("heap_shape_count", 0) or 0)
        heap_valid = int(structural.get("heap_best_valid", 0) or 0)
        heap_equal = int(structural.get("heap_best_index_equal", 0) or 0)
        names_seeded = meta.get("names_seeded") or {}
        names_state = "used" if names_seeded.get("attempted") else "not used"
        heap_text = ""
        if heap_shapes or int(structural.get("heap_slot_count", 0) or 0):
            heap_text = (
                f", heap_shapes={heap_shapes}, heap_best_valid={heap_valid}, "
                f"heap_index_eq={heap_equal}"
            )
        return (
            f"{failure_kind}; signatures={hit_count} hit(s), "
            f"normalized={normalized}, names={names_state}, structural_shapes={shapes}"
            f"{heap_text}"
        )

    def _reset_offset_scan_for_retry(self):
        clear_fname_cache()
        clear_gobjects_scan_state()
        try:
            from src.core.memory import clear_memory_snapshots, reset_read_telemetry

            clear_memory_snapshots()
            reset_read_telemetry()
        except Exception:
            pass
        if self.kernel_var.get():
            try:
                from src.core.driver import invalidate_cr3_cache

                invalidate_cr3_cache(self.pid)
            except Exception:
                pass
        self.gnames = 0
        self.gobjects = 0
        self.gworld = 0
        self._detect_process()

    def _run_offset_scan_attempt(self, profile: dict):
        from src.core.diagnostics import ScanDiagnostics
        from src.engines.ue.detector import choose_ue_scan_version
        from src.engines.ue.offsets_override import load_game_offsets_override
        from src.engines.ue.version_matrix import get_version_config

        handle = attach(self.pid)
        if not handle:
            return {
                "success": False,
                "code": "attach_failed",
                "detail": "Could not attach to process.",
                "diag_text": "",
            }

        self.handle = handle
        diag = ScanDiagnostics()
        try:
            ver = choose_ue_scan_version(self.detected_engine, self.ue_version)
            use_cached_offsets = not self.kernel_var.get()
            scan_process_name = self.process_name if use_cached_offsets else None
            kernel_cached_gworld_slot = 0
            if not use_cached_offsets:
                self._log(
                    "Kernel mode: resolving GObjects/GNames live; cached offsets only remain a validated GWorld fallback.",
                    "dim",
                )
                diag.info(
                    "Kernel live scan skips cached GObjects/GNames OffsetsInfo overrides.",
                    "GObjects",
                )

            version_cfg = get_version_config(ver)
            if version_cfg.get("confirmed"):
                diag.set_confidence("Version", 1.0, f"UE {ver} - confirmed layout")
            elif self.ue_version:
                diag.set_confidence("Version", 0.6, f"UE {ver} - inferred layout (untested)")
            else:
                diag.warn(f"UE version unknown, falling back to {ver}", "Version")
                diag.set_confidence("Version", 0.3, f"defaulted to {ver}")

            self._scan_stage_begin("gobjects", "Step 1/3: GObjects")
            self._log("Finding GObjects...", "info")
            self._set_progress(5)
            gobjects, probed_item_size = find_gobjects(
                handle, self.base, self.size, ver,
                process_name=scan_process_name, diag=diag,
            )
            gobjects_meta = get_last_gobjects_resolution_meta()
            self._scan_stage_finish("gobjects")
            if not gobjects:
                return {
                    "success": False,
                    "code": "gobjects_not_found",
                    "detail": "GObjects could not be resolved.",
                    "diag_text": "\n".join(diag.format_report()),
                    "gobjects_meta": gobjects_meta,
                }

            self.gobjects = gobjects
            self.item_size = probed_item_size
            gobjects_off = gobjects - self.base
            num = get_object_count(handle, gobjects)
            self._set_info("gobjects", f"0x{gobjects_off:X}", GREEN)
            self._set_info("objects", f"{num:,}", FG)
            self._log(f"[OK] GObjects = base + 0x{gobjects_off:X}  ({num:,} objects, stride {probed_item_size})", "ok")
            summary = self._format_gobjects_resolution_summary(gobjects_meta)
            if summary:
                self._log(f"  GObjects resolver: {summary}", "dim")
            self._set_progress(33)

            override = load_game_offsets_override(self.process_name)
            gnames_override = override[0] if override is not None else None
            gworld_override = override[2] if override is not None else None
            gworld_live_override = gworld_override if use_cached_offsets else None
            if not use_cached_offsets and gworld_override is not None:
                self._log(
                    "Kernel mode: cached GWorld RVA retained as validated fallback if live search fails.",
                    "dim",
                )

            self._scan_stage_begin("gnames", "Step 2/3: GNames")
            self._log("Finding GNames...", "info")
            gnames, self.legacy_names = find_gnames(
                handle, self.base, self.size, ver,
                gobjects_hint=gobjects, gobjects_item_size=self.item_size,
                process_name=scan_process_name, override_rva=gnames_override,
                diag=diag,
            )
            self._scan_stage_finish("gnames")
            if not gnames:
                return {
                    "success": False,
                    "code": "gnames_not_found",
                    "detail": "GNames could not be resolved.",
                    "diag_text": "\n".join(diag.format_report()),
                }

            self.gnames = gnames
            gnames_off = gnames - self.base
            is_valid, cp = validate_gnames(handle, gnames, ver)
            self.case_preserving = cp or False
            self._set_info("gnames", f"0x{gnames_off:X}", GREEN)
            self._log(f"[OK] GNames = base + 0x{gnames_off:X}  (validated: {is_valid})", "ok")
            self._set_progress(66)

            try:
                from src.engines.ue.sdk_walker import (
                    probe_ffield_layout,
                    ue_version_for_ffield_layout,
                )
                from src.engines.ue.version_matrix import get_ffield_layout

                layout_probe = probe_ffield_layout(
                    handle,
                    gobjects,
                    gnames,
                    ver,
                    self.case_preserving,
                    item_size=self.item_size,
                    legacy_names=self.legacy_names,
                )
                probed_layout = layout_probe.get("layout")
                if probed_layout in ("ue427", "ue52plus"):
                    old_layout = get_ffield_layout(ver)
                    if probed_layout != old_layout:
                        old_ver = ver
                        ver = ue_version_for_ffield_layout(probed_layout, fallback=ver)
                        self.ue_version = ver
                        diag.warn(
                            f"FField layout probe changed SDK walk layout from {old_layout} "
                            f"({old_ver}) to {probed_layout} ({ver})",
                            "Version",
                        )
                        diag.set_confidence(
                            "Version",
                            max(0.8, float(layout_probe.get("confidence", 0.0))),
                            f"runtime FField probe selected {probed_layout}",
                        )
                        self._log(
                            f"  FField layout probe: {old_layout} -> {probed_layout}; "
                            f"using UE {ver} SDK layout",
                            "warn",
                        )
                    else:
                        diag.set_confidence(
                            "Version",
                            max(diag.get_confidence("Version"), 0.8),
                            f"runtime FField probe confirmed {probed_layout}",
                        )
                        self._log(
                            f"  FField layout probe: {probed_layout} confirmed "
                            f"({layout_probe.get('samples', 0)} samples)",
                            "ok",
                        )
            except Exception as exc:
                diag.warn(f"FField layout probe failed: {exc}", "Version")
                self._log(f"  FField layout probe failed: {exc}", "warn")

            if gworld_override is not None:
                from src.engines.ue.gworld import validate_gworld_rva

                if not validate_gworld_rva(
                    handle,
                    self.base,
                    gworld_override,
                    gnames,
                    ver,
                    self.case_preserving,
                    module_size=self.size,
                ):
                    if self.kernel_var.get():
                        self._log(
                            f"  Cached GWorld RVA 0x{gworld_override:X} failed kernel validation; "
                            "continuing with live scan only",
                            "warn",
                        )
                    else:
                        from src.engines.ue.offsets_override import mark_offsets_stale

                        self._log(f"  Cached GWorld RVA 0x{gworld_override:X} is stale - rescanning", "warn")
                        mark_offsets_stale(self.process_name)
                    gworld_override = None
                    gworld_live_override = None
                else:
                    self._log(f"  Cached GWorld RVA 0x{gworld_override:X} validated", "ok")
                    if self.kernel_var.get():
                        kernel_cached_gworld_slot = self.base + gworld_override
                        gworld_live_override = None
                    else:
                        gworld_live_override = gworld_override

            self._scan_stage_begin("gworld", "Step 3/3: GWorld")
            self._log("Finding GWorld...", "info")
            gworld_timeout = float(profile.get("gworld_timeout", 0.0) or 0.0)
            if gworld_timeout:
                self._log(f"  GWorld timeout guard: {int(gworld_timeout)}s ({profile.get('label', 'profile')})", "dim")

            gworld = find_gworld(
                handle,
                self.base,
                self.size,
                ver,
                override_rva=gworld_live_override,
                diag=diag,
                gobjects_ptr=gobjects,
                gnames_ptr=gnames,
                case_preserving=self.case_preserving,
                item_size=self.item_size,
                timeout_seconds=gworld_timeout,
            )
            self._scan_stage_finish("gworld")
            if not gworld and self.kernel_var.get() and kernel_cached_gworld_slot:
                self._log("  Live kernel GWorld resolution failed; trying cached fallback...", "warn")
                if validate_gworld(
                    handle,
                    kernel_cached_gworld_slot,
                    module_base=self.base,
                    module_size=self.size,
                    gnames_ptr=gnames,
                    ue_version=ver,
                    case_preserving=self.case_preserving,
                ):
                    gworld = kernel_cached_gworld_slot
                    self._log("  Cached fallback validated in kernel mode", "ok")
                else:
                    self._log("  Cached fallback failed validation in kernel mode", "warn")
            self.gworld = gworld or 0
            gworld_off = (gworld - self.base) if gworld else 0

            timed_out = any(
                entry.target == "GWorld"
                and entry.result == "warn"
                and "timed out" in entry.detail.lower()
                for entry in getattr(diag, "entries", [])
            )
            if not gworld:
                self._set_info("gworld", "Not found", YELLOW)
                return {
                    "success": False,
                    "code": "gworld_timeout" if timed_out else "gworld_not_found",
                    "detail": "GWorld scan timed out." if timed_out else "GWorld was not found by validation.",
                    "diag_text": "\n".join(diag.format_report()),
                }

            info = get_world_info(handle, gworld, self.base, self.size, gnames, ver, self.case_preserving)
            world_name = info["name"] if info else "?"
            self._set_info("gworld", f"0x{gworld_off:X}", GREEN)
            self._log(f"[OK] GWorld = base + 0x{gworld_off:X}  ({world_name})", "ok")
            self._set_progress(90)

            output_dir = self.output_var.get()
            os.makedirs(output_dir, exist_ok=True)

            pe_timestamp = 0
            try:
                from src.engines.ue.detector import _find_exe_from_process
                from src.core.pe_parser import get_pe_timestamp
                exe_path = _find_exe_from_process(self.process_name)
                if exe_path:
                    pe_timestamp = get_pe_timestamp(exe_path)
            except Exception:
                pass

            from src.output.json_writer import write_offsets_json
            write_offsets_json(
                os.path.join(output_dir, "OffsetsInfo.json"),
                gnames_off, gobjects_off, gworld_off,
                process_name=self.process_name,
                ue_version=ver,
                pe_timestamp=pe_timestamp,
                steam_appid=self._current_steam_appid(),
            )
            return {
                "success": True,
                "diag": diag,
                "gnames_off": gnames_off,
                "gobjects_off": gobjects_off,
                "gworld_off": gworld_off,
                "pe_timestamp": pe_timestamp,
                "output_dir": output_dir,
            }
        finally:
            if handle:
                detach(handle)
            if self.handle == handle:
                self.handle = None

    def _offset_failure_card_content(self, code: str):
        mapping = {
            "attach_failed": (
                "Could not attach to the target process.",
                "Close and relaunch as Administrator, then retry.",
            ),
            "gobjects_not_found": (
                "Signature voting did not produce a valid GObjects pointer.",
                "Review the GObjects diagnostics, then re-run after the map is fully loaded.",
            ),
            "gnames_not_found": (
                "GNames did not pass validation in this scan.",
                "Use Retry now to run recovery profile with cache reset.",
            ),
            "gworld_timeout": (
                "GWorld scan timed out before validation completed.",
                "Use Retry now. The dumper will escalate timeout profiles automatically.",
            ),
            "gworld_not_found": (
                "GWorld signatures did not converge on a valid pointer.",
                "Use Retry now, then run Check Dump after success to confirm health.",
            ),
            "exception": (
                "Unexpected exception interrupted the scan.",
                "Use Retry now and review sdkkit_debug.log if it repeats.",
            ),
        }
        return mapping.get(code, ("Offset scan failed.", "Use Retry now to run recovery profiles."))

    def _run_offset_scan_with_retries(self, _internal=False):
        self._scan_started_at = time.time()
        self._scan_stage_durations = {}
        self._last_scan_failure = None
        try:
            self._set_status("Scanning...", ACCENT)
            self._set_progress(0)

            profiles = self._offset_scan_retry_profiles()
            result = None
            for attempt_index, profile in enumerate(profiles, start=1):
                if attempt_index > 1:
                    self._log(f"[Retry] Attempt {attempt_index}/{len(profiles)} ({profile['label']})", "warn")
                if profile.get("cache_reset"):
                    self._log("  Resetting caches + re-detecting process...", "dim")
                    self._reset_offset_scan_for_retry()
                result = self._run_offset_scan_attempt(profile)
                if result.get("success"):
                    break
                self._last_scan_failure = result
                self._log(f"Attempt {attempt_index} failed: {result.get('detail', 'Unknown failure')}", "warn")
                gobjects_summary = self._format_gobjects_resolution_summary(
                    result.get("gobjects_meta") or {}
                )
                if gobjects_summary:
                    self._log(f"  GObjects resolver: {gobjects_summary}", "dim")
                diag_text = result.get("diag_text", "")
                if diag_text:
                    for line in diag_text.splitlines():
                        tag = "err" if "[!!]" in line else "warn" if "[??]" in line else "dim"
                        self._log(line, tag)
                if attempt_index < len(profiles):
                    if not self._should_continue_offset_scan_retries(result):
                        self._log(
                            "  Remaining profiles only extend later offset stages; GObjects recovery is already exhausted.",
                            "dim",
                        )
                        break
                    self._set_status("Retrying...", YELLOW)

            if not result or not result.get("success"):
                failure = self._last_scan_failure or {"code": "unknown", "detail": "Unknown failure", "diag_text": ""}
                cause, action = self._offset_failure_card_content(str(failure.get("code", "unknown")))
                self._set_status("Scan failed", RED)
                self._record_dump_history(
                    run_type="offset_scan",
                    success=False,
                    engine="ue",
                    detail=str(failure.get("detail", "")),
                    stage_durations=self._scan_stage_durations,
                    verification_status="Not Verified",
                )
                self.root.after(
                    0,
                    lambda c=cause, a=action, d=str(failure.get("diag_text", "") or failure.get("detail", "")):
                        self._show_scan_failure_card(c, a, d),
                )
                return

            self._set_progress(100)
            self._set_step("Done!")
            self._log("", "")
            self._log(f"  GNames   = 0x{result['gnames_off']:X}", "ok")
            self._log(f"  GObjects = 0x{result['gobjects_off']:X}", "ok")
            self._log(f"  GWorld   = 0x{result['gworld_off']:X}", "ok")
            self._log_confidence(result.get("diag"))
            self._log("", "")
            self._log(f"Offsets saved to {result['output_dir']}/OffsetsInfo.json", "ok")
            if not _internal:
                self._maybe_send_webhook_gui(
                    process_name=self.process_name,
                    engine="ue",
                    output_dir=result["output_dir"],
                    structs_count=0,
                    enums_count=0,
                    pe_timestamp=result.get("pe_timestamp", 0),
                )
            self._set_status("Offsets found!", GREEN)
            self._refresh_current_trust_badge()
            self._record_dump_history(
                run_type="offset_scan",
                success=True,
                engine="ue",
                detail="Resolved UE globals.",
                stage_durations=self._scan_stage_durations,
                verification_status=self._latest_trust_snapshot.get("status", ""),
            )
        except Exception as e:
            self._log(f"Error: {e}", "err")
            self._set_status("Error", RED)
            self._record_dump_history(
                run_type="offset_scan",
                success=False,
                engine="ue",
                detail=str(e),
                stage_durations=self._scan_stage_durations,
                verification_status="Not Verified",
            )
            cause, action = self._offset_failure_card_content("exception")
            self.root.after(0, lambda: self._show_scan_failure_card(cause, action, str(e)))
        finally:
            self._scan_stage_clear()
            if self.handle:
                detach(self.handle)
                self.handle = None
            if not _internal:
                self.scanning = False
                self.root.after(0, lambda: self.scan_btn.configure(state=tk.NORMAL))
                self.root.after(0, lambda: self.sdk_btn.configure(state=tk.NORMAL))
                self.root.after(0, self._refresh_dump_buttons)

    def _run_offset_scan(self, _internal=False):
        return self._run_offset_scan_with_retries(_internal=_internal)

        """Run the offset scan. When _internal=True, skip the finally cleanup
        (caller manages scanning state and button re-enable)."""
        try:
            self._set_status("Scanning...", ACCENT)
            self._set_progress(0)

            handle = attach(self.pid)
            if not handle:
                self._log("Could not attach. Run as admin.", "err")
                return
            self.handle = handle
            clear_fname_cache()
            clear_gobjects_scan_state()
            from src.engines.ue.detector import choose_ue_scan_version
            ver = choose_ue_scan_version(self.detected_engine, self.ue_version)

            from src.core.diagnostics import ScanDiagnostics
            diag = ScanDiagnostics()
            use_cached_offsets = not self.kernel_var.get()
            scan_process_name = self.process_name if use_cached_offsets else None
            if not use_cached_offsets:
                self._log("Kernel mode: ignoring cached OffsetsInfo overrides; resolving live.", "dim")

            from src.engines.ue.version_matrix import get_version_config
            vc = get_version_config(ver)
            if vc.get("confirmed"):
                diag.set_confidence("Version", 1.0, f"UE {ver} — confirmed layout")
            elif self.ue_version:
                diag.set_confidence("Version", 0.6, f"UE {ver} — inferred layout (untested)")
            else:
                diag.warn(f"UE version unknown, falling back to {ver}", "Version")
                diag.set_confidence("Version", 0.3, f"defaulted to {ver}")

            self._set_step("Step 1/3: GObjects")
            self._log("Finding GObjects...", "info")
            self._set_progress(5)
            gobjects, probed_item_size = find_gobjects(
                handle, self.base, self.size, ver,
                process_name=scan_process_name, diag=diag,
            )
            if not gobjects:
                self._log("GObjects not found", "err")
                self._log_diagnostics(diag)
                detach(handle)
                return
            self.gobjects = gobjects
            self.item_size = probed_item_size
            gobjects_off = gobjects - self.base
            num = get_object_count(handle, gobjects)
            self._set_info("gobjects", f"0x{gobjects_off:X}", GREEN)
            self._set_info("objects", f"{num:,}", FG)
            self._log(f"[OK] GObjects = base + 0x{gobjects_off:X}  ({num:,} objects, stride {probed_item_size})", "ok")
            self._set_progress(33)

            from src.engines.ue.offsets_override import load_game_offsets_override
            _override = load_game_offsets_override(self.process_name) if use_cached_offsets else None
            _ogn_rva = _override[0] if _override is not None else None
            _ogw_rva = _override[2] if _override is not None else None

            if False:
                from src.engines.ue.gworld import validate_gworld_rva
                from src.engines.ue.offsets_override import mark_offsets_stale
                if not validate_gworld_rva(handle, self.base, _ogw_rva, self.gnames, ver, self.case_preserving):
                    self._log(f"  Cached GWorld RVA 0x{_ogw_rva:X} is stale - rescanning", "warn")
                    mark_offsets_stale(self.process_name)
                    _ogw_rva = None
                else:
                    self._log(f"  Cached GWorld RVA 0x{_ogw_rva:X} validated", "ok")

            self._set_step("Step 2/3: GNames")
            self._log("Finding GNames...", "info")
            gnames, self.legacy_names = find_gnames(
                handle, self.base, self.size, ver,
                gobjects_hint=gobjects, gobjects_item_size=self.item_size,
                process_name=scan_process_name, override_rva=_ogn_rva,
                diag=diag,
            )
            if not gnames:
                self._log("GNames not found", "err")
                self._log_diagnostics(diag)
                detach(handle)
                return
            self.gnames = gnames
            gnames_off = gnames - self.base
            is_valid, cp = validate_gnames(handle, gnames, ver)
            self.case_preserving = cp or False
            self._set_info("gnames", f"0x{gnames_off:X}", GREEN)
            self._log(f"[OK] GNames = base + 0x{gnames_off:X}  (validated: {is_valid})", "ok")
            self._set_progress(66)

            if _ogw_rva is not None:
                from src.engines.ue.gworld import validate_gworld_rva
                from src.engines.ue.offsets_override import mark_offsets_stale
                if not validate_gworld_rva(handle, self.base, _ogw_rva, gnames, ver, self.case_preserving):
                    self._log(f"  Cached GWorld RVA 0x{_ogw_rva:X} is stale - rescanning", "warn")
                    mark_offsets_stale(self.process_name)
                    _ogw_rva = None
                else:
                    self._log(f"  Cached GWorld RVA 0x{_ogw_rva:X} validated", "ok")

            self._set_step("Step 3/3: GWorld")
            self._log("Finding GWorld...", "info")
            gworld_timeout = self._gworld_timeout_seconds if self.kernel_var.get() else 0.0
            if gworld_timeout:
                self._log(
                    f"  GWorld timeout guard: {int(gworld_timeout)}s (will continue if exceeded)",
                    "dim",
                )
            gworld = find_gworld(
                handle,
                self.base,
                self.size,
                ver,
                override_rva=_ogw_rva,
                diag=diag,
                gobjects_ptr=gobjects,
                gnames_ptr=gnames,
                case_preserving=self.case_preserving,
                item_size=self.item_size,
                timeout_seconds=gworld_timeout,
            )
            self.gworld = gworld or 0
            gworld_off = (gworld - self.base) if gworld else 0
            if not gworld:
                timed_out = any(
                    entry.target == "GWorld"
                    and entry.result == "warn"
                    and "timed out" in entry.detail.lower()
                    for entry in getattr(diag, "entries", [])
                )
                if timed_out:
                    self._log("GWorld search hit timeout; continuing without GWorld (non-critical)", "warn")
            if gworld:
                info = get_world_info(handle, gworld, self.base, self.size, gnames, ver, self.case_preserving)
                wname = info["name"] if info else "?"
                self._set_info("gworld", f"0x{gworld_off:X}", GREEN)
                self._log(f"[OK] GWorld = base + 0x{gworld_off:X}  ({wname})", "ok")
            else:
                self._set_info("gworld", "Not found", YELLOW)
                self._log("GWorld not found (non-critical)", "warn")
            self._set_progress(90)

            output_dir = self.output_var.get()
            os.makedirs(output_dir, exist_ok=True)

            pe_timestamp = 0
            try:
                from src.engines.ue.detector import _find_exe_from_process
                from src.core.pe_parser import get_pe_timestamp
                exe_path = _find_exe_from_process(self.process_name)
                if exe_path:
                    pe_timestamp = get_pe_timestamp(exe_path)
            except Exception:
                pass

            from src.output.json_writer import write_offsets_json
            write_offsets_json(
                os.path.join(output_dir, "OffsetsInfo.json"),
                gnames_off, gobjects_off, gworld_off,
                process_name=self.process_name,
                ue_version=ver,
                pe_timestamp=pe_timestamp,
                steam_appid=self._current_steam_appid(),
            )
            self._set_progress(100)
            self._set_step("Done!")
            self._log("", "")
            self._log(f"  GNames   = 0x{gnames_off:X}", "ok")
            self._log(f"  GObjects = 0x{gobjects_off:X}", "ok")
            self._log(f"  GWorld   = 0x{gworld_off:X}", "ok")
            self._log_confidence(diag)
            self._log("", "")
            self._log(f"Offsets saved to {output_dir}/OffsetsInfo.json", "ok")
            if not _internal:
                self._maybe_send_webhook_gui(
                    process_name=self.process_name,
                    engine="ue",
                    output_dir=output_dir,
                    structs_count=0,
                    enums_count=0,
                    pe_timestamp=pe_timestamp,
                )
            self._set_status("Offsets found!", GREEN)
            detach(handle)
            self.handle = None

        except Exception as e:
            self._log(f"Error: {e}", "err")
            self._set_status("Error", RED)
        finally:
            if self.handle:
                detach(self.handle)
                self.handle = None
            if not _internal:
                self.scanning = False
                self.root.after(0, lambda: self.scan_btn.configure(state=tk.NORMAL))
                self.root.after(0, lambda: self.sdk_btn.configure(state=tk.NORMAL))
                self.root.after(0, self._refresh_dump_buttons)

    def _start_full_dump(self):
        if self.scanning:
            return
        if not self.pid:
            self._detect_process()
        if not self.pid:
            return
        self._scan_started_at = time.time()
        self.scanning = True
        self.scan_btn.configure(state=tk.DISABLED)
        self.sdk_btn.configure(state=tk.DISABLED)
        threading.Thread(target=self._run_full_dump, daemon=True).start()

    def _run_full_dump(self):
        engine = self.engine_var.get()
        try:
            if engine == "il2cpp":
                self._run_il2cpp_dump()
            elif engine == "mono":
                self._run_mono_dump()
            elif engine == "avm2":
                self._run_avm2_dump()
            elif engine == "r6s":
                self._run_r6s_dump()
            elif engine == "source2":
                self._run_source2_scan()
            elif engine == "source":
                self._run_source_scan()
            else:
                self._run_ue_dump()
        except Exception as e:
            self._log(f"Error: {e}", "err")
            import traceback
            self._log(traceback.format_exc(), "err")
            self._set_status("Error", RED)
            self._record_dump_history(
                run_type="full_dump",
                success=False,
                engine=engine,
                detail=str(e),
                verification_status="Not Verified",
            )
        finally:
            self.scanning = False
            self.root.after(0, lambda: self.scan_btn.configure(state=tk.NORMAL))
            self.root.after(0, lambda: self.sdk_btn.configure(state=tk.NORMAL))
            self.root.after(0, self._refresh_dump_buttons)

    def _run_ue_dump(self):
        if not self.gnames or not self.gobjects:
            self._run_offset_scan(_internal=True)
        if not self.gnames or not self.gobjects:
            self._log("Cannot do SDK dump without offsets", "err")
            return

        self._set_status("SDK walk...", ACCENT)
        self._set_step("Walking SDK...")
        self._log("Starting full SDK walk...", "info")

        handle = attach(self.pid)
        if not handle:
            self._log("Could not attach", "err")
            return

        from src.engines.ue.detector import choose_ue_scan_version
        ver = choose_ue_scan_version(self.detected_engine, self.ue_version)
        start_time = time.time()

        self._set_step("Walking SDK...")

        progress_state = {"last_current": -1, "last_t": 0.0}

        def progress(current, total):
            pct = 10 + (current * 85 / total) if total else 0
            self.root.after(0, lambda p=pct: self._set_progress(p))
            if total:
                now = time.time()
                delta_needed = max(1, total // 1000)
                should_refresh = (
                    progress_state["last_current"] < 0
                    or current >= total
                    or (current - progress_state["last_current"]) >= delta_needed
                    or (now - progress_state["last_t"]) >= 0.5
                )
                if should_refresh:
                    progress_state["last_current"] = current
                    progress_state["last_t"] = now
                    self.root.after(
                        0,
                        lambda c=current, t=total: self._set_status(f"{c:,}/{t:,}", ACCENT),
                    )

        dump = walk_sdk(
            handle, self.gobjects, self.gnames, ver,
            self.case_preserving, self.legacy_names, self.item_size,
            progress_callback=progress,
        )

        self._set_step("Writing files...")
        self._set_progress(97)
        elapsed = time.time() - start_time

        pe_timestamp = 0
        try:
            from src.engines.ue.detector import _find_exe_from_process
            from src.core.pe_parser import get_pe_timestamp
            exe_path = _find_exe_from_process(self.process_name)
            if exe_path:
                pe_timestamp = get_pe_timestamp(exe_path)
        except Exception:
            pass

        output_dir = self.output_var.get()
        gnames_off = self.gnames - self.base
        gobjects_off = self.gobjects - self.base
        gworld_off = (self.gworld - self.base) if self.gworld else 0

        gengine_off = 0
        try:
            gengine_off = find_gengine(
                handle, self.base, self.size,
                self.gnames, ver, self.case_preserving,
            )
            if gengine_off:
                self._log(f"[OK] GEngine = base + 0x{gengine_off:X}", "ok")
        except Exception:
            pass

        write_all(
            output_dir,
            dump,
            gnames_off,
            gobjects_off,
            gworld_off,
            process_name=self.process_name,
            ue_version=ver,
            pe_timestamp=pe_timestamp,
            steam_appid=self._current_steam_appid(),
            gengine_off=gengine_off,
        )

        detach(handle)
        self._set_progress(100)
        self._set_step("Done!")
        self._log("", "")
        self._log(f"SDK dump complete in {elapsed:.1f}s!", "ok")
        self._log(f"  Structs/Classes: {len(dump.structs)}", "ok")
        self._log(f"  Enums:           {len(dump.enums)}", "ok")
        self._log("", "")
        for f in os.listdir(output_dir):
            fp = os.path.join(output_dir, f)
            if os.path.isfile(fp):
                fsize = os.path.getsize(fp)
                self._log(f"  {f:30s} {fsize // 1024:>6d} KB", "dim")
        self._log("", "")
        self._log(f"Output: {os.path.abspath(output_dir)}", "ok")
        self._set_status(f"Done! {len(dump.structs)} classes", GREEN)
        self._maybe_send_webhook_gui(
            process_name=self.process_name,
            engine="ue",
            output_dir=output_dir,
            structs_count=len(dump.structs),
            enums_count=len(dump.enums),
            pe_timestamp=pe_timestamp,
        )
        self._record_dump_history(
            run_type="full_dump",
            success=True,
            engine="ue",
            detail=f"SDK walk complete ({len(dump.structs)} structs, {len(dump.enums)} enums).",
            verification_status=self._latest_trust_snapshot.get("status", ""),
        )

        self._auto_generate_sdk(output_dir, dump)
        self.root.after(500, self._verify_dump)

    def _run_il2cpp_dump(self):
        from src.engines.il2cpp.dumper import dump_il2cpp
        self._set_status("IL2CPP dump...", ACCENT)
        self._set_step("IL2CPP...")
        self._log("Starting IL2CPP dump...", "info")
        handle = attach(self.pid)
        if not handle:
            self._log("Could not attach", "err")
            return
        from src.core.memory import get_module_info
        from src.engines.ue.detector import find_il2cpp_module, _find_exe_from_process
        il2cpp_mod = find_il2cpp_module(self.pid) or "GameAssembly.dll"
        ga_base, ga_size = get_module_info(self.pid, il2cpp_mod)
        if not ga_base:
            ga_base, ga_size = get_module_info(self.pid, self.process_name)
        if not ga_base and self.kernel_var.get():
            from src.core.driver import get_module_base_kernel, get_module_size_kernel
            self._log("  Toolhelp32 blocked — using kernel GETBASE...", "warn")
            ga_base = get_module_base_kernel(self.pid)
            if ga_base:
                ga_size = get_module_size_kernel(self.pid, ga_base) or (256 * 1024 * 1024)
        if not ga_base:
            self._log(f"IL2CPP module ({il2cpp_mod}) not found", "err")
            detach(handle)
            return
        self._log(f"[OK] {il2cpp_mod}: 0x{ga_base:X}", "ok")

        exe_path = None
        pe_timestamp = 0
        try:
            from src.core.pe_parser import get_pe_timestamp
            exe_path = _find_exe_from_process(self.process_name)
            if exe_path:
                pe_timestamp = get_pe_timestamp(exe_path)
        except Exception:
            pass

        self._log(f"  Module size: {ga_size // (1024*1024)} MB", "dim")

        start_time = time.time()
        def progress(current, total):
            pct = current * 100 / total if total else 0
            self.root.after(0, lambda p=pct: self._set_progress(p))

        def _log_fn(msg: str):
            self.root.after(0, lambda m=msg: self._log(f"  {m}", "dim"))

        dump = dump_il2cpp(
            handle, ga_base, ga_size, self.process_name,
            exe_path=exe_path,
            progress_callback=progress,
            log_fn=_log_fn,
        )
        elapsed = time.time() - start_time

        if not dump.structs and not dump.enums:
            self._run_diagnostics_il2cpp(handle, self.pid, il2cpp_mod, exe_path)

        output_dir = self.output_var.get()

        from src.output.json_writer import write_all
        write_all(
            output_dir,
            dump,
            0,
            0,
            0,
            process_name=self.process_name,
            engine="il2cpp",
            unity_version=getattr(dump, "unity_version", ""),
            metadata_version=getattr(dump, "metadata_version", ""),
            pe_timestamp=pe_timestamp,
            steam_appid=self._current_steam_appid(),
        )
        detach(handle)
        self._set_progress(100)
        self._set_step("Done!")
        self._log("", "")
        self._log(f"IL2CPP dump complete in {elapsed:.1f}s!", "ok")
        self._log(f"  Structs/Classes: {len(dump.structs)}", "ok")
        self._log(f"  Enums:           {len(dump.enums)}", "ok")
        self._log("", "")
        for f in os.listdir(output_dir):
            fp = os.path.join(output_dir, f)
            if os.path.isfile(fp):
                fsize = os.path.getsize(fp)
                self._log(f"  {f:30s} {fsize // 1024:>6d} KB", "dim")
        self._log("", "")
        self._log(f"Output: {os.path.abspath(output_dir)}", "ok")
        self._set_status(f"Done! {len(dump.structs)} classes", GREEN if dump.structs else RED)
        self._maybe_send_webhook_gui(
            process_name=self.process_name,
            engine="il2cpp",
            output_dir=output_dir,
            structs_count=len(dump.structs),
            enums_count=len(dump.enums),
            pe_timestamp=pe_timestamp,
        )
        self._record_dump_history(
            run_type="full_dump",
            success=True,
            engine="il2cpp",
            detail=f"IL2CPP dump complete ({len(dump.structs)} structs, {len(dump.enums)} enums).",
            verification_status=self._latest_trust_snapshot.get("status", ""),
        )

        self._auto_generate_sdk(output_dir, dump)
        self.root.after(500, self._verify_dump)

    def _run_diagnostics_il2cpp(self, handle, pid, il2cpp_mod, exe_path):
        import struct as _struct
        from src.core.memory import read_bytes, iter_readable_regions
        from src.core.pe_parser import get_pe_export_names

        STANDARD_MAGIC = b"\xAF\x1B\xB1\xFA"
        SEP = "-" * 48

        self._log("", "")
        self._log(SEP, "dim")
        self._log("  DIAGNOSTICS", "info")
        self._log(SEP, "dim")

        game_dir = os.path.dirname(exe_path) if exe_path else None
        meta_path = None
        meta_magic = None

        if game_dir and os.path.isdir(game_dir):
            for entry in os.listdir(game_dir):
                entry_path = os.path.join(game_dir, entry)
                if not os.path.isdir(entry_path):
                    continue
                if not (entry.endswith("_Data") or entry == "Data"):
                    continue
                meta_dir = os.path.join(entry_path, "il2cpp_data", "Metadata")
                if not os.path.isdir(meta_dir):
                    continue
                for fname in os.listdir(meta_dir):
                    if not fname.endswith(".dat"):
                        continue
                    cand = os.path.join(meta_dir, fname)
                    try:
                        with open(cand, "rb") as f:
                            first = f.read(8)
                        if first[:4] == STANDARD_MAGIC:
                            meta_path = cand
                            meta_magic = "standard"
                        elif meta_path is None:
                            meta_path = cand
                            meta_magic = first[:4].hex()
                    except OSError:
                        pass
                if meta_path:
                    break

        if meta_path is None:
            self._log("  No metadata .dat file found in il2cpp_data/Metadata/", "warn")
            self._log("  Unusual install structure or missing game files.", "dim")
        elif meta_magic == "standard":
            self._log(f"  Metadata on disk: {os.path.basename(meta_path)} — standard format", "ok")
            self._log("  File is readable. Dump may have failed due to unsupported IL2CPP version.", "dim")
        else:
            size_mb = os.path.getsize(meta_path) // (1024 * 1024)
            self._log(f"  Metadata on disk: {os.path.basename(meta_path)} ({size_mb} MB) — ENCRYPTED", "warn")
            self._log(f"  Magic bytes: {meta_magic}  (expected: af1bb1fa)", "dim")
            self._log("  The game ships an encrypted metadata file.", "dim")

        self._log("  Scanning process memory for decrypted metadata...", "dim")
        found_in_mem = False
        try:
            CHUNK = 4 * 1024 * 1024
            for region_base, region_size in iter_readable_regions(handle):
                if region_size < 4:
                    continue
                offset = 0
                while offset < region_size:
                    chunk = read_bytes(handle, region_base + offset, min(CHUNK, region_size - offset))
                    if chunk and STANDARD_MAGIC in chunk:
                        idx = chunk.index(STANDARD_MAGIC)
                        ver = _struct.unpack_from("<I", chunk, idx + 4)[0] if idx + 8 <= len(chunk) else 0
                        self._log(f"  Decrypted metadata in memory at 0x{region_base+offset+idx:X} (version {ver})", "ok")
                        self._log("  This should have been found automatically — please report as a bug.", "warn")
                        found_in_mem = True
                        break
                    offset += CHUNK
                if found_in_mem:
                    break
        except Exception as e:
            self._log(f"  Memory scan error: {e}", "err")

        if not found_in_mem:
            self._log("  No standard IL2CPP metadata found in process memory.", "warn")
            if meta_magic and meta_magic != "standard":
                self._log("  Encrypted on disk + not decrypted to standard format in memory.", "dim")
                self._log("  This game uses a proprietary IL2CPP fork with custom encryption.", "dim")
            else:
                self._log("  The game may still be loading, or the tool lacks memory access.", "dim")
                self._log("  Try running as Administrator and retry.", "dim")

        il2cpp_path = None
        if game_dir:
            cand = os.path.join(game_dir, il2cpp_mod)
            if os.path.isfile(cand):
                il2cpp_path = cand

        if il2cpp_path:
            try:
                exports = get_pe_export_names(il2cpp_path)
                total = len(exports)
                if total > 0:
                    readable = sum(
                        1 for n in exports
                        if any(kw in n.lower() for kw in ("il2cpp", "unity", "mono", "_", "."))
                    )
                    obfuscated = total - readable
                    self._log(f"  {il2cpp_mod}: {total} exports — {readable} readable, {obfuscated} obfuscated", "dim")
                    if obfuscated > readable and total > 10:
                        self._log("  Export names are obfuscated — custom/protected IL2CPP build.", "dim")
            except Exception:
                pass

        self._log(SEP, "dim")
        self._log("", "")

    def _run_mono_dump(self):
        from src.engines.mono.dumper import dump_mono
        self._set_status("Mono dump...", ACCENT)
        self._set_step("Mono...")
        self._log("Starting Mono dump...", "info")
        handle = attach(self.pid)
        if not handle:
            self._log("Could not attach", "err")
            return
        start_time = time.time()
        def progress(current, total):
            pct = current * 100 / total if total else 0
            self.root.after(0, lambda p=pct: self._set_progress(p))

        pe_timestamp = 0
        try:
            from src.engines.ue.detector import _find_exe_from_process
            from src.core.pe_parser import get_pe_timestamp
            exe_path = _find_exe_from_process(self.process_name)
            if exe_path:
                pe_timestamp = get_pe_timestamp(exe_path)
        except Exception:
            pass

        def mono_log(msg):
            for line in str(msg).split("\n"):
                self._log(line, "dim")

        dump = dump_mono(handle, self.pid, self.process_name, progress_callback=progress, log=mono_log)
        elapsed = time.time() - start_time
        output_dir = self.output_var.get()
        from src.output.json_writer import write_all
        write_all(
            output_dir,
            dump,
            0,
            0,
            0,
            process_name=self.process_name,
            engine="mono",
            pe_timestamp=pe_timestamp,
            steam_appid=self._current_steam_appid(),
        )
        detach(handle)
        self._set_progress(100)
        self._set_step("Done!")
        self._log("", "")
        self._log(f"Mono dump complete in {elapsed:.1f}s!", "ok")
        self._log(f"  Structs/Classes: {len(dump.structs)}", "ok")
        self._log(f"  Enums:           {len(dump.enums)}", "ok")
        self._log("", "")
        for f in os.listdir(output_dir):
            fp = os.path.join(output_dir, f)
            if os.path.isfile(fp):
                fsize = os.path.getsize(fp)
                self._log(f"  {f:30s} {fsize // 1024:>6d} KB", "dim")
        self._log("", "")
        self._log(f"Output: {os.path.abspath(output_dir)}", "ok")
        self._set_status(f"Done! {len(dump.structs)} classes", GREEN)
        self._maybe_send_webhook_gui(
            process_name=self.process_name,
            engine="mono",
            output_dir=output_dir,
            structs_count=len(dump.structs),
            enums_count=len(dump.enums),
            pe_timestamp=pe_timestamp,
        )
        self._record_dump_history(
            run_type="full_dump",
            success=True,
            engine="mono",
            detail=f"Mono dump complete ({len(dump.structs)} structs, {len(dump.enums)} enums).",
            verification_status=self._latest_trust_snapshot.get("status", ""),
        )

        self._auto_generate_sdk(output_dir, dump)
        self.root.after(500, self._verify_dump)

    def _run_avm2_dump(self):
        from src.engines.avm2.dumper import run_dump
        self._set_status("AVM2 dump...", ACCENT)
        self._set_step("AVM2...")
        self._log("Starting AVM2 entity dump...", "info")
        game_name = self.process_name.replace(".exe", "").lower()
        output_dir = self.output_var.get()
        start_time = time.time()
        def progress(step, total, msg):
            pct = step * 100 / total if total else 0
            self.root.after(0, lambda p=pct: self._set_progress(p))
            self.root.after(0, lambda m=msg: self._set_status(m, ACCENT))
            self._log(f"[{step}/{total}] {msg}", "info")
        result = run_dump(
            process_name=self.process_name, game_name=game_name,
            output_dir=output_dir, progress_callback=progress, verbose=False,
        )
        elapsed = time.time() - start_time
        if result.get("error"):
            self._log(f"{result['error']}", "err")
            self._set_status("Error", RED)
            return
        entities = result.get("entities", [])
        self._set_progress(100)
        self._set_step("Done!")
        self._log(f"AVM2 dump complete in {elapsed:.1f}s!", "ok")
        self._log(f"  Chain used: {result.get('successful_chain', 'none')}", "ok")
        self._log(f"  Entities:   {len(entities)}", "ok")
        if result.get("output_path"):
            self._log(f"Output: {os.path.abspath(result['output_path'])}", "ok")
        self._set_status(f"Done! {len(entities)} entities", GREEN)
        self._maybe_send_webhook_gui(
            process_name=self.process_name,
            engine="avm2",
            output_dir=output_dir,
            structs_count=0,
            enums_count=0,
            pe_timestamp=0,
        )
        self._record_dump_history(
            run_type="full_dump",
            success=True,
            engine="avm2",
            detail=f"AVM2 dump complete ({len(entities)} entities).",
            verification_status=self._latest_trust_snapshot.get("status", ""),
        )

        self.root.after(500, self._verify_dump)

    def _run_r6s_dump(self):
        from src.engines.r6s.dumper import run_r6s_dump, format_scan_report
        from src.core.memory import get_module_info

        self._set_status("R6S offset scan...", ACCENT)
        self._set_step("Scanning...")
        self._log("Starting Rainbow Six Siege offset scan...", "info")

        if not self.handle:
            self.handle = attach(self.pid)
        if not self.handle:
            self._log("Failed to attach to process", "err")
            self._set_status("Attach failed", RED)
            return

        mod_base, mod_size = get_module_info(self.pid, self.process_name)
        if not mod_base and self.kernel_var.get():
            from src.core.driver import get_module_base_kernel, get_module_size_kernel
            self._log("  Toolhelp32 blocked — using kernel GETBASE...", "warn")
            mod_base = get_module_base_kernel(self.pid)
            if mod_base:
                mod_size = get_module_size_kernel(self.pid, mod_base) or (256 * 1024 * 1024)
        if not mod_base:
            self._log(f"Could not find module {self.process_name}", "err")
            self._set_status("Module not found", RED)
            return

        self._log(f"[OK] {self.process_name}: 0x{mod_base:X} ({mod_size // (1024*1024)} MB)", "ok")

        output_dir = self.output_var.get()
        start_time = time.time()

        def progress(step, total, msg):
            pct = step * 100 / total if total else 0
            self.root.after(0, lambda p=pct: self._set_progress(p))
            self.root.after(0, lambda m=msg: self._set_status(m, ACCENT))

        result = run_r6s_dump(
            handle=self.handle,
            pid=self.pid,
            module_base=mod_base,
            module_size=mod_size,
            process_name=self.process_name,
            output_dir=output_dir,
            progress_callback=progress,
        )

        elapsed = time.time() - start_time

        report = format_scan_report(result)
        for line in report.split("\n"):
            if "[!!]" in line:
                self._log(line, "err")
            elif "[OK]" in line:
                self._log(line, "ok")
            elif "[??]" in line:
                self._log(line, "warn")
            else:
                self._log(line, "info")

        self._set_progress(100)
        self._set_step("Done!")
        self._log(f"R6S scan complete in {elapsed:.1f}s!", "ok")
        self._log(f"  Found: {result.total_found}  Valid: {result.total_valid}", "ok")
        if output_dir:
            self._log(f"Output: {os.path.abspath(output_dir)}", "ok")
        self._set_status(
            f"Done! {result.total_found} offsets ({result.total_valid} valid)", GREEN
        )
        self._maybe_send_webhook_gui(
            process_name=self.process_name,
            engine="r6s",
            output_dir=output_dir,
            structs_count=int(getattr(result, "total_found", 0)),
            enums_count=0,
            pe_timestamp=0,
        )
        self._record_dump_history(
            run_type="full_dump",
            success=True,
            engine="r6s",
            detail=f"R6S scan complete ({result.total_found} found, {result.total_valid} valid).",
            verification_status=self._latest_trust_snapshot.get("status", ""),
        )

    def _auto_generate_sdk(self, dump_dir, dump):
        try:
            self._set_step("Generating SDK...")
            self._log("Starting SDK generation...", "info")
            base_game_dir = os.path.dirname(os.path.normpath(dump_dir))
            sdk_dir = os.path.join(base_game_dir, "SDK")
            from src.output.sdk_gen import generate_sdk
            packages = generate_sdk(dump_dir, sdk_dir)
            num_packages = len(packages) if packages else 0
            self._log(f"[OK] Generated {num_packages} packages in {os.path.abspath(sdk_dir)}", "ok")
        except Exception as e:
            self._log(f"SDK generation error: {e}", "err")

    def _verify_dump(self):
        dump_dir = self.output_var.get()
        if not dump_dir or not os.path.exists(os.path.join(dump_dir, "ClassesInfo.json")):
            messagebox.showwarning("GameSDK-Kit", "No dump found. Run Full SDK Dump first.")
            return

        self._log("Checking current dump...", "info")
        try:
            from src.output.health_check import run_health_check, format_health_report, write_health_sidecar

            dump, ue_ver = self._load_dump_for_verification(dump_dir)
            report = run_health_check(dump, ue_version=ue_ver)
            text = format_health_report(report, ue_version=ue_ver)
            health_path = write_health_sidecar(dump_dir, report, ue_version=ue_ver)
            self._show_report_popup("Dump Health", text, size="640x420")

            violations = len(report.structs_with_size_violations)
            if violations == 0 and report.confidence_grade == "HIGH":
                status = "clean"
                tag = "ok"
            elif violations == 0:
                status = f"{report.confidence_grade.lower()} confidence"
                tag = "warn"
            else:
                status = f"{violations} size violations"
                tag = "warn"
            self._log(
                f"Check Dump: {report.total_structs} structs, {report.total_enums} enums - {status}",
                tag,
            )
            self._log(f"Health report saved: {os.path.abspath(health_path)}", "dim")
            self._refresh_current_trust_badge()
            self._maybe_send_webhook_gui(
                process_name=self.process_name or self.process_var.get().strip(),
                engine=self.engine_var.get(),
                output_dir=dump_dir,
                structs_count=report.total_structs,
                enums_count=report.total_enums,
                pe_timestamp=0,
            )
            self._record_dump_history(
                run_type="check_dump",
                success=(violations == 0 and report.confidence_grade == "HIGH"),
                engine=self.engine_var.get(),
                detail=f"Check dump result: {status}",
                verification_status=self._latest_trust_snapshot.get("status", ""),
            )
        except Exception as e:
            self._log(f"Verify failed: {e}", "err")
            self._record_dump_history(
                run_type="check_dump",
                success=False,
                engine=self.engine_var.get(),
                detail=str(e),
                verification_status="Not Verified",
            )

    def _verify_library(self):
        if not os.path.isdir(self.games_root):
            messagebox.showwarning("GameSDK-Kit", f"Games folder not found:\n{self.games_root}")
            return

        self._log("Verifying dump library under games...", "info")
        try:
            from src.output.health_check import run_health_check, write_health_sidecar

            game_dirs = [
                os.path.join(self.games_root, name)
                for name in sorted(os.listdir(self.games_root))
                if os.path.isdir(os.path.join(self.games_root, name))
            ]

            lines = ["Dump Library Verification", ""]
            total_games = 0
            healthy_games = 0
            warning_games = 0
            missing_games = 0

            for game_dir in game_dirs:
                total_games += 1
                game_name = os.path.basename(game_dir)
                dump_dir = os.path.join(game_dir, "Offsets")
                sdk_dir = os.path.join(game_dir, "SDK")

                if not os.path.exists(os.path.join(dump_dir, "ClassesInfo.json")):
                    missing_games += 1
                    sdk_ok, sdk_msg = self._summarize_sdk_dir(sdk_dir)
                    lines.append(f"[MISSING] {game_name}")
                    lines.append("  Offsets: missing or incomplete")
                    lines.append(f"  SDK: {'OK' if sdk_ok else 'MISSING'} - {sdk_msg}")
                    lines.append("")
                    continue

                dump, ue_ver = self._load_dump_for_verification(dump_dir)
                report = run_health_check(dump, ue_version=ue_ver)
                write_health_sidecar(dump_dir, report, ue_version=ue_ver)
                sdk_ok, sdk_msg = self._summarize_sdk_dir(sdk_dir)
                violations = len(report.structs_with_size_violations)
                zero_enums = len(report.enums_with_zero_values)

                is_clean = (
                    violations == 0 and
                    report.total_structs > 0 and
                    sdk_ok and
                    report.confidence_grade == "HIGH"
                )
                if is_clean:
                    healthy_games += 1
                    tag = "[OK]"
                else:
                    warning_games += 1
                    tag = "[WARN]"

                lines.append(f"{tag} {game_name}")
                lines.append(
                    f"  Offsets: {report.total_structs} structs, {report.total_enums} enums, "
                    f"{violations} size issues, confidence {report.confidence_grade}, UE {ue_ver or 'unknown'}"
                )
                if zero_enums:
                    lines.append(f"  Enums with no values: {zero_enums}")
                lines.append(f"  SDK: {'OK' if sdk_ok else 'WARN'} - {sdk_msg}")
                lines.append("")

            summary = (
                f"Scanned {total_games} game folders - "
                f"{healthy_games} clean, {warning_games} warnings, {missing_games} missing offsets"
            )
            lines.insert(2, summary)
            lines.insert(3, "")

            self._show_report_popup("Dump Library Verification", "\n".join(lines), size="760x520")
            self._log(summary, "ok" if warning_games == 0 and missing_games == 0 else "warn")
        except Exception as e:
            self._log(f"Library verification failed: {e}", "err")

def main():
    root = tk.Tk()
    app = SDKKitApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
