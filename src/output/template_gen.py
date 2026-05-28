
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Tuple

_PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

@dataclass
class FeatureCandidate:
    label: str
    group: str
    class_name: str
    full_name: str
    field_name: str
    field_type: str
    offset: int
    size: int
    control: str
    score: int
    notes: str

_FEATURE_HINTS: Tuple[Tuple[str, str, str, int], ...] = (
    ("health", "Vitals", "slider_float", 120),
    ("hp", "Vitals", "slider_float", 105),
    ("stamina", "Vitals", "slider_float", 100),
    ("energy", "Vitals", "slider_float", 92),
    ("mana", "Vitals", "slider_float", 90),
    ("shield", "Vitals", "slider_float", 88),
    ("armor", "Vitals", "slider_float", 84),
    ("speed", "Movement", "slider_float", 110),
    ("movespeed", "Movement", "slider_float", 106),
    ("walkspeed", "Movement", "slider_float", 102),
    ("runspeed", "Movement", "slider_float", 98),
    ("jump", "Movement", "slider_float", 82),
    ("gravity", "Movement", "slider_float", 80),
    ("ammo", "Weapons", "slider_int", 104),
    ("reload", "Weapons", "slider_float", 92),
    ("damage", "Weapons", "slider_float", 100),
    ("spread", "Weapons", "slider_float", 74),
    ("recoil", "Weapons", "slider_float", 74),
    ("firerate", "Weapons", "slider_float", 78),
    ("cooldown", "Systems", "slider_float", 84),
    ("gold", "Resources", "slider_int", 92),
    ("money", "Resources", "slider_int", 92),
    ("coins", "Resources", "slider_int", 88),
    ("currency", "Resources", "slider_int", 88),
    ("xp", "Progression", "slider_int", 76),
    ("experience", "Progression", "slider_int", 80),
    ("level", "Progression", "slider_int", 72),
    ("time", "World", "slider_float", 70),
)

_BOOL_KEYWORDS = (
    "enabled",
    "visible",
    "active",
    "invulnerable",
    "god",
    "noclip",
    "frozen",
    "debug",
    "lock",
)

_IGNORED_PACKAGES = {
    "system",
    "mono",
    "microsoft",
    "ms",
    "aot",
    "newtonsoft",
    "jetbrains",
}

def _load_json(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)

def _copy_snapshot_tree(source_dir: str, target_dir: str) -> int:
    if not os.path.isdir(source_dir):
        return 0

    if os.path.isdir(target_dir):
        shutil.rmtree(target_dir)
    os.makedirs(os.path.dirname(target_dir), exist_ok=True)
    shutil.copytree(source_dir, target_dir)

    copied = 0
    for _, _, files in os.walk(target_dir):
        copied += len(files)
    return copied

def _safe_stem(name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_]+", "_", name.strip())
    safe = safe.strip("_") or "workbench"
    if safe[0].isdigit():
        safe = f"_{safe}"
    return safe

def _cpp_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')

def _humanize_label(value: str) -> str:
    base = value.replace("_", " ").strip()
    base = re.sub(r"(?<!^)(?=[A-Z])", " ", base)
    return re.sub(r"\s+", " ", base).strip().title()

def _iter_dump_members(dump_dir: str) -> Iterable[Dict[str, object]]:
    for file_name, is_class in (
        ("ClassesInfo.json", True),
        ("StructsInfo.json", False),
    ):
        path = os.path.join(dump_dir, file_name)
        if not os.path.exists(path):
            continue
        for entry in _load_json(path).get("data", []):
            for full_name, details in entry.items():
                if full_name.startswith("__"):
                    continue
                package = full_name.split(".", 1)[0] if "." in full_name else "Global"
                class_name = full_name.split(".")[-1]
                for item in details:
                    if not isinstance(item, dict):
                        continue
                    if any(key.startswith("__") for key in item):
                        continue
                    for field_name, field_def in item.items():
                        if not isinstance(field_def, list) or len(field_def) != 3:
                            continue
                        type_info, offset, size = field_def
                        type_name = ""
                        if isinstance(type_info, list) and type_info:
                            type_name = str(type_info[0])
                        elif type_info is not None:
                            type_name = str(type_info)
                        yield {
                            "package": package,
                            "class_name": class_name,
                            "full_name": full_name,
                            "field_name": field_name,
                            "field_type": type_name or "unknown",
                            "offset": int(offset),
                            "size": int(size),
                            "is_class": is_class,
                        }

def _score_candidate(member: Dict[str, object]) -> FeatureCandidate | None:
    package = str(member["package"])
    class_name = str(member["class_name"])
    field_name = str(member["field_name"])
    field_type = str(member["field_type"])
    name_l = field_name.lower()
    class_l = class_name.lower()
    package_l = package.lower()

    if package_l in _IGNORED_PACKAGES:
        return None
    if class_l.startswith("i") and len(class_name) > 1 and class_name[1].isupper():
        return None
    if name_l in {"value__", "klass", "monitor", "_items", "_size", "_version"}:
        return None

    control = "read_only"
    score = 0
    group = "Discovered"
    label = _humanize_label(field_name) or field_name
    notes = "Recovered from the current dump."

    if field_type.lower() in {"bool", "boolean"} or any(
        flag in name_l for flag in _BOOL_KEYWORDS
    ):
        control = "toggle"
        score = max(score, 64)
        group = "Toggles"
        notes = "Likely state flag based on field naming."

    for needle, hinted_group, hinted_control, hinted_score in _FEATURE_HINTS:
        if needle in name_l or needle in class_l:
            group = hinted_group
            control = hinted_control
            score = max(score, hinted_score)
            label = _humanize_label(field_name)
            notes = f"Matched the '{needle}' feature heuristic from the dump."

    if field_type.lower() in {"float", "double", "single"} and control == "read_only":
        control = "slider_float"
        score = max(score, 40)
    elif (
        any(token in field_type.lower() for token in ("int", "uint", "long", "short"))
        and control == "read_only"
    ):
        control = "slider_int"
        score = max(score, 36)

    if "component" in class_l or "stats" in class_l or "attribute" in class_l:
        score += 8
    if member["offset"] == 0:
        score -= 12
    if member["size"] <= 0:
        score -= 8

    if score < 45:
        return None

    return FeatureCandidate(
        label=label,
        group=group,
        class_name=class_name,
        full_name=str(member["full_name"]),
        field_name=field_name,
        field_type=field_type,
        offset=int(member["offset"]),
        size=int(member["size"]),
        control=control,
        score=score,
        notes=notes,
    )

def _build_feature_catalog(dump_dir: str, limit: int = 18) -> List[FeatureCandidate]:
    seen = set()
    candidates: List[FeatureCandidate] = []
    for member in _iter_dump_members(dump_dir):
        candidate = _score_candidate(member)
        if not candidate:
            continue
        dedupe_key = (candidate.full_name, candidate.field_name)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        candidates.append(candidate)
    candidates.sort(
        key=lambda item: (-item.score, item.group, item.class_name, item.offset)
    )
    return candidates[:limit]

def _build_package_summary(sdk_dir: str, limit: int = 14) -> List[Tuple[str, int]]:
    if not os.path.isdir(sdk_dir):
        return []
    headers = [name for name in os.listdir(sdk_dir) if name.lower().endswith(".hpp")]
    summary: List[Tuple[str, int]] = []
    for name in headers:
        path = os.path.join(sdk_dir, name)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                line_count = sum(1 for _ in handle)
        except OSError:
            line_count = 0
        summary.append((os.path.splitext(name)[0], line_count))
    summary.sort(key=lambda item: (-item[1], item[0].lower()))
    return summary[:limit]

def _read_offsets_meta(dump_dir: str) -> Dict[str, str]:
    path = os.path.join(dump_dir, "OffsetsInfo.json")
    if not os.path.exists(path):
        return {}
    data = _load_json(path)
    game = data.get("game", {})
    return {
        "engine": str(data.get("engine", "")),
        "process": str(game.get("process", "")),
        "ue_version": str(game.get("ue_version", "")),
        "unity_version": str(game.get("unity_version", "")),
        "metadata_version": str(game.get("metadata_version", "")),
        "dump_timestamp": str(game.get("dump_timestamp", "")),
    }

def _detect_engine_type(meta: Dict[str, str]) -> str:
    engine = (meta.get("engine") or "").lower().strip()
    ue_ver = (meta.get("ue_version") or "").strip()
    unity_ver = (meta.get("unity_version") or "").strip()

    if engine in ("ue", "unreal", "ue4", "ue5"):
        if ue_ver.startswith("5."):
            return "ue5"
        return "ue4"
    if engine in ("unity", "il2cpp", "mono"):
        return "unity"
    if unity_ver:
        return "unity"
    if ue_ver:
        return "ue5" if ue_ver.startswith("5.") else "ue4"
    return "unknown"

def _window_class_for_engine(engine_type: str) -> str:
    if engine_type in ("ue4", "ue5"):
        return "UnrealWindow"
    if engine_type == "unity":
        return "UnityWndClass"
    return ""

def _extract_engine_offsets(
    dump_dir: str, engine_type: str
) -> Dict[str, int]:
    offsets: Dict[str, int] = {}

    if engine_type in ("ue4", "ue5"):
        offsets = _extract_ue_offsets_inner(dump_dir)
    elif engine_type == "unity":
        offsets = _extract_unity_offsets_inner(dump_dir)

    return offsets

def _extract_ue_offsets_inner(dump_dir: str) -> Dict[str, int]:
    offsets: Dict[str, int] = {}

    globals_path = os.path.join(dump_dir, "Globals.json")
    if os.path.exists(globals_path):
        g = _load_json(globals_path)
        for key in ("GWorld", "gworld"):
            if key in g:
                offsets["kGWorld"] = int(str(g[key]), 16) if isinstance(g[key], str) else int(g[key])
                break

    fields_path = os.path.join(dump_dir, "Fields.csv")
    if not os.path.exists(fields_path):
        return offsets

    _FIELD_MAP = {
        ("World", "PersistentLevel"):                        "kWorldPersistentLevel",
        ("World", "OwningGameInstance"):                     "kWorldOwningGameInstance",
        ("GameInstance", "LocalPlayers"):                    "kGameInstanceLocalPlayers",
        ("PLAYER", "PlayerController"):                     "kPlayerPlayerController",
        ("PlayerController", "AcknowledgedPawn"):            "kPlayerControllerAcknowledgedPawn",
        ("PlayerController", "PlayerCameraManager"):         "kPlayerControllerCameraManager",
        ("Controller", "ControlRotation"):                   "kControllerControlRotation",
        ("PlayerCameraManager", "CameraCachePrivate"):       "kPlayerCameraManagerCameraCachePrivate",
        ("Actor", "RootComponent"):                          "kActorRootComponent",
        ("SceneComponent", "RelativeLocation"):              "kSceneComponentRelativeLocation",
        ("Pawn", "PlayerState"):                             "kPawnPlayerState",
    }

    try:
        with open(fields_path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) < 3:
                    continue
                cls, field, off_str = parts[0], parts[1], parts[2]
                key = (cls, field)
                if key in _FIELD_MAP and off_str.startswith("0x"):
                    offsets[_FIELD_MAP[key]] = int(off_str, 16)
    except Exception:
        pass

    return offsets

def _extract_unity_offsets_inner(dump_dir: str) -> Dict[str, int]:
    offsets: Dict[str, int] = {}

    globals_path = os.path.join(dump_dir, "Globals.json")
    if os.path.exists(globals_path):
        g = _load_json(globals_path)
        for key, const in [
            ("GameObjectManager", "kGameObjectManager"),
            ("GOM", "kGameObjectManager"),
            ("gom", "kGameObjectManager"),
        ]:
            if key in g:
                offsets[const] = int(str(g[key]), 16) if isinstance(g[key], str) else int(g[key])
                break

    fields_path = os.path.join(dump_dir, "Fields.csv")
    if not os.path.exists(fields_path):
        return offsets

    _UNITY_FIELD_MAP = {
        ("Transform", "m_LocalPosition"):            "kTransformLocalPosition",
        ("Transform", "localPosition"):              "kTransformLocalPosition",
        ("Camera", "m_Fov"):                         "kCameraFov",
        ("Camera", "fieldOfView"):                   "kCameraFov",
        ("Camera", "m_FieldOfView"):                 "kCameraFov",
        ("GameObject", "m_Layer"):                   "kGameObjectLayer",
        ("GameObject", "m_Tag"):                     "kGameObjectTag",
        ("Component", "m_GameObject"):               "kComponentGameObject",
        ("Behaviour", "m_Enabled"):                  "kBehaviourEnabled",
    }

    try:
        with open(fields_path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) < 3:
                    continue
                cls, field, off_str = parts[0], parts[1], parts[2]
                key = (cls, field)
                if key in _UNITY_FIELD_MAP and off_str.startswith("0x"):
                    offsets[_UNITY_FIELD_MAP[key]] = int(off_str, 16)
    except Exception:
        pass

    return offsets

def _render_generated_catalog_header(
    game_name: str,
    meta: Dict[str, str],
    features: List[FeatureCandidate],
    packages: List[Tuple[str, int]],
    ue_offsets: Dict[str, int] | None = None,
    engine_type: str = "unknown",
    window_class: str = "",
) -> str:
    feature_rows = []
    for item in features:
        feature_rows.append(
            "    {"
            f'"{_cpp_string(item.label)}", '
            f'"{_cpp_string(item.group)}", '
            f'"{_cpp_string(item.class_name)}", '
            f'"{_cpp_string(item.full_name)}", '
            f'"{_cpp_string(item.field_name)}", '
            f'"{_cpp_string(item.field_type)}", '
            f"{item.offset}, "
            f'"0x{item.offset:X}", '
            f"{item.size}, "
            f'"{_cpp_string(item.control)}", '
            f'"{_cpp_string(item.notes)}"'
            "},"
        )

    package_rows = []
    for package_name, line_count in packages:
        package_rows.append(f'    {{"{_cpp_string(package_name)}", {line_count}}},')

    dump_stamp = meta.get("dump_timestamp") or datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    engine_line = meta.get("engine") or "unknown"
    version_line = meta.get("unity_version") or meta.get("ue_version") or "unknown"

    feature_body = (
        os.linesep.join(feature_rows)
        if feature_rows
        else (
            '    {"No mapped features", "Review", "ManualReview", "ManualReview", '
            '"Check dump", "n/a", "0x0", 0, "read_only", '
            '"No strong feature candidates were discovered automatically."},'
        )
    )
    package_body = (
        os.linesep.join(package_rows) if package_rows else '    {"SDK pending", 0},'
    )

    _ENGINE_ENUM = {"ue4": 0, "ue5": 1, "unity": 2, "unknown": 3}
    engine_enum_val = _ENGINE_ENUM.get(engine_type, 3)

    offsets_block = ""
    if ue_offsets:
        lines = []
        _UE_ORDER = [
            "kGWorld", "kWorldPersistentLevel", "kWorldOwningGameInstance",
            "kGameInstanceLocalPlayers", "kPlayerPlayerController",
            "kPlayerControllerAcknowledgedPawn", "kPlayerControllerCameraManager",
            "kControllerControlRotation", "kPlayerCameraManagerCameraCachePrivate",
            "kActorRootComponent", "kSceneComponentRelativeLocation",
            "kPawnPlayerState",
        ]
        _UNITY_ORDER = [
            "kGameObjectManager",
            "kTransformLocalPosition", "kCameraFov",
            "kGameObjectLayer", "kGameObjectTag",
            "kComponentGameObject", "kBehaviourEnabled",
        ]
        order = _UE_ORDER if engine_type in ("ue4", "ue5") else _UNITY_ORDER
        for name in order:
            if name in ue_offsets:
                lines.append(
                    f"inline constexpr std::uint64_t {name} = "
                    f"0x{ue_offsets[name]:X}ULL;"
                )
        for name, val in ue_offsets.items():
            if name not in order:
                lines.append(
                    f"inline constexpr std::uint64_t {name} = 0x{val:X}ULL;"
                )
        label = "UE" if engine_type in ("ue4", "ue5") else "Unity/IL2CPP"
        if lines:
            offsets_block = (
                f"\\n// Auto-detected {label} pointer-chain offsets from the dump.\\n"
                "// Verify these against snapshot/Offsets/Fields.csv if ESP is wrong.\\n"
                "namespace offsets {{\\n"
                + "\\n".join(lines)
                + "\\n}}  // namespace offsets\\n"
            )

    return f"""#pragma once
#include <array>
#include <cstddef>
#include <cstdint>

namespace trainer::template_data {{

// Engine type: 0=UE4, 1=UE5, 2=Unity/IL2CPP, 3=Unknown
enum class EngineType {{ UE4 = 0, UE5 = 1, Unity = 2, Unknown = 3 }};

struct FeatureCard {{
    const char* label;
    const char* group;
    const char* class_name;
    const char* full_name;
    const char* field_name;
    const char* field_type;
    int offset;
    const char* offset_hex;
    int size;
    const char* control;
    const char* notes;
}};

struct PackageCard {{
    const char* name;
    int line_count;
}};

inline constexpr const char* kGameName = "{_cpp_string(game_name)}";
inline constexpr const char* kEngine = "{_cpp_string(engine_line)}";
inline constexpr const char* kVersion = "{_cpp_string(version_line)}";
inline constexpr const char* kDumpTimestamp = "{_cpp_string(dump_stamp)}";
inline constexpr const char* kProcessName = "{_cpp_string(meta.get("process", ""))}";
inline constexpr EngineType kEngineType = EngineType::{engine_type.upper() if engine_type in ("ue4", "ue5") else ("Unity" if engine_type == "unity" else "Unknown")};
inline constexpr const wchar_t* kWindowClass = L"{_cpp_string(window_class)}";

{offsets_block}

inline constexpr std::array<FeatureCard, {max(1, len(feature_rows))}> kFeatures = {{{{
{feature_body}
}}}};

inline constexpr std::array<PackageCard, {max(1, len(package_rows))}> kPackages = {{{{
{package_body}
}}}};

}}  // namespace trainer::template_data
"""

_TPL_CMAKELISTS = """cmake_minimum_required(VERSION 3.20)
project(trainer_workbench LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(IMGUI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/imgui")

add_executable(trainer_workbench
    src/main.cpp
    src/trainer_ui.cpp
    src/driver.cpp
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_dx11.cpp
    ${IMGUI_DIR}/backends/imgui_impl_win32.cpp
)

target_include_directories(trainer_workbench PRIVATE
    src
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
)

target_compile_definitions(trainer_workbench PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_link_libraries(trainer_workbench PRIVATE d3d11 dxgi d3dcompiler)
"""

_TPL_VENDOR_README = """Drop Dear ImGui into `third_party/imgui` before building this mock project.

Suggested layout:
third_party/
  imgui/
    imgui.h
    imgui.cpp
    imgui_draw.cpp
    imgui_tables.cpp
    imgui_widgets.cpp
    backends/
      imgui_impl_dx11.cpp
      imgui_impl_dx11.h
      imgui_impl_win32.cpp
      imgui_impl_win32.h

The generated code expects the official Win32 + DirectX11 backend files.
"""

_TPL_DRIVER_H = """#pragma once
// driver.h - Usermode IPC client for the kernel driver (wdfsvc64.sys).
//
// Load via gsd_mapper (requires driver mapper).
//
// Usage:
//   1. Load wdfsvc64.sys via gsd_mapper.
//   2. Call driver::Init() to map the shared IPC section.
//   3. Use Read<T> / Write<T> for typed memory access.

#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstring>

namespace trainer { namespace driver {

// ── Protocol constants (must match driver/comm.h) ──────────

constexpr DWORD  COMMAND_MAGIC        = 0xD3C2B1A0; // Non-ASCII (stealth)
constexpr DWORD  COMMAND_READ         = 1;
constexpr DWORD  COMMAND_WRITE        = 2;
constexpr DWORD  COMMAND_GETBASE      = 3;
constexpr DWORD  COMMAND_FINDCR3      = 4;
constexpr DWORD  COMMAND_SCATTER_READ = 5;
constexpr DWORD  COMMAND_HEALTH_CHECK = 6;

constexpr DWORD  CMD_STATUS_WAITING   = 0;
constexpr DWORD  CMD_STATUS_COMPLETE  = 1;
constexpr DWORD  CMD_STATUS_ERROR     = 2;

constexpr DWORD  COMM_PAGE_SIZE   = 65536;
constexpr DWORD  COMM_HEADER_SIZE = 48;
constexpr DWORD  COMM_DATA_MAX    = COMM_PAGE_SIZE - COMM_HEADER_SIZE;

// ── Shared memory structs ──────────────────────────────────

#pragma pack(push, 8)
struct MemoryCommand {
    DWORD     MagicCode;      // 0x00
    DWORD     Instruction;    // 0x04
    DWORD     ProcessId;      // 0x08
    DWORD     _Pad0;          // 0x0C
    ULONGLONG TargetAddress;  // 0x10
    ULONGLONG BufferAddress;  // 0x18
    SIZE_T    Size;           // 0x20
    DWORD     Status;         // 0x28
    DWORD     _Pad1;          // 0x2C
};  // Total: 48 bytes
#pragma pack(pop)

#pragma pack(push, 1)
struct ScatterEntry {
    ULONGLONG Address;
    DWORD     Size;
};  // 12 bytes
#pragma pack(pop)

// ── Driver client API ────────────────────────────

bool       Init();
void       Shutdown();
bool       IsConnected();
bool       HealthCheck();
bool       ReadMemory(DWORD pid, ULONGLONG address, void* buffer, SIZE_T size);
bool       WriteMemory(DWORD pid, ULONGLONG address, const void* data, SIZE_T size);
ULONGLONG  GetModuleBase(DWORD pid);
DWORD      FindProcessByName(const wchar_t* name);

// Batch-read multiple addresses in a single driver call.
bool       ScatterRead(DWORD pid, const ScatterEntry* entries, int count,
                       void* out_buf, SIZE_T out_size);

template<typename T>
T Read(DWORD pid, ULONGLONG address) {
    T val{};
    ReadMemory(pid, address, &val, sizeof(T));
    return val;
}

template<typename T>
bool Write(DWORD pid, ULONGLONG address, const T& val) {
    return WriteMemory(pid, address, &val, sizeof(T));
}

}}  // namespace driver
"""

_TPL_DRIVER_CPP = """#include "driver.h"

namespace trainer::driver {

static const wchar_t* SECTION_PREFIX = L"Global\\\\{wdf-";
static const wchar_t* SECTION_LEGACY =
    L"Global\\\\{a8f5c2b1-d3e7-49a6-8c01-7f2b3e4d5a6c}";

static const wchar_t* DiscoverSectionName() {
    return SECTION_LEGACY;
}

static HANDLE g_mapping = nullptr;
static void*  g_view    = nullptr;

static void* DataArea() {
    return g_view ? static_cast<char*>(g_view) + COMM_HEADER_SIZE : nullptr;
}

static bool SendCommand(DWORD pid, ULONGLONG address, SIZE_T size,
                         DWORD instruction, DWORD timeout_ms = 20) {
    if (!g_view) return false;
    auto* cmd = static_cast<MemoryCommand*>(g_view);
    cmd->Instruction   = instruction;
    cmd->ProcessId     = pid;
    cmd->_Pad0         = 0;
    cmd->TargetAddress = address;
    cmd->BufferAddress = 0;
    cmd->Size          = size;
    cmd->Status        = CMD_STATUS_WAITING;
    cmd->_Pad1         = 0;
    MemoryBarrier();
    cmd->MagicCode = COMMAND_MAGIC;
    DWORD start = GetTickCount();
    while (cmd->Status == CMD_STATUS_WAITING) {
        if ((GetTickCount() - start) > timeout_ms) return false;
        YieldProcessor();
    }
    return cmd->Status == CMD_STATUS_COMPLETE;
}

// ── EFI placeholder (not implemented) ───────────────────────

static bool EnableEnvironmentPrivilege() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, L"SeSystemEnvironmentPrivilege", &luid)) {
        CloseHandle(hToken);
        return false;
    }
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr);
    CloseHandle(hToken);
    return ok && GetLastError() == ERROR_SUCCESS;
}

// EFI Bootkit trigger — maps the driver via the firmware hook.
// Returns an NTSTATUS code (0 for success, >0 for errors like STATUS_NOT_IMPLEMENTED)
DWORD TriggerEfiMap() {
    // 1. Acquire firmware variable privilege
    if (!EnableEnvironmentPrivilege()) return 0xC0000061; // STATUS_PRIVILEGE_NOT_HELD

    // 2. Resolve NtSetSystemEnvironmentValueEx from ntdll
    using FnNtSetSysEnvValEx = LONG (NTAPI*)(
        const wchar_t*, const GUID*, void*, ULONG, ULONG);
    auto pNtSetSysEnvValEx = reinterpret_cast<FnNtSetSysEnvValEx>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                       "NtSetSystemEnvironmentValueEx"));
    if (!pNtSetSysEnvValEx) return 0xC0000002;

    // 3. Build the handshake request
    GUID magic_guid;
    std::memcpy(&magic_guid, EFI_MAGIC_GUID, sizeof(GUID));

    EfiMapRequest req{};
    req.Command    = EFI_CMD_MAP_DRIVER;
    req.MappedBase = 0;
    req.Status     = 0;
    req.DriverSize = 0;

    // 4. Call the hooked SetVariable via NT API
    constexpr ULONG attrs = 0x7; // NV | BS_ACCESS | RT_ACCESS
    LONG status = pNtSetSysEnvValEx(
        EFI_MAGIC_VAR, &magic_guid, &req,
        static_cast<ULONG>(sizeof(req)), attrs);

    if (status != 0) return static_cast<DWORD>(status);
    if (req.Status != 0 || req.MappedBase == 0) return req.Status;
    
    return 0; // Success
}

// ── Standard IPC ────────────────────────────────────────────

bool Init() {
    if (g_view) return true;
    g_mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, DiscoverSectionName());
    if (!g_mapping) return false;
    g_view = MapViewOfFile(g_mapping, FILE_MAP_ALL_ACCESS, 0, 0, COMM_PAGE_SIZE);
    if (!g_view) {
        CloseHandle(g_mapping);
        g_mapping = nullptr;
        return false;
    }
    return true;
}

void Shutdown() {
    if (g_view)    { UnmapViewOfFile(g_view); g_view = nullptr; }
    if (g_mapping) { CloseHandle(g_mapping);  g_mapping = nullptr; }
}

bool IsConnected() { return g_view != nullptr; }

bool HealthCheck() {
    return SendCommand(0, 0, 0, COMMAND_HEALTH_CHECK, 2000);
}

bool ReadMemory(DWORD pid, ULONGLONG address, void* buffer, SIZE_T size) {
    if (!buffer || size == 0 || size > COMM_DATA_MAX) return false;
    if (!SendCommand(pid, address, size, COMMAND_READ)) return false;
    std::memcpy(buffer, DataArea(), size);
    return true;
}

bool WriteMemory(DWORD pid, ULONGLONG address, const void* data, SIZE_T size) {
    if (!data || size == 0 || size > COMM_DATA_MAX) return false;
    std::memcpy(DataArea(), data, size);
    return SendCommand(pid, address, size, COMMAND_WRITE);
}

ULONGLONG GetModuleBase(DWORD pid) {
    if (!SendCommand(pid, 0, 0, COMMAND_GETBASE)) return 0;
    ULONGLONG base = 0;
    std::memcpy(&base, DataArea(), sizeof(base));
    return base;
}

DWORD FindProcessByName(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

bool ScatterRead(DWORD pid, const ScatterEntry* entries, int count,
                 void* out_buf, SIZE_T out_size) {
    if (!entries || count <= 0 || !out_buf || out_size == 0) return false;
    SIZE_T entries_size = static_cast<SIZE_T>(count) * sizeof(ScatterEntry);
    if (entries_size > COMM_DATA_MAX) return false;
    std::memcpy(DataArea(), entries, entries_size);
    if (!SendCommand(pid, static_cast<ULONGLONG>(count), entries_size,
                     COMMAND_SCATTER_READ)) {
        char* dst = static_cast<char*>(out_buf);
        SIZE_T offset = 0;
        for (int i = 0; i < count && offset + entries[i].Size <= out_size; ++i) {
            if (!ReadMemory(pid, entries[i].Address, dst + offset, entries[i].Size))
                std::memset(dst + offset, 0, entries[i].Size);
            offset += entries[i].Size;
        }
        return true;
    }
    SIZE_T copy_size = (out_size < COMM_DATA_MAX) ? out_size : COMM_DATA_MAX;
    std::memcpy(out_buf, DataArea(), copy_size);
    return true;
}

}  // namespace driver
"""

_TPL_LAUNCH_BAT = """@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Trainer Launcher
cd /d "%~dp0"

echo ============================================
echo   Trainer Launcher
echo ============================================
echo.
echo Prerequisites:
echo   - Run this as Administrator
echo.
echo Starting cheat_client.exe ...
cheat_client.exe
pause
"""

_TPL_BUILD_BAT = """@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Trainer Template Build
cd /d "%~dp0"

echo.
echo   +------------------------------------------+
echo   ^|         Trainer Template Builder         ^|
echo   +------------------------------------------+
echo.

:: ── Check for CMake ──────────────────────────────────
:: ── Check for CMake ──────────────────────────────────
set "CMAKE_EXE="
where cmake >nul 2>nul
if not errorlevel 1 (
    set "CMAKE_EXE=cmake"
    goto :found_cmake
)

echo   [INFO]  CMake not on PATH. Looking for Visual Studio...

for %%p in (
    "%ProgramFiles%\\Microsoft Visual Studio\\2022\\Community\\Common7\\IDE\\CommonExtensions\\Microsoft\\CMake\\CMake\\bin\\cmake.exe"
    "%ProgramFiles%\\Microsoft Visual Studio\\2022\\Professional\\Common7\\IDE\\CommonExtensions\\Microsoft\\CMake\\CMake\\bin\\cmake.exe"
    "%ProgramFiles%\\Microsoft Visual Studio\\2022\\Enterprise\\Common7\\IDE\\CommonExtensions\\Microsoft\\CMake\\CMake\\bin\\cmake.exe"
    "%ProgramFiles%\\Microsoft Visual Studio\\2022\\BuildTools\\Common7\\IDE\\CommonExtensions\\Microsoft\\CMake\\CMake\\bin\\cmake.exe"
    "%ProgramFiles(x86)%\\Microsoft Visual Studio\\2019\\Community\\Common7\\IDE\\CommonExtensions\\Microsoft\\CMake\\CMake\\bin\\cmake.exe"
    "%ProgramFiles(x86)%\\Microsoft Visual Studio\\2019\\Professional\\Common7\\IDE\\CommonExtensions\\Microsoft\\CMake\\CMake\\bin\\cmake.exe"
    "%ProgramFiles(x86)%\\Microsoft Visual Studio\\2019\\Enterprise\\Common7\\IDE\\CommonExtensions\\Microsoft\\CMake\\CMake\\bin\\cmake.exe"
    "%ProgramFiles(x86)%\\Microsoft Visual Studio\\2019\\BuildTools\\Common7\\IDE\\CommonExtensions\\Microsoft\\CMake\\CMake\\bin\\cmake.exe"
) do (
    if exist "%%~p" (
        set "CMAKE_EXE=%%~p"
        goto :found_cmake
    )
)

echo   [FAIL]  CMake not found on PATH or via Visual Studio.
echo          Install CMake from https://cmake.org/download/
echo          or install Visual Studio with C++ desktop workload.
echo.
pause
exit /b 1

:found_cmake
for /f "usebackq delims=" %%v in (`"%CMAKE_EXE%" --version 2^>^&1 ^| findstr /i "version"`) do set "CMAKE_VER=%%v"
echo   [ OK ]  %CMAKE_VER%

:: ── Auto-clone ImGui if missing ──────────────────────
if not exist "third_party\\imgui\\imgui.h" (
    echo.
    echo   [AUTO]  Dear ImGui not found -- cloning...
    where git >nul 2>nul
    if errorlevel 1 (
        echo   [FAIL]  Git not found. Please install Git or manually place
        echo          Dear ImGui into third_party\\imgui\\
        echo.
        pause
        exit /b 1
    )
    git clone --depth 1 --branch v1.91.8 https://github.com/ocornut/imgui.git third_party\\imgui
    if errorlevel 1 (
        echo   [FAIL]  Failed to clone Dear ImGui.
        pause
        exit /b 1
    )
    echo   [ OK ]  Dear ImGui cloned successfully.
)
echo   [ OK ]  Dear ImGui found
echo.

:: ── Build kernel driver if MSBuild + WDK available ───
set "MSBUILD="
for %%p in (
    "%ProgramFiles%\\Microsoft Visual Studio\\2022\\Community\\MSBuild\\Current\\Bin\\MSBuild.exe"
    "%ProgramFiles%\\Microsoft Visual Studio\\2022\\Professional\\MSBuild\\Current\\Bin\\MSBuild.exe"
    "%ProgramFiles%\\Microsoft Visual Studio\\2022\\Enterprise\\MSBuild\\Current\\Bin\\MSBuild.exe"
    "%ProgramFiles%\\Microsoft Visual Studio\\2022\\BuildTools\\MSBuild\\Current\\Bin\\MSBuild.exe"
) do (
    if exist "%%~p" (
        set "MSBUILD=%%~p"
        goto :found_msbuild
    )
)
where MSBuild.exe >nul 2>nul
if not errorlevel 1 (
    for /f "delims=" %%i in ('where MSBuild.exe') do (
        set "MSBUILD=%%i"
        goto :found_msbuild
    )
)
echo   [SKIP]  MSBuild not found -- skipping driver build.
goto :skip_driver

:found_msbuild
echo   [ OK ]  MSBuild found
set "DRIVER_PROJ=%~dp0..\\..\\..\\driver\\driver.vcxproj"
if not exist "%DRIVER_PROJ%" (
    echo   [SKIP]  driver.vcxproj not found -- skipping driver build.
    goto :skip_driver
)
echo   Compiling kernel driver ^(Release x64^)...
"!MSBUILD!" "%DRIVER_PROJ%" /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo
if not exist "bin" mkdir "bin"
for %%f in ("%~dp0..\\..\\..\\bin\\wdfsvc64.sys") do (
    if exist "%%~f" (
        copy /Y "%%~f" "bin\\wdfsvc64.sys" >nul
        echo   [ OK ]  bin\\wdfsvc64.sys
    )
)
echo.

:skip_driver

:: ── Configure with CMake (generates .sln) ────────────
echo   Configuring with CMake...
"%CMAKE_EXE%" -S . -B build -G "Visual Studio 17 2022" -A x64
if errorlevel 1 (
    echo.
    echo   [NOTE]  VS 2022 generator failed, trying default...
    "%CMAKE_EXE%" -S . -B build
    if errorlevel 1 (
        echo   [FAIL]  CMake configure failed.
        pause
        exit /b 1
    )
)
echo   [ OK ]  CMake configured  ^(build\\ directory^)
echo.

:: ── Build Release ────────────────────────────────────
echo   Building Release...
"%CMAKE_EXE%" --build build --config Release
if errorlevel 1 (
    echo.
    echo   [FAIL]  Build failed. Check output above.
    pause
    exit /b 1
)
echo.

:: ── Copy output to project root (del+copy /B to update timestamp) ─
set "BUILT_EXE="
if exist "build\\Release\\cheat_client.exe" set "BUILT_EXE=build\\Release\\cheat_client.exe"
if not defined BUILT_EXE (
    for %%f in (build\\Release\\*.exe) do if not defined BUILT_EXE set "BUILT_EXE=%%f"
)
if not defined BUILT_EXE if exist "build\\cheat_client.exe" set "BUILT_EXE=build\\cheat_client.exe"
if not defined BUILT_EXE (
    for %%f in (build\\*.exe) do if not defined BUILT_EXE set "BUILT_EXE=%%f"
)
if not defined BUILT_EXE (
    echo   [FAIL]  Could not find built executable.
    pause
    exit /b 1
)
if exist "cheat_client.exe" del /F "cheat_client.exe"
copy /Y /B "!BUILT_EXE!" "cheat_client.exe" >nul
if errorlevel 1 (
    echo   [FAIL]  Could not copy cheat_client.exe. Is it still running?
    pause
    exit /b 1
)
echo   [ OK ]  cheat_client.exe

echo.
echo   +------------------------------------------+
echo   ^|  Build Summary                          ^|
echo   +------------------------------------------+
echo.
echo.
if exist "build\\*.sln" (
    for %%f in (build\\*.sln) do (
        echo   [ OK ]  Visual Studio solution: %%f
        echo.
        echo   To open in Visual Studio:
        echo     open %%f
    )
)
echo.
echo   To load the kernel driver:
echo     Run Launch.bat as Administrator
echo.
pause
"""

def _try_clone_imgui(vendor_dir: str) -> bool:
    imgui_dir = os.path.join(vendor_dir, "imgui")
    if os.path.isfile(os.path.join(imgui_dir, "imgui.h")):
        return True
    try:
        result = subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--branch",
                "v1.91.8",
                "https://github.com/ocornut/imgui.git",
                imgui_dir,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False

_TPL_TRAINER_UI_HPP = """#pragma once

#include <cstdint>

namespace trainer {

struct TrainerState {
    bool driver_connected = false;
    bool process_attached = false;
    unsigned long target_pid = 0;
    unsigned long long module_base = 0;
    char process_name[128] = "";
    char status[256] = "Driver not loaded";
};

void RenderTrainerWorkbench(TrainerState& state);

}  // namespace trainer
"""

_TPL_TRAINER_UI_CPP = """#include "trainer_ui.hpp"
#include "driver.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "imgui.h"
#include "generated_feature_catalog.hpp"

namespace {

ImVec4 AccentFromGroup(const char* group) {
    if (std::strcmp(group, "Vitals") == 0) return {0.38f, 0.73f, 0.96f, 1.0f};
    if (std::strcmp(group, "Weapons") == 0) return {0.96f, 0.56f, 0.40f, 1.0f};
    if (std::strcmp(group, "Movement") == 0) return {0.44f, 0.82f, 0.67f, 1.0f};
    if (std::strcmp(group, "Resources") == 0) return {0.93f, 0.77f, 0.33f, 1.0f};
    return {0.62f, 0.66f, 0.98f, 1.0f};
}

bool PassesSearch(const trainer::template_data::FeatureCard& card, const char* needle) {
    if (!needle || !needle[0]) return true;
    std::string haystack = std::string(card.label) + " " + card.class_name + " " + card.field_name;
    std::string lowered_haystack = haystack;
    std::string lowered_needle = needle;
    std::transform(lowered_haystack.begin(), lowered_haystack.end(), lowered_haystack.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::transform(lowered_needle.begin(), lowered_needle.end(), lowered_needle.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return lowered_haystack.find(lowered_needle) != std::string::npos;
}

const char* ControlLabel(const char* control) {
    if (std::strcmp(control, "toggle") == 0) return "Toggle";
    if (std::strcmp(control, "slider_int") == 0) return "Slider<int>";
    if (std::strcmp(control, "slider_float") == 0) return "Slider<float>";
    return "Read only";
}

void ApplyTheme() {
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 18.0f;
    style.ChildRounding = 16.0f;
    style.FrameRounding = 12.0f;
    style.PopupRounding = 12.0f;
    style.ScrollbarRounding = 999.0f;
    style.GrabRounding = 10.0f;
    style.WindowPadding = ImVec2(18.0f, 18.0f);
    style.FramePadding = ImVec2(12.0f, 8.0f);
    style.ItemSpacing = ImVec2(12.0f, 10.0f);
    style.ItemInnerSpacing = ImVec2(8.0f, 6.0f);
    style.Colors[ImGuiCol_WindowBg] = ImVec4(0.05f, 0.07f, 0.10f, 1.0f);
    style.Colors[ImGuiCol_ChildBg] = ImVec4(0.08f, 0.10f, 0.14f, 1.0f);
    style.Colors[ImGuiCol_PopupBg] = ImVec4(0.10f, 0.12f, 0.16f, 0.98f);
    style.Colors[ImGuiCol_FrameBg] = ImVec4(0.11f, 0.14f, 0.19f, 1.0f);
    style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.14f, 0.18f, 0.24f, 1.0f);
    style.Colors[ImGuiCol_FrameBgActive] = ImVec4(0.16f, 0.20f, 0.27f, 1.0f);
    style.Colors[ImGuiCol_Button] = ImVec4(0.17f, 0.21f, 0.29f, 1.0f);
    style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.22f, 0.28f, 0.39f, 1.0f);
    style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.26f, 0.32f, 0.44f, 1.0f);
    style.Colors[ImGuiCol_Header] = ImVec4(0.16f, 0.20f, 0.28f, 1.0f);
    style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.22f, 0.28f, 0.39f, 1.0f);
    style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.26f, 0.32f, 0.44f, 1.0f);
    style.Colors[ImGuiCol_Border] = ImVec4(0.18f, 0.22f, 0.30f, 0.85f);
    style.Colors[ImGuiCol_Text] = ImVec4(0.93f, 0.95f, 0.98f, 1.0f);
    style.Colors[ImGuiCol_TextDisabled] = ImVec4(0.57f, 0.62f, 0.72f, 1.0f);
    style.Colors[ImGuiCol_ScrollbarBg] = ImVec4(0.06f, 0.08f, 0.11f, 1.0f);
    style.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.22f, 0.27f, 0.36f, 1.0f);
    style.Colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.30f, 0.36f, 0.47f, 1.0f);
}

// Per-feature live state
struct FeatureState {
    float value_f = 0.0f;
    int value_i = 0;
    bool value_b = false;
};

// Per-class instance tracking
struct ClassEntry {
    const char* name = nullptr;
    unsigned long long base = 0;
    char hex_input[18] = "";
};

}  // namespace

namespace trainer {

void RenderTrainerWorkbench(TrainerState& state) {
    ApplyTheme();

    static char search[96] = "";
    static int pinned_index = 0;
    static bool show_metrics = true;
    static FeatureState feat_state[64] = {};
    static ClassEntry classes[32] = {};
    static int num_classes = 0;
    static bool init_done = false;

    // One-time: collect unique class names from the feature catalog
    if (!init_done) {
        for (const auto& feat : trainer::template_data::kFeatures) {
            bool found = false;
            for (int j = 0; j < num_classes; ++j) {
                if (std::strcmp(classes[j].name, feat.class_name) == 0) { found = true; break; }
            }
            if (!found && num_classes < 32) {
                classes[num_classes].name = feat.class_name;
                ++num_classes;
            }
        }
        init_done = true;
    }

    ImGui::SetNextWindowSize(ImVec2(1320, 820), ImGuiCond_FirstUseEver);
    ImGui::Begin("Trainer Workbench", nullptr, ImGuiWindowFlags_NoCollapse);

    ImGui::TextUnformatted(trainer::template_data::kGameName);
    ImGui::SameLine();
    ImGui::TextDisabled("| %s | %s", trainer::template_data::kEngine, trainer::template_data::kVersion);
    ImGui::Spacing();

    // ── Connection Panel ──────────────────────────────────
    if (ImGui::BeginChild("connection", ImVec2(0, 110), true)) {
        ImGui::Columns(3, nullptr, false);

        // ── Column 1: Driver Connect ──────────────────────
        if (state.driver_connected) {
            ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.5f, 1.0f), "Driver: Connected");
        } else {
            ImGui::TextColored(ImVec4(0.9f, 0.7f, 0.3f, 1.0f), "Driver: Disconnected");
            if (ImGui::Button("Connect Driver")) {
                if (driver::Init()) {
                    state.driver_connected = true;
                    driver::HealthCheck();
                    std::strncpy(state.status, "Driver connected.", sizeof(state.status) - 1);
                } else {
                    std::strncpy(state.status, "Driver not found. Load wdfsvc64.sys via gsd_mapper.", sizeof(state.status) - 1);
                }
            }
            ImGui::TextDisabled("Load wdfsvc64.sys first");
        }

        ImGui::NextColumn();
        ImGui::InputText("Process", state.process_name, sizeof(state.process_name));
        if (!state.process_attached) {
            if (state.driver_connected && ImGui::SmallButton("Attach")) {
                wchar_t wname[128] = {};
                MultiByteToWideChar(CP_UTF8, 0, state.process_name, -1, wname, 128);
                DWORD pid = driver::FindProcessByName(wname);
                if (pid) {
                    state.target_pid = pid;
                    state.module_base = driver::GetModuleBase(pid);
                    state.process_attached = true;
                    std::snprintf(state.status, sizeof(state.status),
                                  "Attached PID %lu | Base 0x%llX", pid, state.module_base);
                } else {
                    std::snprintf(state.status, sizeof(state.status),
                                  "'%s' not found", state.process_name);
                }
            }
        } else {
            ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.5f, 1.0f), "PID: %lu", state.target_pid);
            ImGui::SameLine();
            if (ImGui::SmallButton("Detach")) {
                state.process_attached = false;
                state.target_pid = 0;
                state.module_base = 0;
                std::strncpy(state.status, "Detached", sizeof(state.status) - 1);
            }
        }
        ImGui::NextColumn();
        if (state.module_base) ImGui::Text("Base: 0x%llX", state.module_base);
        ImGui::TextDisabled("%s", state.status);
        ImGui::Columns(1);
    }
    ImGui::EndChild();
    ImGui::Spacing();

    ImGui::InputTextWithHint("##search", "Search fields, classes, or labels", search, sizeof(search));
    ImGui::Spacing();

    // ── Periodic memory reads (10 Hz) ─────────────────────
    static DWORD last_read_tick = 0;
    DWORD tick_now = GetTickCount();
    bool should_read = state.process_attached && state.driver_connected
                       && (tick_now - last_read_tick) >= 100;
    if (should_read) {
        last_read_tick = tick_now;
        for (std::size_t fi = 0; fi < trainer::template_data::kFeatures.size() && fi < 64; ++fi) {
            const auto& fc = trainer::template_data::kFeatures[fi];
            unsigned long long cb = 0;
            for (int ci = 0; ci < num_classes; ++ci) {
                if (std::strcmp(classes[ci].name, fc.class_name) == 0) { cb = classes[ci].base; break; }
            }
            if (!cb) continue;
            unsigned long long ra = cb + fc.offset;
            auto& fs = feat_state[fi];
            if (std::strcmp(fc.control, "toggle") == 0)
                fs.value_b = driver::Read<bool>(state.target_pid, ra);
            else if (std::strcmp(fc.control, "slider_int") == 0)
                fs.value_i = driver::Read<int>(state.target_pid, ra);
            else if (std::strcmp(fc.control, "slider_float") == 0)
                fs.value_f = driver::Read<float>(state.target_pid, ra);
        }
    }

    ImGui::BeginChild("feature_lane", ImVec2(ImGui::GetContentRegionAvail().x * 0.65f, 0), true);
    ImGui::TextUnformatted("Feature Workbench");
    ImGui::Separator();

    for (std::size_t i = 0; i < trainer::template_data::kFeatures.size(); ++i) {
        const auto& card = trainer::template_data::kFeatures[i];
        if (!PassesSearch(card, search)) {
            continue;
        }
        ImVec4 accent = AccentFromGroup(card.group);
        ImGui::PushStyleColor(ImGuiCol_Border, accent);
        ImGui::BeginChild(static_cast<int>(i + 10), ImVec2(0, 128), true);
        ImGui::TextColored(accent, "%s", card.group);
        ImGui::SameLine();
        ImGui::TextDisabled("| %s", ControlLabel(card.control));
        ImGui::Text("%s", card.label);
        ImGui::TextDisabled("%s :: %s  @ %s", card.class_name, card.field_name, card.offset_hex);
        // ── Live memory I/O ──────────────────────────────
        unsigned long long cls_base = 0;
        for (int ci = 0; ci < num_classes; ++ci) {
            if (std::strcmp(classes[ci].name, card.class_name) == 0) { cls_base = classes[ci].base; break; }
        }
        auto& fs = feat_state[i];
        bool live = state.process_attached && state.driver_connected && cls_base != 0;
        unsigned long long addr = cls_base + card.offset;

        if (live) {
            if (std::strcmp(card.control, "toggle") == 0) {
                if (ImGui::Checkbox(("##t" + std::to_string(i)).c_str(), &fs.value_b)) {
                    driver::Write<bool>(state.target_pid, addr, fs.value_b);
                }
            } else if (std::strcmp(card.control, "slider_int") == 0) {
                if (ImGui::SliderInt(("##si" + std::to_string(i)).c_str(), &fs.value_i, 0, 999999)) {
                    driver::Write<int>(state.target_pid, addr, fs.value_i);
                }
            } else if (std::strcmp(card.control, "slider_float") == 0) {
                if (ImGui::SliderFloat(("##sf" + std::to_string(i)).c_str(), &fs.value_f, 0.0f, 100000.0f, "%.2f")) {
                    driver::Write<float>(state.target_pid, addr, fs.value_f);
                }
            } else {
                ImGui::TextDisabled("Read-only @ 0x%llX", addr);
            }
        } else {
            ImGui::TextDisabled(cls_base ? "Attach to process first" : "Set class address in right panel");
        }
        ImGui::EndChild();
        ImGui::PopStyleColor();
        ImGui::Spacing();
    }
    ImGui::EndChild();

    ImGui::SameLine();
    ImGui::BeginChild("right_rail", ImVec2(0, 0), true);

    // Class instance addresses
    ImGui::TextUnformatted("Class Instances");
    ImGui::Separator();
    ImGui::TextWrapped("Enter the base address of each class instance (hex). Find these with a pointer scanner or ReClass.");
    ImGui::Spacing();
    for (int ci = 0; ci < num_classes; ++ci) {
        ImGui::PushID(ci + 2000);
        ImGui::Text("%s", classes[ci].name);
        ImGui::SameLine(ImGui::GetContentRegionAvail().x * 0.45f);
        if (ImGui::InputText("##ca", classes[ci].hex_input, sizeof(classes[ci].hex_input),
                             ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue)) {
            classes[ci].base = std::strtoull(classes[ci].hex_input, nullptr, 16);
        }
        ImGui::PopID();
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::TextUnformatted("SDK Snapshot");
    ImGui::Separator();
    for (const auto& package : trainer::template_data::kPackages) {
        ImGui::BulletText("%s  (%d lines)", package.name, package.line_count);
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Checkbox("Show diagnostics", &show_metrics);
    if (show_metrics) {
        ImGui::TextDisabled("Frame: %.1f FPS", ImGui::GetIO().Framerate);
        ImGui::TextDisabled("Features: %d | Classes: %d",
            static_cast<int>(trainer::template_data::kFeatures.size()), num_classes);
    }
    ImGui::EndChild();

    ImGui::End();
}

}  // namespace trainer
"""

_TPL_MAIN_CPP = """#include <windows.h>
#include <d3d11.h>

#include "imgui.h"
#include "backends/imgui_impl_dx11.h"
#include "backends/imgui_impl_win32.h"

#include "trainer_ui.hpp"
#include "driver.h"
#include "generated_feature_catalog.hpp"

#pragma comment(lib, "d3d11.lib")

static ID3D11Device* g_device = nullptr;
static ID3D11DeviceContext* g_context = nullptr;
static IDXGISwapChain* g_swap_chain = nullptr;
static ID3D11RenderTargetView* g_main_rtv = nullptr;

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

static void CreateRenderTarget() {
    ID3D11Texture2D* back_buffer = nullptr;
    if (SUCCEEDED(g_swap_chain->GetBuffer(0, IID_PPV_ARGS(&back_buffer)))) {
        g_device->CreateRenderTargetView(back_buffer, nullptr, &g_main_rtv);
        back_buffer->Release();
    }
}

static void CleanupRenderTarget() {
    if (g_main_rtv) {
        g_main_rtv->Release();
        g_main_rtv = nullptr;
    }
}

static bool CreateDeviceD3D(HWND hwnd) {
    DXGI_SWAP_CHAIN_DESC desc = {};
    desc.BufferCount = 2;
    desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    desc.OutputWindow = hwnd;
    desc.SampleDesc.Count = 1;
    desc.Windowed = TRUE;
    desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    const D3D_FEATURE_LEVEL feature_levels[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
    D3D_FEATURE_LEVEL feature_level_out = D3D_FEATURE_LEVEL_11_0;

    HRESULT hr = D3D11CreateDeviceAndSwapChain(
        nullptr,
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        0,
        feature_levels,
        2,
        D3D11_SDK_VERSION,
        &desc,
        &g_swap_chain,
        &g_device,
        &feature_level_out,
        &g_context
    );
    if (FAILED(hr)) {
        return false;
    }
    CreateRenderTarget();
    return true;
}

static void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_swap_chain) {
        g_swap_chain->Release();
        g_swap_chain = nullptr;
    }
    if (g_context) {
        g_context->Release();
        g_context = nullptr;
    }
    if (g_device) {
        g_device->Release();
        g_device = nullptr;
    }
}

static LRESULT WINAPI WindowProc(HWND hwnd, UINT msg, WPARAM w_param, LPARAM l_param) {
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, w_param, l_param)) {
        return 1;
    }

    switch (msg) {
    case WM_SIZE:
        if (g_device != nullptr && w_param != SIZE_MINIMIZED) {
            CleanupRenderTarget();
            g_swap_chain->ResizeBuffers(0, static_cast<UINT>(LOWORD(l_param)), static_cast<UINT>(HIWORD(l_param)), DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((w_param & 0xfff0) == SC_KEYMENU) {
            return 0;
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProc(hwnd, msg, w_param, l_param);
}

int WINAPI WinMain(HINSTANCE instance, HINSTANCE, LPSTR, int show_cmd) {
    WNDCLASSEXW wc = {
        sizeof(wc),
        CS_CLASSDC,
        WindowProc,
        0L,
        0L,
        instance,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        L"TrainerWorkbench",
        nullptr
    };
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowW(
        wc.lpszClassName,
        L"Trainer Workbench",
        WS_OVERLAPPEDWINDOW,
        100,
        100,
        1440,
        900,
        nullptr,
        nullptr,
        wc.hInstance,
        nullptr
    );

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ShowWindow(hwnd, show_cmd);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_device, g_context);

    trainer::TrainerState trainer_state{};
    std::strncpy(trainer_state.process_name,
                 trainer::template_data::kProcessName,
                 sizeof(trainer_state.process_name) - 1);
    if (driver::Init()) {
        trainer_state.driver_connected = true;
        if (driver::HealthCheck()) {
            std::strncpy(trainer_state.status, "Driver connected (healthy)",
                         sizeof(trainer_state.status) - 1);
        } else {
            std::strncpy(trainer_state.status, "Driver connected",
                         sizeof(trainer_state.status) - 1);
        }
    }

    bool running = true;
    while (running) {
        MSG msg;
        while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT) {
                running = false;
            }
        }
        if (!running) {
            break;
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        trainer::RenderTrainerWorkbench(trainer_state);

        ImGui::Render();
        const float clear_color[4] = {0.05f, 0.07f, 0.10f, 1.0f};
        g_context->OMSetRenderTargets(1, &g_main_rtv, nullptr);
        g_context->ClearRenderTargetView(g_main_rtv, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_swap_chain->Present(1, 0);
    }

    driver::Shutdown();
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return 0;
}
"""

def _render_template_readme(
    game_name: str,
    meta: Dict[str, str],
    features: List[FeatureCandidate],
    *,
    sdk_snapshot_files: int = 0,
    offsets_snapshot_files: int = 0,
) -> str:
    engine = meta.get("engine") or "unknown"
    version = meta.get("unity_version") or meta.get("ue_version") or "unknown"
    dump_stamp = meta.get("dump_timestamp") or datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    lines = [
        f"# {game_name} Trainer Workbench",
        "",
        "Generated from the currently selected dump and SDK output.",
        "",
        "## Snapshot",
        "",
        f"- Engine: `{engine}`",
        f"- Version: `{version}`",
        f"- Dump timestamp: `{dump_stamp}`",
        f"- Recovered feature cards: `{len(features)}`",
        "",
        "## What This Template Gives You",
        "",
        "- **Kernel driver client** (`driver.h/.cpp`) — stealth IPC via shared memory.",
        "- **Driver binaries** (`bin/wdfsvc64.sys` + `bin/gsd_mapper.exe`) — ready to load.",
        "- **Connection panel** — attach to the game process by name, resolve module base automatically.",
        "- **Live memory read/write** — feature cards read values at 10 Hz and write back on slider change.",
        "- **Feature cards** seeded from the dump with offsets, types, and heuristic scoring.",
        "- **Class instance panel** — enter base addresses per class to enable live I/O.",
        "",
        "## Quick Start",
        "",
        "1. **Load the driver** (run as Administrator): `Launch.bat`",
        "2. Put Dear ImGui into `third_party/imgui` (Win32 + DirectX11 backend files).",
        "3. Build: `cmake -S . -B build && cmake --build build --config Release`",
        "4. Run the trainer — it will auto-connect to the driver and pre-fill the process name.",
        "5. Click **Attach** to find the game process and resolve the module base.",
        "6. Enter class instance addresses in the right panel (find with ReClass or pointer scanner).",
        "7. Feature cards go live — sliders read/write game memory through the kernel driver.",
        "",
        "## Bundled Snapshot",
        "",
        f"- `snapshot/Offsets` copied from the selected dump (`{offsets_snapshot_files}` files).",
        f"- `snapshot/SDK` copied from the selected SDK output (`{sdk_snapshot_files}` files).",
        "- Regenerate the template after a new dump so these snapshots stay in sync.",
        "",
        "## Driver Notes",
        "",
        "- The kernel driver uses physical memory translation (CR3 + MmCopyMemory) — no hooked APIs.",
        "- Shared memory IPC via GUID-named section — no IOCTLs, no device objects.",
        "- Requires: Secure Boot OFF, Core Isolation (HVCI) OFF, Administrator.",
        "",
    ]
    if features:
        lines.extend(["## Seeded Cards", ""])
        for feature in features[:10]:
            lines.append(
                f"- `{feature.group}` | `{feature.class_name}::{feature.field_name}` at `0x{feature.offset:X}` as `{feature.control}`"
            )
        lines.append("")
    return "\n".join(lines)

def _render_manifest(
    game_name: str,
    meta: Dict[str, str],
    features: List[FeatureCandidate],
    packages: List[Tuple[str, int]],
) -> Dict[str, object]:
    return {
        "project": {
            "name": game_name,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "engine": meta.get("engine", ""),
            "version": meta.get("unity_version") or meta.get("ue_version") or "",
            "dump_timestamp": meta.get("dump_timestamp", ""),
        },
        "features": [
            {
                "label": item.label,
                "group": item.group,
                "class_name": item.class_name,
                "full_name": item.full_name,
                "field_name": item.field_name,
                "field_type": item.field_type,
                "offset": item.offset,
                "size": item.size,
                "control": item.control,
                "notes": item.notes,
                "score": item.score,
            }
            for item in features
        ],
        "sdk_packages": [
            {"name": name, "line_count": line_count} for name, line_count in packages
        ],
    }

def _render_manifest_schema() -> Dict[str, object]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://example.local/schemas/trainer_manifest.schema.json",
        "title": "Trainer Manifest",
        "type": "object",
        "required": ["project", "features", "sdk_packages"],
        "properties": {
            "project": {
                "type": "object",
                "required": ["name", "generated_at"],
                "properties": {
                    "name": {"type": "string"},
                    "generated_at": {"type": "string"},
                    "engine": {"type": "string"},
                    "version": {"type": "string"},
                    "dump_timestamp": {"type": "string"},
                },
                "additionalProperties": False,
            },
            "features": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": [
                        "label",
                        "group",
                        "class_name",
                        "field_name",
                        "field_type",
                        "offset",
                        "size",
                        "control",
                        "score",
                    ],
                    "properties": {
                        "label": {"type": "string"},
                        "group": {"type": "string"},
                        "class_name": {"type": "string"},
                        "full_name": {"type": "string"},
                        "field_name": {"type": "string"},
                        "field_type": {"type": "string"},
                        "offset": {"type": "integer"},
                        "size": {"type": "integer"},
                        "control": {"type": "string"},
                        "notes": {"type": "string"},
                        "score": {"type": "integer"},
                    },
                    "additionalProperties": False,
                },
            },
            "sdk_packages": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["name", "line_count"],
                    "properties": {
                        "name": {"type": "string"},
                        "line_count": {"type": "integer"},
                    },
                    "additionalProperties": False,
                },
            },
        },
        "additionalProperties": False,
    }

_TPL_ADMIN_MATH_HPP = """#pragma once
// math.hpp - 3D math utilities for ESP projection.
// Generated by GameSDK-Kit — do not edit manually; regenerate from a fresh dump.

#include <cmath>
#include <cstdint>

namespace game {

struct Vec2 { float x = 0, y = 0; };
struct Vec3 { float x = 0, y = 0, z = 0; };

struct ViewMatrix {
    float m[4][4] = {};
};

inline bool WorldToScreen(const Vec3& world, Vec2& screen,
                           const ViewMatrix& vm, float screen_w, float screen_h) {
    float w = vm.m[0][3] * world.x + vm.m[1][3] * world.y + vm.m[2][3] * world.z + vm.m[3][3];
    if (w < 0.001f) return false;

    float x = vm.m[0][0] * world.x + vm.m[1][0] * world.y + vm.m[2][0] * world.z + vm.m[3][0];
    float y = vm.m[0][1] * world.x + vm.m[1][1] * world.y + vm.m[2][1] * world.z + vm.m[3][1];

    float inv_w = 1.0f / w;
    x *= inv_w;
    y *= inv_w;

    screen.x = (screen_w * 0.5f) + (x * screen_w * 0.5f);
    screen.y = (screen_h * 0.5f) - (y * screen_h * 0.5f);
    return true;
}

inline float Distance3D(const Vec3& a, const Vec3& b) {
    float dx = a.x - b.x, dy = a.y - b.y, dz = a.z - b.z;
    return std::sqrt(dx * dx + dy * dy + dz * dz);
}

}  // namespace game
"""

_TPL_ADMIN_OVERLAY_HPP = """#pragma once
// overlay.hpp - External transparent overlay window for ESP rendering.

#include <d3d11.h>
#include <dwmapi.h>
#include <windows.h>
#pragma comment(lib, "dwmapi.lib")

namespace overlay {

bool Create(HINSTANCE instance);
void Destroy();
bool BeginFrame();
void EndFrame();
HWND GetHwnd();
ID3D11Device *GetDevice();
ID3D11DeviceContext *GetContext();
float GetWidth();
float GetHeight();
float GetX();
float GetY();
bool IsVisible();
HWND GetGameHwnd();
bool IsGameActive();

// Call each frame to reposition overlay on top of the game window.
void TrackWindow(const wchar_t *window_class, const wchar_t *window_title,
                 bool menu_open = false);

// Toggles WS_EX_TRANSPARENT so the ImGui menu can actually be clicked.
void SetClickThrough(bool click_through);

}  // namespace overlay
"""

_TPL_ADMIN_ESP_HPP = """#pragma once
// esp.hpp - ESP rendering framework.

#include "math.hpp"
#include "driver.h"
#include "imgui.h"
#include <cstdint>

namespace esp {

enum class BoxStyle { Full, Corner, Rounded };

struct Config {
    bool        enabled            = true;
    bool        box_esp            = true;
    bool        name_esp           = true;
    bool        health_esp         = true;
    bool        guard_esp          = true;
    bool        distance_esp       = true;
    bool        line_esp           = false;
    bool        plus_ultra_esp     = false;
    bool        show_teammates     = false;
    bool        show_local_player  = false;
    bool        use_team_colors    = true;
    bool        glow_outline       = false;
    BoxStyle    box_style          = BoxStyle::Corner;
    ImVec4      box_color          = { 1.0f, 0.2f, 0.2f, 1.0f };
    ImVec4      enemy_color        = { 1.0f, 0.2f, 0.2f, 1.0f };
    ImVec4      teammate_color     = { 0.2f, 1.0f, 0.2f, 1.0f };
    ImVec4      name_color         = { 1.0f, 1.0f, 1.0f, 1.0f };
    float       max_distance       = 500.0f;
};

struct EntityData {
    Vec3         position     = {};
    float        health       = 100.0f;
    float        max_health   = 100.0f;
    float        guard        = 0.0f;
    float        max_guard    = 100.0f;
    float        plus_ultra   = 0.0f;
    char         name[64]     = "Player";
    bool         is_valid     = false;
    bool         is_local     = false;
    bool         is_teammate  = false;
    std::uint8_t team_id      = 0xFF;
    std::uint64_t actor       = 0;
};

void RenderESP(const Config& cfg, const EntityData* entities, int count,
               const ViewMatrix& vm, const Vec3& local_pos,
               float screen_w, float screen_h,
               float offset_x = 0.0f, float offset_y = 0.0f);

void DrawBox(const Vec2& top_left, const Vec2& bot_right,
             ImU32 color, BoxStyle style, float thickness = 1.5f);

}  // namespace esp
"""

_TPL_ADMIN_MENU_HPP = """#pragma once
// menu.hpp - Organized tabbed ImGui menu for Admin-Mode.

#include "esp.hpp"

namespace menu {

enum class AimbotActivationMode { Hold = 0, Toggle = 1 };

struct MenuState {
    bool                visible       = true;
    esp::Config   esp_config    = {};

    // Combat
    bool   aimbot_enabled         = false;
    float  aimbot_fov             = 5.0f;
    float  aimbot_smooth          = 3.0f;
    AimbotActivationMode aimbot_activation_mode = AimbotActivationMode::Hold;
    int    aimbot_key             = 0x02;  // VK_RBUTTON
    bool   aimbot_active          = false;
    bool   aimbot_toggled_on      = false;
    bool   aimbot_was_down        = false;

    // Misc
    bool   show_fps          = true;
    bool   show_watermark    = true;
    bool   show_debug_panel  = true;

    // Internal
    char   config_path[256]  = "config.json";
};

void Render(MenuState& state, bool driver_connected, unsigned long target_pid,
            unsigned long long module_base);
void Toggle(MenuState& state);
void SaveConfig(const MenuState& state, const char* path);
void LoadConfig(MenuState& state, const char* path);

}  // namespace menu
"""

_TPL_ADMIN_ENTITY_CACHE_HPP = """#pragma once
// entity_cache.hpp - Thread-safe double-buffered entity snapshot.
// The reader thread writes to the back buffer; the render thread reads the front.

#include "esp.hpp"
#include "math.hpp"
#include <atomic>
#include <cstring>
#include <mutex>

namespace game {

struct LocalTelemetry {
    float health = 0, max_health = 100, guard = 0, max_guard = 100, plus_ultra = 0;
};

struct CameraDiag {
    Vec3 location{}, rotation{};
    float fov = 90.0f;
    int source = 0;  // 0=none, 1=CameraCache, 2=CachePrv, 3=CtrlRot
};

struct ChainDiag {
    std::uint64_t world = 0, game_instance = 0, local_players_data = 0;
    std::uint64_t local_player = 0, player_controller = 0;
    std::uint64_t local_pawn = 0, camera_manager = 0;
    int fail_step = -1;
};

struct ReaderDiag {
    int tracked_count = 0, raw_actor_count = 0;
    int position_reads_ok = 0, position_reads_failed = 0;
    int context_fail_streak = 0, context_fail_total = 0, last_context_fail_step = 0;
    bool used_cached_context = false, scatter_positions = false;
    DWORD actor_refresh_age_ms = 0, cycle_time_ms = 0;
    DWORD read_calls = 0, read_fails = 0;
};

struct AimbotResult {
    std::uint64_t controller = 0;
    bool has_controller = false, ran = false, read_rotation_ok = false, write_ok = false;
    int scanned = 0, candidates = 0;
    float best_fov = 999.0f;
    Vec3 current_rot{}, target_rot{};
    const char* reason = "idle";
};

struct EntitySnapshot {
    static constexpr int kMaxEntities = 128;
    esp::EntityData entities[kMaxEntities] = {};
    int entity_count = 0;
    ViewMatrix view_matrix{};
    Vec3 local_position{};
    LocalTelemetry local_stats{};
    std::uint8_t local_team_id = 0xFF;
    CameraDiag camera_diag{};
    ChainDiag chain_diag{};
    ReaderDiag reader_diag{};
    AimbotResult aimbot_result{};
    float read_hz = 0.0f;
};

class EntityCache {
public:
    EntitySnapshot& GetBackBuffer() { return buffers_[1 - front_.load(std::memory_order_acquire)]; }
    void CommitBackBuffer() {
        std::lock_guard<std::mutex> lock(mutex_);
        front_.store(1 - front_.load(std::memory_order_relaxed), std::memory_order_release);
    }
    void ReadSnapshot(EntitySnapshot& out) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::memcpy(&out, &buffers_[front_.load(std::memory_order_relaxed)], sizeof(EntitySnapshot));
    }
private:
    EntitySnapshot buffers_[2]{};
    std::atomic<int> front_{0};
    std::mutex mutex_;
};

}  // namespace game
"""

_TPL_ADMIN_READER_THREAD_HPP = """#pragma once
// reader_thread.hpp - Background thread that reads game memory via the kernel
// driver and writes results into an EntityCache.

#include "entity_cache.hpp"
#include "driver.h"
#include "generated_feature_catalog.hpp"
#include "menu.hpp"
#include <atomic>
#include <cstdint>
#include <mutex>
#include <thread>

namespace game {

class ReaderThread {
public:
    void Start(EntityCache* cache, DWORD pid, ULONGLONG base);
    void Stop();
    bool IsRunning() const { return running_.load(std::memory_order_acquire); }
    void SetTarget(DWORD pid, ULONGLONG base);
    void SetMenuOpen(bool open);
    void SetAimbotConfig(const menu::MenuState& ms, float screen_w, float screen_h);

    struct AimbotConfig {
        bool enabled = false, active = false;
        float fov = 5.0f, smooth = 3.0f;
        float screen_w = 1920.0f, screen_h = 1080.0f;
    };

private:
    void ThreadFunc();
    EntityCache* cache_ = nullptr;
    std::thread thread_;
    std::atomic<bool> running_{false}, stop_requested_{false}, menu_open_{false};
    std::atomic<DWORD> pid_{0};
    std::atomic<ULONGLONG> base_{0};
    std::mutex aim_cfg_mutex_;
    AimbotConfig aim_cfg_;
    unsigned long long locked_target_ = 0;
};

}  // namespace game
"""

_TPL_ADMIN_READER_THREAD_CPP = """#include "reader_thread.hpp"
#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <mutex>
#include <vector>

namespace game {

static constexpr float kPi = 3.14159265358979323846f;
static std::uint64_t g_read_calls_total = 0, g_read_fail_total = 0;

static bool ReadRaw(DWORD pid, std::uint64_t addr, void* out, SIZE_T size) {
    ++g_read_calls_total;
    bool ok = driver::ReadMemory(pid, addr, out, size);
    if (!ok) ++g_read_fail_total;
    return ok;
}

static bool ScatterRaw(DWORD pid, const driver::ScatterEntry* e, int c, void* o, SIZE_T s) {
    ++g_read_calls_total;
    bool ok = driver::ScatterRead(pid, e, c, o, s);
    if (!ok) ++g_read_fail_total;
    return ok;
}

static bool IsProbablyPointer(std::uint64_t p) {
    return p >= 0x10000ULL && p <= 0x00007FFFFFFFFFFFULL;
}

static float NormalizeAngle(float a) {
    while (a > 180.0f) a -= 360.0f;
    while (a < -180.0f) a += 360.0f;
    return a;
}

static float ClampPitch(float p) { return (p > 89.0f) ? 89.0f : (p < -89.0f) ? -89.0f : p; }

static Vec3 CalculateAimRotation(const Vec3& from, const Vec3& to) {
    Vec3 d{to.x - from.x, to.y - from.y, to.z - from.z};
    float hyp = std::sqrt(d.x * d.x + d.y * d.y);
    Vec3 out{};
    out.x = ClampPitch(-std::atan2(d.z, hyp) * 180.0f / kPi);
    out.y = NormalizeAngle(std::atan2(d.y, d.x) * 180.0f / kPi);
    return out;
}

template<typename T> static bool ReadVal(DWORD pid, std::uint64_t addr, T* out) {
    return out && ReadRaw(pid, addr, out, sizeof(T));
}

static bool ReadVec3(DWORD pid, std::uint64_t addr, Vec3* out) {
    if (!ReadVal(pid, addr, out)) return false;
    return std::isfinite(out->x) && std::isfinite(out->y) && std::isfinite(out->z);
}

// ── Local context resolution ────────────────────────────────
struct LocalContext {
    std::uint64_t world = 0, game_instance = 0, local_player = 0;
    std::uint64_t player_controller = 0, local_pawn = 0, camera_manager = 0;
    std::uint8_t team_id = 0xFF;
};

// ── UE4/UE5 context resolution ─────────────────────────────
static bool ResolveLocalContext_UE(DWORD pid, ULONGLONG base, LocalContext* ctx, ChainDiag* diag) {
    namespace off = template_data::offsets;
    *ctx = {};
    ChainDiag cd{};
    ReadVal(pid, base + off::kGWorld, &ctx->world); cd.world = ctx->world;
    if (!IsProbablyPointer(ctx->world)) { cd.fail_step = 1; if (diag) *diag = cd; return false; }
    ReadVal(pid, ctx->world + off::kWorldOwningGameInstance, &ctx->game_instance); cd.game_instance = ctx->game_instance;
    if (!IsProbablyPointer(ctx->game_instance)) { cd.fail_step = 2; if (diag) *diag = cd; return false; }
    std::uint64_t lp_data = 0;
    ReadVal(pid, ctx->game_instance + off::kGameInstanceLocalPlayers, &lp_data); cd.local_players_data = lp_data;
    if (!IsProbablyPointer(lp_data)) { cd.fail_step = 3; if (diag) *diag = cd; return false; }
    ReadVal(pid, lp_data, &ctx->local_player); cd.local_player = ctx->local_player;
    if (!IsProbablyPointer(ctx->local_player)) { cd.fail_step = 4; if (diag) *diag = cd; return false; }
    ReadVal(pid, ctx->local_player + off::kPlayerPlayerController, &ctx->player_controller); cd.player_controller = ctx->player_controller;
    if (!IsProbablyPointer(ctx->player_controller)) { cd.fail_step = 5; if (diag) *diag = cd; return false; }
    ReadVal(pid, ctx->player_controller + off::kPlayerControllerAcknowledgedPawn, &ctx->local_pawn); cd.local_pawn = ctx->local_pawn;
    ReadVal(pid, ctx->player_controller + off::kPlayerControllerCameraManager, &ctx->camera_manager); cd.camera_manager = ctx->camera_manager;
    cd.fail_step = 0;
    if (diag) *diag = cd;
    return true;
}

// ── Unity/IL2CPP context resolution (stub) ─────────────────
// Unity games don't have a universal GWorld chain.  Override this
// function with your game's specific manager class hierarchy.
// The template provides the scaffolding; fill in the pointer chain
// from your dump's SDK output (Il2CppDumper / GameObjectManager).
static bool ResolveLocalContext_Unity(DWORD pid, ULONGLONG base, LocalContext* ctx, ChainDiag* diag) {
    (void)base;
    *ctx = {};
    ChainDiag cd{};
    // TODO: Wire your game's manager chain here.
    //   Example for a typical Unity FPS:
    //     1. Read GameObjectManager tagged objects list
    //     2. Find the local player GameObject by tag/name
    //     3. Read its Transform for position
    //     4. Find the Camera component for view matrix
    //   The offsets in template_data::offsets give you the field
    //   offsets for Transform, Camera, etc. from the dump.
    cd.fail_step = 1;  // Always fails until wired
    if (diag) *diag = cd;
    return false;
}

static bool ResolveLocalContext(DWORD pid, ULONGLONG base, LocalContext* ctx, ChainDiag* diag = nullptr) {
    using ET = template_data::EngineType;
    constexpr auto engine = template_data::kEngineType;
    if constexpr (engine == ET::UE4 || engine == ET::UE5)
        return ResolveLocalContext_UE(pid, base, ctx, diag);
    else if constexpr (engine == ET::Unity)
        return ResolveLocalContext_Unity(pid, base, ctx, diag);
    else {
        // Unknown engine — try UE chain first, it's the most common
        return ResolveLocalContext_UE(pid, base, ctx, diag);
    }
}

// ── View matrix builder ─────────────────────────────────────
struct CachePOV { Vec3 location, rotation; float fov, timestamp; bool valid; };
static CachePOV ParseCacheBlob(const std::uint8_t* d) {
    CachePOV p{};
    std::memcpy(&p.timestamp, d, 4);
    std::memcpy(&p.location, d + 0x10, 12);
    std::memcpy(&p.rotation, d + 0x1C, 12);
    std::memcpy(&p.fov, d + 0x28, 4);
    p.valid = std::isfinite(p.rotation.x) && std::isfinite(p.rotation.y)
           && std::isfinite(p.fov) && p.fov >= 10.0f && p.fov <= 170.0f && p.timestamp > 0.0f;
    return p;
}

static ViewMatrix BuildVMFromPOV(const Vec3& loc, const Vec3& rot, float fov) {
    float sp = std::sinf(rot.x * kPi / 180.0f), cp = std::cosf(rot.x * kPi / 180.0f);
    float sy = std::sinf(rot.y * kPi / 180.0f), cy = std::cosf(rot.y * kPi / 180.0f);
    float sr = std::sinf(rot.z * kPi / 180.0f), cr = std::cosf(rot.z * kPi / 180.0f);
    Vec3 ax{cp*cy, cp*sy, sp};
    Vec3 ay{cy*sp*sr - cr*sy, sy*sp*sr + cr*cy, -cp*sr};
    Vec3 az{-cr*cy*sp - sr*sy, -cr*sy*sp + sr*cy, cp*cr};
    ViewMatrix vm{};
    vm.m[0][0]=ay.x; vm.m[1][0]=ay.y; vm.m[2][0]=ay.z;
    vm.m[0][1]=az.x; vm.m[1][1]=az.y; vm.m[2][1]=az.z;
    vm.m[0][2]=ax.x; vm.m[1][2]=ax.y; vm.m[2][2]=ax.z;
    vm.m[3][0]=-(loc.x*ay.x + loc.y*ay.y + loc.z*ay.z);
    vm.m[3][1]=-(loc.x*az.x + loc.y*az.y + loc.z*az.z);
    vm.m[3][2]=-(loc.x*ax.x + loc.y*ax.y + loc.z*ax.z);
    vm.m[3][3]=1.0f / std::tanf(fov * kPi / 360.0f);
    return vm;
}

// ── Entity tracking ─────────────────────────────────────────
struct TrackedEntity {
    std::uint64_t actor = 0, root = 0;
    Vec3 position{};
    LocalTelemetry combat{};
    std::uint8_t team_id = 0xFF;
    bool alive = false;
};

static constexpr int kMaxTracked = 96;
static TrackedEntity g_tracked[kMaxTracked] = {};
static int g_tracked_count = 0, g_combat_cursor = 0, g_last_raw_actor_count = 0;
static DWORD g_last_actor_refresh = 0;
static bool g_use_scatter = true;
static int g_position_cursor = 0;

static bool ReadCombatTelemetry(DWORD pid, std::uint64_t actor, LocalTelemetry *out) {
    namespace off = template_data::offsets;
    if (!IsProbablyPointer(actor) || !out) return false;
    LocalTelemetry s{};
    bool any = false;

    std::uint64_t ps = 0;
    if (ReadVal(pid, actor + off::kCharacterBattlePlayerState, &ps) && IsProbablyPointer(ps)) {
        ReadVal(pid, ps + off::kPlayerStateHealthData, &s.health);
        ReadVal(pid, ps + off::kPlayerStateGuardPoint, &s.guard);
        ReadVal(pid, ps + off::kPlayerStatePlusUltraPoint, &s.plus_ultra);
        any = true;
    } else if (ReadVal(pid, actor + off::kPawnPlayerState, &ps) && IsProbablyPointer(ps)) {
        ReadVal(pid, ps + off::kPlayerStateHealthData, &s.health);
        ReadVal(pid, ps + off::kPlayerStateGuardPoint, &s.guard);
        ReadVal(pid, ps + off::kPlayerStatePlusUltraPoint, &s.plus_ultra);
        any = true;
    }

    if (!std::isfinite(s.health) || s.health < 0.0f || s.health >= 20000.0f) s.health = 100.0f;
    s.max_health = std::max(s.health, 100.0f);
    if (!std::isfinite(s.guard) || s.guard < 0.0f || s.guard > 20000.0f) s.guard = 0.0f;
    s.max_guard = (s.guard > 0.0f) ? std::max(s.guard, 100.0f) : 100.0f;
    if (!std::isfinite(s.plus_ultra) || s.plus_ultra < 0.0f || s.plus_ultra > 1000.0f) s.plus_ultra = 0.0f;

    *out = s;
    return any;
}

static void RefreshActorList(DWORD pid, ULONGLONG base, const LocalContext& ctx) {
    namespace off = template_data::offsets;
    std::uint64_t world = 0;
    if (!ReadVal(pid, base + off::kGWorld, &world) || !world) return;
    std::uint64_t level = 0;
    if (!ReadVal(pid, world + off::kWorldPersistentLevel, &level) || !IsProbablyPointer(level)) return;

    // Try common actor array offsets
    std::vector<std::uint64_t> buf;
    bool have = false;
    for (std::uint64_t o : {0xA0ULL, 0x98ULL, 0xA8ULL, 0x28ULL}) {
        std::uint64_t data = 0; int cnt = 0;
        if (ReadVal(pid, level + o, &data) && IsProbablyPointer(data) &&
            ReadVal(pid, level + o + 8, &cnt) && cnt > 0 && cnt < 30000) {
            int readable = std::min(cnt, (int)(driver::COMM_DATA_MAX / sizeof(std::uint64_t)));
            buf.resize(readable);
            if (ReadRaw(pid, data, buf.data(), buf.size() * sizeof(std::uint64_t))) { have = true; break; }
        }
    }
    if (!have) { g_last_raw_actor_count = 0; return; }
    g_last_raw_actor_count = (int)buf.size();

    for (int i = 0; i < g_tracked_count; ++i) g_tracked[i].alive = false;
    int adds = 0;
    for (auto ptr : buf) {
        if (!IsProbablyPointer(ptr)) continue;
        bool found = false;
        for (int i = 0; i < g_tracked_count; ++i)
            if (g_tracked[i].actor == ptr) { g_tracked[i].alive = true; found = true; break; }
        if (!found && g_tracked_count < kMaxTracked && adds < 24) {
            std::uint64_t ps = 0;
            if (!(ReadVal(pid, ptr + off::kPawnPlayerState, &ps) && IsProbablyPointer(ps))) continue;
            auto& t = g_tracked[g_tracked_count++];
            t = {}; t.actor = ptr; t.alive = true;
            ReadVal(pid, ptr + off::kActorRootComponent, &t.root);
            ++adds;
        }
    }
    int dst = 0;
    for (int i = 0; i < g_tracked_count; ++i)
        if (g_tracked[i].alive) { if (dst != i) g_tracked[dst] = g_tracked[i]; ++dst; }
    g_tracked_count = dst;
    g_combat_cursor = 0;
}

struct PositionPassStats {
    int ok = 0;
    int failed = 0;
};

static PositionPassStats FastUpdatePositions(DWORD pid) {
    namespace off = template_data::offsets;
    PositionPassStats stats{};
    if (g_tracked_count <= 0) return stats;

    if (!g_use_scatter) {
        int n = std::min(16, g_tracked_count);
        for (int i = 0; i < n; ++i) {
            int idx = (g_position_cursor + i) % g_tracked_count;
            auto& t = g_tracked[idx];
            if (!IsProbablyPointer(t.root)) {
                t.position = {};
                ++stats.failed;
                continue;
            }
            Vec3 pos{};
            if (ReadVec3(pid, t.root + off::kSceneComponentRelativeLocation, &pos)) {
                t.position = pos;
                ++stats.ok;
            } else {
                t.position = {};
                ++stats.failed;
            }
        }
        g_position_cursor = (g_position_cursor + n) % std::max(1, g_tracked_count);
        return stats;
    }

    std::array<driver::ScatterEntry, kMaxTracked> entries{};
    std::array<Vec3, kMaxTracked> results{};
    std::array<int, kMaxTracked> map{};
    int sc = 0;
    for (int i = 0; i < g_tracked_count; ++i) {
        auto& t = g_tracked[i];
        if (!IsProbablyPointer(t.root)) {
            t.position = {};
            ++stats.failed;
            continue;
        }
        entries[sc].Address = t.root + off::kSceneComponentRelativeLocation;
        entries[sc].Size = sizeof(Vec3);
        map[sc] = i; ++sc;
    }
    if (sc <= 0) return stats;
    DWORD t0 = GetTickCount();
    if (ScatterRaw(pid, entries.data(), sc, results.data(), sc * sizeof(Vec3))) {
        if (GetTickCount() - t0 > 150) { g_use_scatter = false; return FastUpdatePositions(pid); }
        for (int n = 0; n < sc; ++n) {
            auto& e = g_tracked[map[n]];
            auto& p = results[n];
            if (std::isfinite(p.x) && std::isfinite(p.y) && std::isfinite(p.z)) { e.position = p; ++stats.ok; }
            else { e.position = {}; ++stats.failed; }
        }
    } else { g_use_scatter = false; return FastUpdatePositions(pid); }
    return stats;
}

static int SnapshotEntities(const LocalContext& ctx, esp::EntityData* out, int max_count) {
    int count = 0;
    for (int i = 0; i < g_tracked_count && count < max_count; ++i) {
        auto& t = g_tracked[i];
        if (t.position.x == 0.0f && t.position.y == 0.0f && t.position.z == 0.0f) continue;
        auto& e = out[count]; e = {};
        e.position = t.position; e.is_valid = true;
        e.is_local = (ctx.local_pawn && t.actor == ctx.local_pawn);
        e.team_id = t.team_id;
        e.is_teammate = (!e.is_local && ctx.team_id != 0xFF && t.team_id != 0xFF && t.team_id == ctx.team_id);
        e.health = t.combat.health; e.max_health = t.combat.max_health;
        e.guard = t.combat.guard; e.max_guard = t.combat.max_guard;
        e.plus_ultra = t.combat.plus_ultra;
        e.actor = t.actor;
        if (e.is_local) std::snprintf(e.name, sizeof(e.name), "You");
        else if (t.team_id == 0xFF) std::snprintf(e.name, sizeof(e.name), "Player");
        else std::snprintf(e.name, sizeof(e.name), "Team %u", (unsigned)t.team_id);
        ++count;
    }
    return count;
}

// ── Aimbot ──────────────────────────────────────────────────
static AimbotResult RunAimbot(DWORD pid, const LocalContext& ctx, const EntitySnapshot& snap,
                              const ReaderThread::AimbotConfig& cfg, unsigned long long& locked) {
    namespace off = template_data::offsets;
    AimbotResult dbg{}; dbg.controller = ctx.player_controller;
    dbg.has_controller = IsProbablyPointer(dbg.controller);
    if (!cfg.enabled) { dbg.reason = "disabled"; locked = 0; return dbg; }
    if (!cfg.active) { dbg.reason = "inactive"; return dbg; }
    dbg.ran = true;
    if (!pid || !dbg.has_controller) { dbg.reason = "no-controller"; locked = 0; return dbg; }

    Vec3 cur_rot{};
    if (!ReadVal(pid, dbg.controller + off::kControllerControlRotation, &cur_rot))
        { dbg.reason = "ctrlrot-read-fail"; return dbg; }
    dbg.read_rotation_ok = true; dbg.current_rot = cur_rot;

    float sw = cfg.screen_w, sh = cfg.screen_h;
    float cx = sw * 0.5f, cy = sh * 0.5f;
    float radius_px = std::max(8.0f, cx * (cfg.fov / 90.0f));
    float best = radius_px; bool found = false;
    Vec3 best_pos{}; unsigned long long new_locked = 0;

    // Sticky lock check
    if (locked) {
        for (int i = 0; i < snap.entity_count; ++i) {
            const auto& e = snap.entities[i];
            if (e.actor == locked && e.is_valid && !e.is_local && !e.is_teammate && e.health > 0.0f) {
                Vec3 tp = e.position; tp.z += 72.0f;
                Vec2 sc{}; if (WorldToScreen(tp, sc, snap.view_matrix, sw, sh)) {
                    float d = std::sqrt((sc.x-cx)*(sc.x-cx)+(sc.y-cy)*(sc.y-cy));
                    if (d <= radius_px * 1.5f) { found=true; best_pos=tp; new_locked=locked; best=d; }
                } break;
            }
        }
    }
    if (!found) {
        for (int i = 0; i < snap.entity_count; ++i) {
            const auto& e = snap.entities[i];
            if (!e.is_valid || e.is_local || e.is_teammate || e.health <= 0.0f) continue;
            ++dbg.scanned;
            Vec3 tp = e.position; tp.z += 72.0f;
            Vec2 sc{}; if (!WorldToScreen(tp, sc, snap.view_matrix, sw, sh)) continue;
            float d = std::sqrt((sc.x-cx)*(sc.x-cx)+(sc.y-cy)*(sc.y-cy));
            if (d <= radius_px) ++dbg.candidates;
            if (d < best) { best=d; best_pos=tp; new_locked=e.actor; found=true; }
        }
    }
    locked = new_locked;
    if (!found) { dbg.reason = "no-target"; return dbg; }

    Vec3 origin = (std::isfinite(snap.camera_diag.location.x)) ? snap.camera_diag.location : snap.local_position;
    Vec3 aim = CalculateAimRotation(origin, best_pos);
    float sm = std::max(cfg.smooth, 1.0f);
    Vec3 out = aim;
    if (sm > 1.0f) { out.x = cur_rot.x + NormalizeAngle(aim.x - cur_rot.x) / sm;
                     out.y = cur_rot.y + NormalizeAngle(aim.y - cur_rot.y) / sm; }
    out.x = ClampPitch(out.x); out.y = NormalizeAngle(out.y);
    dbg.target_rot = out; dbg.best_fov = best;
    dbg.write_ok = driver::WriteMemory(pid, dbg.controller + off::kControllerControlRotation, &out, sizeof(out));
    dbg.reason = dbg.write_ok ? "ok" : "ctrlrot-write-fail";
    return dbg;
}

// ── ReaderThread implementation ─────────────────────────────
void ReaderThread::Start(EntityCache* cache, DWORD pid, ULONGLONG base) {
    cache_ = cache; pid_.store(pid); base_.store(base);
    stop_requested_.store(false); running_.store(true);
    thread_ = std::thread(&ReaderThread::ThreadFunc, this);
}

void ReaderThread::Stop() {
    stop_requested_.store(true);
    if (thread_.joinable()) thread_.join();
    running_.store(false);
}

void ReaderThread::SetTarget(DWORD pid, ULONGLONG base) { pid_.store(pid); base_.store(base); }
void ReaderThread::SetMenuOpen(bool open) { menu_open_.store(open); }

void ReaderThread::SetAimbotConfig(const menu::MenuState& ms, float sw, float sh) {
    std::lock_guard<std::mutex> lock(aim_cfg_mutex_);
    aim_cfg_.enabled = ms.aimbot_enabled; aim_cfg_.active = ms.aimbot_active;
    aim_cfg_.fov = ms.aimbot_fov; aim_cfg_.smooth = ms.aimbot_smooth;
    aim_cfg_.screen_w = sw; aim_cfg_.screen_h = sh;
}

void ReaderThread::ThreadFunc() {
    LocalContext cached_ctx{}; ChainDiag cached_chain{};
    bool ctx_valid = false; int ctx_skip = 0;
    int context_fail_streak = 0, context_fail_total = 0, last_fail_step = 0;
    DWORD last_cycle = 0; float smoothed_hz = 0.0f;
    int last_cam_source = 0;

    // Track state for reader diag locally
    PositionPassStats last_pos_stats{};

    while (!stop_requested_.load(std::memory_order_acquire)) {
        DWORD pid = pid_.load(); ULONGLONG base = base_.load();
        if (!pid || !base) { Sleep(50); continue; }

        DWORD now = GetTickCount();
        const DWORD cycle_start = now;
        const auto reads_start = g_read_calls_total;
        const auto fails_start = g_read_fail_total;

        // Resolve context (every 4th cycle)
        bool do_ctx = !ctx_valid || (++ctx_skip >= 4);
        bool used_cached = false;
        LocalContext ctx{}; ChainDiag chain{};
        if (do_ctx) {
            ctx_skip = 0;
            if (ResolveLocalContext(pid, base, &ctx, &chain)) {
                cached_ctx = ctx; cached_chain = chain; ctx_valid = true; context_fail_streak = 0;
            } else {
                ++context_fail_streak; ++context_fail_total; last_fail_step = chain.fail_step;
                if (!ctx_valid) {
                    EntitySnapshot& fs = cache_->GetBackBuffer();
                    fs.chain_diag = chain; fs.entity_count = 0; fs.read_hz = smoothed_hz;
                    cache_->CommitBackBuffer(); Sleep(16); continue;
                }
                cached_chain = chain; used_cached = true;
            }
        }
        ctx = cached_ctx; chain = cached_chain;

        // Actor refresh (~every 2.8s)
        if ((now - g_last_actor_refresh) > 2800 || g_tracked_count == 0) {
            RefreshActorList(pid, base, ctx); g_last_actor_refresh = now;
        }

        last_pos_stats = FastUpdatePositions(pid);

        // Staggered combat (2 per cycle)
        for (int n = 0; n < 2 && g_tracked_count > 0; ++n) {
            int idx = g_combat_cursor % g_tracked_count;
            auto& t = g_tracked[idx];
            ReadCombatTelemetry(pid, t.actor, &t.combat);
            ++g_combat_cursor;
        }

        // Camera
        EntitySnapshot& snap = cache_->GetBackBuffer();
        {
            namespace off = template_data::offsets;
            if (IsProbablyPointer(ctx.camera_manager)) {
                std::array<std::uint8_t, 0x40> cam{};
                bool ok = false;
                if (last_cam_source == 2 || last_cam_source == 0) {
                    ok = ReadRaw(pid, ctx.camera_manager + off::kPlayerCameraManagerCameraCachePrivate, cam.data(), cam.size());
                    if (ok) { auto p = ParseCacheBlob(cam.data()); ok = p.valid;
                        if (ok) { snap.view_matrix = BuildVMFromPOV(p.location, p.rotation, p.fov);
                                  snap.camera_diag = {p.location, p.rotation, p.fov, 2}; last_cam_source = 2; } }
                }
                if (!ok) {
                    ok = ReadRaw(pid, ctx.camera_manager + 0x290ULL, cam.data(), cam.size());
                    if (ok) { auto p = ParseCacheBlob(cam.data()); ok = p.valid;
                        if (ok) { snap.view_matrix = BuildVMFromPOV(p.location, p.rotation, p.fov);
                                  snap.camera_diag = {p.location, p.rotation, p.fov, 1}; last_cam_source = 1; } }
                }
                if (!ok && IsProbablyPointer(ctx.player_controller)) {
                    Vec3 cr{}; if (ReadVal(pid, ctx.player_controller + off::kControllerControlRotation, &cr) &&
                        std::isfinite(cr.x) && std::isfinite(cr.y)) {
                        snap.view_matrix = BuildVMFromPOV(snap.local_position, cr, 80.0f);
                        snap.camera_diag = {snap.local_position, cr, 80.0f, 3}; last_cam_source = 3;
                    }
                }

            }
        } // end camera

        // Local position
        if (IsProbablyPointer(ctx.local_pawn)) {
            std::uint64_t root = 0;
            if (ReadVal(pid, ctx.local_pawn + off::kActorRootComponent, &root) && IsProbablyPointer(root))
                ReadVec3(pid, root + off::kSceneComponentRelativeLocation, &snap.local_position);
        }

        snap.chain_diag = chain;
        DWORD cycle_now = GetTickCount();
        if (last_cycle > 0 && cycle_now > last_cycle)
            smoothed_hz = smoothed_hz * 0.8f + (1000.0f / (cycle_now - last_cycle)) * 0.2f;
        last_cycle = cycle_now;
        snap.read_hz = smoothed_hz;
        snap.entity_count = SnapshotEntities(ctx, snap.entities, EntitySnapshot::kMaxEntities);

        DWORD diag_now = GetTickCount();
        snap.reader_diag.tracked_count = g_tracked_count;
        snap.reader_diag.raw_actor_count = g_last_raw_actor_count;
        snap.reader_diag.position_reads_ok = last_pos_stats.ok;
        snap.reader_diag.position_reads_failed = last_pos_stats.failed;
        snap.reader_diag.context_fail_streak = context_fail_streak;
        snap.reader_diag.used_cached_context = used_cached;
        snap.reader_diag.cycle_time_ms = diag_now >= cycle_start ? diag_now - cycle_start : 0;
        snap.reader_diag.read_calls = (DWORD)(g_read_calls_total - reads_start);
        snap.reader_diag.read_fails = (DWORD)(g_read_fail_total - fails_start);
        snap.reader_diag.scatter_positions = g_use_scatter;

        AimbotConfig acfg;
        { std::lock_guard<std::mutex> lock(aim_cfg_mutex_); acfg = aim_cfg_; }
        snap.aimbot_result = RunAimbot(pid, ctx, snap, acfg, locked_target_);

        cache_->CommitBackBuffer();
        Sleep(0);
    }
}

}  // namespace game
"""

_TPL_ADMIN_MAIN_CPP = """#include <windows.h>
#include <shellapi.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "entity_cache.hpp"
#include "esp.hpp"
#include "generated_feature_catalog.hpp"
#include "menu.hpp"
#include "driver.h"
#include "overlay.hpp"
#include "reader_thread.hpp"

#include "imgui.h"

namespace {

constexpr float kPi = 3.14159265358979323846f;

bool IsProbablyPointer(std::uint64_t p) {
  return p >= 0x10000ULL && p <= 0x00007FFFFFFFFFFFULL;
}

float NormalizeAngle(float a) {
  while (a > 180.0f)
    a -= 360.0f;
  while (a < -180.0f)
    a += 360.0f;
  return a;
}

const char *VkLabel(int vk) {
  switch (vk) {
  case VK_RBUTTON:
    return "RMB";
  case VK_LBUTTON:
    return "LMB";
  case VK_XBUTTON1:
    return "Mouse4";
  case VK_XBUTTON2:
    return "Mouse5";
  case VK_LSHIFT:
    return "LShift";
  case VK_LMENU:
    return "LAlt";
  case 'Q':
    return "Q";
  case 'E':
    return "E";
  case 'F':
    return "F";
  case 'X':
    return "X";
  case 'C':
    return "C";
  default:
    return "Custom";
  }
}

const char *PhaseGuess(const game::EntitySnapshot &snap) {
  if (!IsProbablyPointer(snap.chain_diag.world))
    return "NoWorld";
  if (!IsProbablyPointer(snap.chain_diag.local_pawn))
    return "Menu/Lobby";
  if (snap.local_stats.health <= 1.0f && snap.entity_count < 8)
    return "Lobby/Loading";
  return "InMatch";
}

void DrawDebugPanel(const game::EntitySnapshot &snap,
                    const menu::MenuState &menu_state,
                    bool driver_connected, DWORD target_pid,
                    ULONGLONG module_base) {
  const auto &aim_dbg = snap.aimbot_result;
  const char *cam_src[] = {"NONE", "CameraCache", "CachePrv", "CtrlRot"};
  const char *chain_names[] = {"OK",      "GWorld", "GameInst", "LPData",
                               "LPlayer", "PCtrl",  "Pawn",     "CamMgr"};
  const bool vm_valid = (snap.view_matrix.m[3][3] > 0.0f);

  ImGui::SetNextWindowPos(ImVec2(overlay::GetWidth() * 0.5f, 8.0f),
                          ImGuiCond_FirstUseEver, ImVec2(0.5f, 0.0f));
  ImGui::SetNextWindowBgAlpha(0.86f);
  ImGuiWindowFlags flags = ImGuiWindowFlags_AlwaysAutoResize;
  if (!menu_state.visible)
    flags |= ImGuiWindowFlags_NoMove;

  ImGui::Begin("Debug", nullptr, flags);
  ImGui::Text("Driver:%s PID:%lu Base:0x%llX", driver_connected ? "OK" : "NO",
              target_pid, module_base);
  ImGui::Text("Read %.1fHz | Cycle %ums | Calls %u | Fails %u | Scatter:%s",
              snap.read_hz, snap.reader_diag.cycle_time_ms,
              snap.reader_diag.read_calls, snap.reader_diag.read_fails,
              snap.reader_diag.scatter_positions ? "on" : "off");
  ImGui::Text("Actors raw:%d tracked:%d snap:%d refreshAge:%ums",
              snap.reader_diag.raw_actor_count, snap.reader_diag.tracked_count,
              snap.entity_count, snap.reader_diag.actor_refresh_age_ms);
  ImGui::Text("Pos reads ok:%d fail:%d | cached-ctx:%s",
              snap.reader_diag.position_reads_ok,
              snap.reader_diag.position_reads_failed,
              snap.reader_diag.used_cached_context ? "yes" : "no");
  const int chain_idx =
      (snap.chain_diag.fail_step >= 0 && snap.chain_diag.fail_step <= 7)
          ? snap.chain_diag.fail_step
          : 0;
  ImGui::Text("Chain fail:%d (%s) streak:%d total:%d lastFail:%d",
              snap.chain_diag.fail_step, chain_names[chain_idx],
              snap.reader_diag.context_fail_streak,
              snap.reader_diag.context_fail_total,
              snap.reader_diag.last_context_fail_step);
  ImGui::Text("GWorld:0x%llX | GI:0x%llX | Pawn:0x%llX | Phase:%s",
              snap.chain_diag.world, snap.chain_diag.game_instance,
              snap.chain_diag.local_pawn, PhaseGuess(snap));
  ImGui::Text("Ptrs W:0x%llX GI:0x%llX LP:0x%llX PC:0x%llX Pawn:0x%llX CM:0x%llX",
              snap.chain_diag.world, snap.chain_diag.game_instance,
              snap.chain_diag.local_player, snap.chain_diag.player_controller,
              snap.chain_diag.local_pawn, snap.chain_diag.camera_manager);
  ImGui::Text("Cam[%s] VM:%s FOV:%.1f Loc(%.0f %.0f %.0f) Rot(%.1f %.1f %.1f)",
              cam_src[snap.camera_diag.source], vm_valid ? "OK" : "BAD",
              snap.camera_diag.fov, snap.camera_diag.location.x,
              snap.camera_diag.location.y, snap.camera_diag.location.z,
              snap.camera_diag.rotation.x, snap.camera_diag.rotation.y,
              snap.camera_diag.rotation.z);
  ImGui::Text("Aimbot en:%s active:%s mode:%s key:%s ran:%s reason:%s",
              menu_state.aimbot_enabled ? "yes" : "no",
              menu_state.aimbot_active ? "yes" : "no",
              menu_state.aimbot_activation_mode ==
                      menu::AimbotActivationMode::Hold
                  ? "hold"
                  : "toggle",
              VkLabel(menu_state.aimbot_key), aim_dbg.ran ? "yes" : "no",
              aim_dbg.reason);
  ImGui::Text("Aim PC:0x%llX rotRead:%s scan:%d cand:%d bestFov:%.2f write:%s",
              aim_dbg.controller, aim_dbg.read_rotation_ok ? "yes" : "no",
              aim_dbg.scanned, aim_dbg.candidates, aim_dbg.best_fov,
              aim_dbg.write_ok ? "yes" : "no");
  ImGui::Text("Local HP %.0f/%.0f GP %.0f/%.0f PU %.0f Team %u",
              snap.local_stats.health, snap.local_stats.max_health,
              snap.local_stats.guard, snap.local_stats.max_guard,
              snap.local_stats.plus_ultra,
              static_cast<unsigned>(snap.local_team_id));
  ImGui::End();
}

} // namespace

int WINAPI WinMain(HINSTANCE instance, HINSTANCE, LPSTR, int) {
  if (!overlay::Create(instance))
    return 1;

  menu::MenuState menu_state{};
  bool driver_connected = false;
  DWORD target_pid = 0;
  ULONGLONG module_base = 0;

  const char *proc_name = trainer::template_data::kProcessName;

  // ── Driver initialisation ────────────────────────────────────
  if (driver::Init()) {
    driver_connected = true;
  } else {
    char exe_dir[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exe_dir, MAX_PATH);
    char *last_slash = std::strrchr(exe_dir, '\\\\');
    if (last_slash)
      *(last_slash + 1) = '\\0';

    char mapper_path[MAX_PATH] = {};
    char driver_path[MAX_PATH] = {};
    char params[MAX_PATH * 2] = {};

    std::snprintf(mapper_path, MAX_PATH, "%sgsd_mapper.exe", exe_dir);
    std::snprintf(driver_path, MAX_PATH, "%swdfsvc64.sys", exe_dir);
    if (GetFileAttributesA(mapper_path) == INVALID_FILE_ATTRIBUTES) {
      std::snprintf(mapper_path, MAX_PATH, "%sbin\\\\gsd_mapper.exe", exe_dir);
      std::snprintf(driver_path, MAX_PATH, "%sbin\\\\wdfsvc64.sys", exe_dir);
    }

    std::snprintf(params, sizeof(params), "\\"%s\\"", driver_path);

    SHELLEXECUTEINFOA sei = {sizeof(sei)};
    sei.lpVerb = "runas";
    sei.lpFile = mapper_path;
    sei.lpParameters = params;
    sei.lpDirectory = exe_dir;
    sei.nShow = SW_HIDE;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    if (ShellExecuteExA(&sei)) {
      if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 10000);
        CloseHandle(sei.hProcess);
      }
      if (driver::Init())
        driver_connected = true;
    }
  }

  if (driver_connected) {
    driver::HealthCheck();
    wchar_t wname[128] = {};
    MultiByteToWideChar(CP_UTF8, 0, proc_name, -1, wname, 128);
    target_pid = driver::FindProcessByName(wname);
    if (target_pid)
      module_base = driver::GetModuleBase(target_pid);
  }

  // ── Start the background reader thread ───────────────────────
  game::EntityCache entity_cache;
  game::ReaderThread reader;

  if (driver_connected && target_pid && module_base) {
    reader.Start(&entity_cache, target_pid, module_base);
  }

  game::EntitySnapshot frame_snap;
  int frame_counter = 0;

  // ── Render loop (NO driver calls — only cache reads) ─────────
  while (true) {
    ++frame_counter;

    // Window class is auto-detected from the dump (UE=UnrealWindow,
    // Unity=UnityWndClass).
    const wchar_t *wc = trainer::template_data::kWindowClass;
    overlay::TrackWindow(wc[0] ? wc : nullptr, nullptr,
                               menu_state.visible);

    // HOME = immediate shutdown. Must invoke ExitProcess for threaded shutdown.
    if (GetAsyncKeyState(VK_HOME) & 1) {
      reader.Stop();
      driver::Shutdown();
      overlay::Destroy();
      ExitProcess(0);
      break;
    }

    // Every ~1s, check that the target is still alive.
    if (target_pid && frame_counter % 60 == 0) {
      HANDLE h =
          OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, target_pid);
      if (!h) {
        target_pid = 0;
        module_base = 0;
        reader.SetTarget(0, 0);
      } else {
        CloseHandle(h);
      }
    }

    // Re-attach if the process respawns.
    if (!target_pid && driver_connected && frame_counter % 60 == 0) {
      wchar_t wname[128] = {};
      MultiByteToWideChar(CP_UTF8, 0, proc_name, -1, wname, 128);
      target_pid = driver::FindProcessByName(wname);
      if (target_pid) {
        module_base = driver::GetModuleBase(target_pid);
        reader.SetTarget(target_pid, module_base);
        if (!reader.IsRunning())
          reader.Start(&entity_cache, target_pid, module_base);
      }
    }

    // ── Input processing since overlay is NOACTIVATE ─────────────────
    ImGuiIO &io = ImGui::GetIO();
    if (menu_state.visible) {
      POINT pt;
      if (GetCursorPos(&pt)) {
        if (ScreenToClient(overlay::GetHwnd(), &pt)) {
          io.AddMousePosEvent(static_cast<float>(pt.x),
                              static_cast<float>(pt.y));
        }
      }
      io.AddMouseButtonEvent(0, (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0);
      io.AddMouseButtonEvent(1, (GetAsyncKeyState(VK_RBUTTON) & 0x8000) != 0);
    }

    // F3 or INSERT toggles menu.
    if ((GetAsyncKeyState(VK_F3) & 1) || (GetAsyncKeyState(VK_INSERT) & 1)) {
      menu::Toggle(menu_state);
    }

    // Auto-close menu if we lost foreground to another app (that isn't the
    // game)
    if (menu_state.visible && !overlay::IsGameActive()) {
      menu_state.visible = false;
    }

    // ── Aimbot activation logic ──────────────────────────────
    {
      const bool key_down =
          (GetAsyncKeyState(menu_state.aimbot_key) & 0x8000) != 0;
      const bool key_pressed = key_down && !menu_state.aimbot_was_down;
      menu_state.aimbot_was_down = key_down;

      // Do NOT run aimbot while dragging sliders in ImGui menu
      if (menu_state.visible && io.WantCaptureMouse) {
        menu_state.aimbot_active = false;
      } else if (!menu_state.aimbot_enabled) {
        menu_state.aimbot_active = false;
        menu_state.aimbot_toggled_on = false;
      } else if (menu_state.aimbot_activation_mode ==
                 menu::AimbotActivationMode::Hold) {
        menu_state.aimbot_toggled_on = false;
        menu_state.aimbot_active = key_down;
      } else {
        if (key_pressed)
          menu_state.aimbot_toggled_on = !menu_state.aimbot_toggled_on;
        menu_state.aimbot_active = menu_state.aimbot_toggled_on;
      }
    }

    reader.SetMenuOpen(menu_state.visible);
    overlay::SetClickThrough(!menu_state.visible);

    if (!overlay::BeginFrame())
      break;

    // Pause rendering entirely if user alt-tabbed to another monitor/window
    if (!overlay::IsVisible() || !overlay::IsGameActive()) {
      overlay::EndFrame();
      continue;
    }

    ImGui::GetIO().MouseDrawCursor = menu_state.visible;

    // LWA_COLORKEY fix: draw a barely-visible rect so RGB(0,0,0) pixels
    // don't pass clicks through to the game when the menu is open.
    if (menu_state.visible) {
      auto *dl = ImGui::GetBackgroundDrawList();
      dl->AddRectFilled(
          ImVec2(0, 0),
          ImVec2(overlay::GetWidth(), overlay::GetHeight()),
          IM_COL32(0, 0, 1, 1));
    }

    // Push aimbot config to reader thread (no driver calls from render thread).
    reader.SetAimbotConfig(menu_state, overlay::GetWidth(),
                           overlay::GetHeight());

    // Grab latest snapshot from the reader thread (fast memcpy under lock).
    entity_cache.ReadSnapshot(frame_snap);

    // ESP rendering — reads only from the local snapshot, zero driver calls.
    esp::RenderESP(menu_state.esp_config, frame_snap.entities,
                         frame_snap.entity_count, frame_snap.view_matrix,
                         frame_snap.local_position, overlay::GetWidth(),
                         overlay::GetHeight(), overlay::GetX(),
                         overlay::GetY());

    // Debug panel (toggled from menu).
    if (menu_state.show_debug_panel) {
      DrawDebugPanel(frame_snap, menu_state, driver_connected, target_pid,
                     module_base);
    }

    menu::Render(menu_state, driver_connected, target_pid, module_base);
    overlay::EndFrame();
  }

  reader.Stop();
  driver::Shutdown();
  overlay::Destroy();
  return 0;
}
"""

_TPL_ADMIN_CMAKELISTS = """cmake_minimum_required(VERSION 3.20)
project(cheat_client LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(IMGUI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/imgui")

add_executable(cheat_client WIN32
    src/main.cpp
    src/overlay.cpp
    src/esp.cpp
    src/menu.cpp
    src/reader_thread.cpp
    src/driver.cpp
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_dx11.cpp
    ${IMGUI_DIR}/backends/imgui_impl_win32.cpp
)

target_include_directories(cheat_client PRIVATE
    src
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
)

target_compile_definitions(cheat_client PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_link_libraries(cheat_client PRIVATE d3d11 dxgi d3dcompiler dwmapi winmm)
"""

_TPL_ADMIN_OVERLAY_CPP = r'''#include "overlay.hpp"
#include "backends/imgui_impl_dx11.h"
#include "backends/imgui_impl_win32.h"
#include "imgui.h"
#include <timeapi.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "winmm.lib")

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM,
                                                             LPARAM);

namespace nova::overlay {

static HWND g_hwnd = nullptr;
static ID3D11Device *g_device = nullptr;
static ID3D11DeviceContext *g_context = nullptr;
static IDXGISwapChain *g_swap = nullptr;
static ID3D11RenderTargetView *g_rtv = nullptr;
static float g_width = 1920.0f;
static float g_height = 1080.0f;
static float g_target_x = 0.0f;
static float g_target_y = 0.0f;
static bool g_click_through = true;

static LRESULT WINAPI WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wp, lp))
    return 1;
  if (msg == WM_DESTROY) {
    PostQuitMessage(0);
    return 0;
  }
  return DefWindowProcW(hwnd, msg, wp, lp);
}

bool Create(HINSTANCE instance) {
  WNDCLASSEXW wc = {sizeof(wc),
                    CS_HREDRAW | CS_VREDRAW,
                    WndProc,
                    0,
                    0,
                    instance,
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr,
                    L"NOVAOverlay",
                    nullptr};
  RegisterClassExW(&wc);

  g_hwnd = CreateWindowExW(
      WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED | WS_EX_TOOLWINDOW |
          WS_EX_NOACTIVATE,
      wc.lpszClassName, L"NOVA", WS_POPUP, 0, 0, GetSystemMetrics(SM_CXSCREEN),
      GetSystemMetrics(SM_CYSCREEN), nullptr, nullptr, instance, nullptr);
  if (!g_hwnd)
    return false;

  SetLayeredWindowAttributes(g_hwnd, RGB(0, 0, 0), 0, LWA_COLORKEY);
  MARGINS margins = {-1};
  DwmExtendFrameIntoClientArea(g_hwnd, &margins);

  DXGI_SWAP_CHAIN_DESC sd = {};
  sd.BufferCount = 2;
  sd.BufferDesc.Width = GetSystemMetrics(SM_CXSCREEN);
  sd.BufferDesc.Height = GetSystemMetrics(SM_CYSCREEN);
  sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
  sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
  sd.OutputWindow = g_hwnd;
  sd.SampleDesc.Count = 1;
  sd.Windowed = TRUE;
  sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

  D3D_FEATURE_LEVEL fl[] = {D3D_FEATURE_LEVEL_11_0};
  D3D_FEATURE_LEVEL fl_out;
  if (FAILED(D3D11CreateDeviceAndSwapChain(
          nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, fl, 1,
          D3D11_SDK_VERSION, &sd, &g_swap, &g_device, &fl_out, &g_context))) {
    DestroyWindow(g_hwnd);
    return false;
  }

  ID3D11Texture2D *bb = nullptr;
  g_swap->GetBuffer(0, IID_PPV_ARGS(&bb));
  g_device->CreateRenderTargetView(bb, nullptr, &g_rtv);
  bb->Release();

  g_width = static_cast<float>(sd.BufferDesc.Width);
  g_height = static_cast<float>(sd.BufferDesc.Height);

  ShowWindow(g_hwnd, SW_SHOWDEFAULT);
  UpdateWindow(g_hwnd);

  // Set timer resolution to 1ms so Sleep(1) actually sleeps ~1ms instead
  // of 15.6ms
  timeBeginPeriod(1);

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGui_ImplWin32_Init(g_hwnd);
  ImGui_ImplDX11_Init(g_device, g_context);

  return true;
}

void Destroy() {
  timeEndPeriod(1);
  ImGui_ImplDX11_Shutdown();
  ImGui_ImplWin32_Shutdown();
  ImGui::DestroyContext();
  if (g_rtv)
    g_rtv->Release();
  if (g_swap)
    g_swap->Release();
  if (g_context)
    g_context->Release();
  if (g_device)
    g_device->Release();
  if (g_hwnd)
    DestroyWindow(g_hwnd);
}

bool BeginFrame() {
  MSG msg;
  while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
    if (msg.message == WM_QUIT)
      return false;
  }
  ImGui_ImplDX11_NewFrame();
  ImGui_ImplWin32_NewFrame();
  ImGui::NewFrame();
  return true;
}

void EndFrame() {
  ImGui::Render();
  const float clear[4] = {0.0f, 0.0f, 0.0f, 0.0f}; // Fully transparent
  g_context->OMSetRenderTargets(1, &g_rtv, nullptr);
  g_context->ClearRenderTargetView(g_rtv, clear);
  ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
  g_swap->Present(
      0, 0); // VSync disabled to prevent DWM lag on transparent overlays
  Sleep(1); // Prevent 100% CPU; requires timeBeginPeriod(1) for ~1ms resolution
}

static HWND g_game_hwnd = nullptr;

void TrackWindow(const wchar_t *window_class, const wchar_t *window_title,
                 bool menu_open) {
  HWND target = nullptr;
  if (window_class)
    target = FindWindowW(window_class, nullptr);
  if (!target && window_title)
    target = FindWindowW(nullptr, window_title);
  if (!target && window_class)
    target = FindWindowW(nullptr, window_class);
  if (!target)
    return;

  g_game_hwnd = target;

  RECT rc;
  if (GetClientRect(target, &rc)) {
    POINT pt = {0, 0};
    ClientToScreen(target, &pt);

    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;

    HWND foreground = GetForegroundWindow();
    bool is_active = (foreground == target || foreground == g_hwnd);

    // When menu is open, always stay on top so we don't fight with
    // SetClickThrough and lose input mid-interaction.
    HWND insert_after;
    if (menu_open) {
      insert_after = HWND_TOPMOST;
    } else {
      insert_after = is_active ? HWND_TOPMOST : HWND_BOTTOM;
    }

    float fw = static_cast<float>(w);
    float fh = static_cast<float>(h);
    float fx = static_cast<float>(pt.x);
    float fy = static_cast<float>(pt.y);

    static bool g_was_active = false;

    if (g_target_x != fx || g_target_y != fy || g_width != fw ||
        g_height != fh || g_was_active != is_active) {
      SetWindowPos(g_hwnd, insert_after, pt.x, pt.y, w, h, SWP_NOACTIVATE);
      g_target_x = fx;
      g_target_y = fy;
      g_width = fw;
      g_height = fh;
      g_was_active = is_active;
    }
  }
}

HWND GetGameHwnd() { return g_game_hwnd; }

HWND GetHwnd() { return g_hwnd; }
ID3D11Device *GetDevice() { return g_device; }
ID3D11DeviceContext *GetContext() { return g_context; }
float GetWidth() { return g_width; }
float GetHeight() { return g_height; }
float GetX() { return g_target_x; }
float GetY() { return g_target_y; }
bool IsVisible() { return true; }

bool IsGameActive() {
  HWND foreground = GetForegroundWindow();
  return (foreground == g_hwnd || foreground == g_game_hwnd);
}

void SetClickThrough(bool click_through) {
  if (!g_hwnd || g_click_through == click_through)
    return;

  LONG ex_style = GetWindowLongW(g_hwnd, GWL_EXSTYLE);
  if (click_through) {
    ex_style |= WS_EX_TRANSPARENT;
  } else {
    ex_style &= ~WS_EX_TRANSPARENT;
  }
  SetWindowLongW(g_hwnd, GWL_EXSTYLE, ex_style);
  SetWindowPos(g_hwnd, nullptr, 0, 0, 0, 0,
               SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE |
                   SWP_FRAMECHANGED);
  g_click_through = click_through;
}

} // namespace nova::overlay
'''

_TPL_ADMIN_ESP_CPP = r'''#include "esp.hpp"
#include <cstdio>

namespace nova::esp {

void DrawBox(const Vec2& tl, const Vec2& br, ImU32 color, BoxStyle style, float thickness) {
    auto* dl = ImGui::GetBackgroundDrawList();
    float w = br.x - tl.x;
    float h = br.y - tl.y;

    switch (style) {
    case BoxStyle::Full:
        dl->AddRect(ImVec2(tl.x, tl.y), ImVec2(br.x, br.y), color, 0.0f, 0, thickness);
        break;
    case BoxStyle::Rounded:
        dl->AddRect(ImVec2(tl.x, tl.y), ImVec2(br.x, br.y), color, 4.0f, 0, thickness);
        break;
    case BoxStyle::Corner: {
        float corner = w * 0.2f;
        if (corner < 6.0f) corner = 6.0f;
        // Top-left
        dl->AddLine(ImVec2(tl.x, tl.y), ImVec2(tl.x + corner, tl.y), color, thickness);
        dl->AddLine(ImVec2(tl.x, tl.y), ImVec2(tl.x, tl.y + corner), color, thickness);
        // Top-right
        dl->AddLine(ImVec2(br.x, tl.y), ImVec2(br.x - corner, tl.y), color, thickness);
        dl->AddLine(ImVec2(br.x, tl.y), ImVec2(br.x, tl.y + corner), color, thickness);
        // Bottom-left
        dl->AddLine(ImVec2(tl.x, br.y), ImVec2(tl.x + corner, br.y), color, thickness);
        dl->AddLine(ImVec2(tl.x, br.y), ImVec2(tl.x, br.y - corner), color, thickness);
        // Bottom-right
        dl->AddLine(ImVec2(br.x, br.y), ImVec2(br.x - corner, br.y), color, thickness);
        dl->AddLine(ImVec2(br.x, br.y), ImVec2(br.x, br.y - corner), color, thickness);
        break;
    }
    }
}

void RenderESP(const Config& cfg, const EntityData* entities, int count,
               const ViewMatrix& vm, const Vec3& local_pos,
               float screen_w, float screen_h,
               float offset_x, float offset_y) {
    if (!cfg.enabled) return;
    auto* dl = ImGui::GetBackgroundDrawList();

    for (int i = 0; i < count; ++i) {
        const auto& ent = entities[i];
        if (!ent.is_valid) continue;
        if (ent.is_local && !cfg.show_local_player) continue;
        if (!ent.is_local && ent.is_teammate && !cfg.show_teammates) continue;

        float dist = Distance3D(local_pos, ent.position) / 100.0f;  // UE units to meters
        if (!ent.is_local && (dist > cfg.max_distance || dist < 1.0f)) continue;

        Vec2 head_screen, feet_screen;
        // In Unreal Engine, the SceneComponent location is the center of the Capsule.
        // Downed players usually have 0 Main Health (and switch to Dying Health).
        // Their capsule shrinks dramatically when they are crawling on the floor.
        float half_height = (ent.health <= 0.0f) ? 30.0f : 90.0f;

        Vec3 feet_pos = ent.position;
        feet_pos.z -= half_height;  // Move down to floor

        Vec3 head_pos = ent.position;
        head_pos.z += half_height;  // Move up to head/torso top

        if (!WorldToScreen(feet_pos, feet_screen, vm, screen_w, screen_h)) continue;
        if (!WorldToScreen(head_pos, head_screen, vm, screen_w, screen_h)) continue;

        feet_screen.x += offset_x;
        feet_screen.y += offset_y;
        head_screen.x += offset_x;
        head_screen.y += offset_y;

        float box_h = feet_screen.y - head_screen.y;
        if (box_h < 4.0f) continue;
        float box_w = box_h * 0.45f;

        Vec2 tl = { head_screen.x - box_w * 0.5f, head_screen.y };
        Vec2 br = { head_screen.x + box_w * 0.5f, feet_screen.y };

        ImVec4 base_color = cfg.box_color;
        if (cfg.use_team_colors && !ent.is_local) {
            base_color = ent.is_teammate ? cfg.teammate_color : cfg.enemy_color;
        }
        ImU32 box_col = ImGui::ColorConvertFloat4ToU32(base_color);

        // Box ESP
        if (cfg.box_esp)
            DrawBox(tl, br, box_col, cfg.box_style);

        // Name ESP
        if (cfg.name_esp) {
            ImVec2 text_size = ImGui::CalcTextSize(ent.name);
            dl->AddText(ImVec2(head_screen.x - text_size.x * 0.5f, tl.y - text_size.y - 2.0f),
                        ImGui::ColorConvertFloat4ToU32(cfg.name_color), ent.name);
        }

        // Health bar ESP
        if (cfg.health_esp && ent.max_health > 0.0f) {
            float hp_frac = ent.health / ent.max_health;
            if (hp_frac < 0.0f) hp_frac = 0.0f;
            if (hp_frac > 1.0f) hp_frac = 1.0f;

            float bar_w = 3.0f;
            float bar_x = tl.x - bar_w - 3.0f;
            float bar_top = tl.y;
            float bar_bot = br.y;
            float bar_fill = bar_top + (bar_bot - bar_top) * (1.0f - hp_frac);

            // Background
            dl->AddRectFilled(ImVec2(bar_x, bar_top), ImVec2(bar_x + bar_w, bar_bot),
                              IM_COL32(0, 0, 0, 180));
            // Health fill (green → red gradient)
            ImU32 hp_color = IM_COL32(
                static_cast<int>((1.0f - hp_frac) * 255),
                static_cast<int>(hp_frac * 255), 0, 255);
            dl->AddRectFilled(ImVec2(bar_x, bar_fill), ImVec2(bar_x + bar_w, bar_bot), hp_color);
        }

        // Guard bar ESP
        if (cfg.guard_esp && ent.max_guard > 0.0f) {
            float gp_frac = ent.guard / ent.max_guard;
            if (gp_frac < 0.0f) gp_frac = 0.0f;
            if (gp_frac > 1.0f) gp_frac = 1.0f;

            float bar_w = 3.0f;
            float bar_x = br.x + 3.0f;
            float bar_top = tl.y;
            float bar_bot = br.y;
            float bar_fill = bar_top + (bar_bot - bar_top) * (1.0f - gp_frac);

            dl->AddRectFilled(ImVec2(bar_x, bar_top), ImVec2(bar_x + bar_w, bar_bot),
                              IM_COL32(0, 0, 0, 180));
            dl->AddRectFilled(ImVec2(bar_x, bar_fill), ImVec2(bar_x + bar_w, bar_bot),
                              IM_COL32(70, 170, 255, 230));
        }

        // Distance ESP
        if (cfg.distance_esp) {
            char dist_buf[16];
            std::snprintf(dist_buf, sizeof(dist_buf), "%.0fm", dist);
            ImVec2 dist_size = ImGui::CalcTextSize(dist_buf);
            dl->AddText(ImVec2(head_screen.x - dist_size.x * 0.5f, br.y + 2.0f),
                        IM_COL32(200, 200, 200, 220), dist_buf);
        }

        if (cfg.plus_ultra_esp) {
            char pu_buf[32];
            std::snprintf(pu_buf, sizeof(pu_buf), "PU %.0f", ent.plus_ultra);
            ImVec2 pu_size = ImGui::CalcTextSize(pu_buf);
            float y = br.y + (cfg.distance_esp ? 16.0f : 2.0f);
            ImU32 pu_col = ent.plus_ultra >= 100.0f ? IM_COL32(255, 215, 90, 230)
                                                    : IM_COL32(170, 170, 210, 220);
            dl->AddText(ImVec2(head_screen.x - pu_size.x * 0.5f, y), pu_col, pu_buf);
        }
    }
}

}  // namespace nova::esp
'''

_TPL_ADMIN_MENU_CPP = r'''#include "menu.hpp"
#include "generated_feature_catalog.hpp"
#include "imgui.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <windows.h>

namespace nova::menu {

struct KeybindOption {
  const char *label;
  int vk;
};

static constexpr KeybindOption kAimbotKeyOptions[] = {
    {"Right Mouse", VK_RBUTTON},
    {"Left Mouse", VK_LBUTTON},
    {"Mouse 4", VK_XBUTTON1},
    {"Mouse 5", VK_XBUTTON2},
    {"Left Shift", VK_LSHIFT},
    {"Left Alt", VK_LMENU},
    {"Q", 'Q'},
    {"E", 'E'},
    {"F", 'F'},
    {"X", 'X'},
    {"C", 'C'},
};

static int FindAimbotKeyIndex(int vk) {
  for (int i = 0; i < static_cast<int>(sizeof(kAimbotKeyOptions) /
                                       sizeof(kAimbotKeyOptions[0]));
       ++i) {
    if (kAimbotKeyOptions[i].vk == vk)
      return i;
  }
  return 0;
}

static void ApplyPremiumTheme() {
  ImGuiStyle &s = ImGui::GetStyle();
  s.WindowRounding = 12.0f;
  s.ChildRounding = 10.0f;
  s.FrameRounding = 8.0f;
  s.PopupRounding = 8.0f;
  s.ScrollbarRounding = 8.0f;
  s.GrabRounding = 8.0f;
  s.TabRounding = 8.0f;
  s.WindowPadding = ImVec2(20.0f, 20.0f);
  s.FramePadding = ImVec2(14.0f, 10.0f);
  s.ItemSpacing = ImVec2(12.0f, 12.0f);
  s.ItemInnerSpacing = ImVec2(10.0f, 8.0f);
  s.WindowBorderSize = 1.0f;
  s.FrameBorderSize = 1.0f;
  s.PopupBorderSize = 1.0f;

  auto &c = s.Colors;
  c[ImGuiCol_WindowBg] = ImVec4(0.06f, 0.06f, 0.09f, 0.96f);
  c[ImGuiCol_ChildBg] = ImVec4(0.09f, 0.09f, 0.12f, 0.70f);
  c[ImGuiCol_PopupBg] = ImVec4(0.08f, 0.08f, 0.11f, 0.98f);
  c[ImGuiCol_Border] = ImVec4(0.20f, 0.20f, 0.25f, 0.80f);
  c[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.40f);
  c[ImGuiCol_FrameBg] = ImVec4(0.12f, 0.12f, 0.17f, 0.80f);
  c[ImGuiCol_FrameBgHovered] = ImVec4(0.20f, 0.20f, 0.28f, 0.90f);
  c[ImGuiCol_FrameBgActive] = ImVec4(0.28f, 0.25f, 0.45f, 0.90f);

  // Vibrant Neon Violet Accents
  ImVec4 accent_base = ImVec4(0.50f, 0.20f, 0.95f, 1.0f);
  ImVec4 accent_hov = ImVec4(0.60f, 0.30f, 1.00f, 1.0f);
  ImVec4 accent_act = ImVec4(0.70f, 0.45f, 1.00f, 1.0f);

  c[ImGuiCol_TitleBg] = ImVec4(0.06f, 0.06f, 0.09f, 1.0f);
  c[ImGuiCol_TitleBgActive] = ImVec4(0.08f, 0.08f, 0.11f, 1.0f);
  c[ImGuiCol_TitleBgCollapsed] = ImVec4(0.06f, 0.06f, 0.09f, 0.51f);

  c[ImGuiCol_MenuBarBg] = ImVec4(0.09f, 0.09f, 0.12f, 1.0f);

  c[ImGuiCol_Tab] = ImVec4(0.12f, 0.12f, 0.16f, 1.0f);
  c[ImGuiCol_TabHovered] = accent_hov;
  c[ImGuiCol_TabActive] = accent_base;
  c[ImGuiCol_TabUnfocused] = ImVec4(0.12f, 0.12f, 0.16f, 1.0f);
  c[ImGuiCol_TabUnfocusedActive] = ImVec4(0.25f, 0.15f, 0.40f, 1.0f);

  c[ImGuiCol_Button] = ImVec4(0.16f, 0.16f, 0.22f, 1.0f);
  c[ImGuiCol_ButtonHovered] = accent_hov;
  c[ImGuiCol_ButtonActive] = accent_act;

  c[ImGuiCol_Header] = ImVec4(0.18f, 0.18f, 0.24f, 1.0f);
  c[ImGuiCol_HeaderHovered] = accent_hov;
  c[ImGuiCol_HeaderActive] = accent_act;

  c[ImGuiCol_Separator] = ImVec4(0.22f, 0.22f, 0.28f, 0.80f);
  c[ImGuiCol_SeparatorHovered] = accent_hov;
  c[ImGuiCol_SeparatorActive] = accent_act;

  c[ImGuiCol_CheckMark] = ImVec4(0.95f, 0.95f, 0.98f, 1.0f);
  c[ImGuiCol_SliderGrab] = accent_base;
  c[ImGuiCol_SliderGrabActive] = accent_act;

  c[ImGuiCol_Text] = ImVec4(0.95f, 0.95f, 0.98f, 1.0f);
  c[ImGuiCol_TextDisabled] = ImVec4(0.60f, 0.60f, 0.65f, 1.0f);
}

void Render(MenuState &state, bool driver_connected, unsigned long target_pid,
            unsigned long long module_base) {
  ApplyPremiumTheme();

  // Watermark
  if (state.show_watermark) {
    auto *dl = ImGui::GetBackgroundDrawList();
    dl->AddText(ImVec2(10, 10), IM_COL32(200, 150, 250, 180),
                "NOVA Core Template");
  }

  if (!state.visible)
    return;

  ImGui::SetNextWindowSize(ImVec2(520, 440), ImGuiCond_FirstUseEver);
  ImGui::Begin("NOVA", &state.visible, ImGuiWindowFlags_NoCollapse);

  if (ImGui::BeginTabBar("MainTabs")) {
    // ── Visuals Tab ──────────────────────────────────
    if (ImGui::BeginTabItem("Visuals")) {
      auto &cfg = state.esp_config;
      ImGui::Checkbox("ESP Enabled", &cfg.enabled);
      ImGui::Separator();

      if (cfg.enabled) {
        ImGui::Checkbox("Box ESP", &cfg.box_esp);
        if (cfg.box_esp) {
          ImGui::SameLine(200);
          const char *styles[] = {"Full", "Corner", "Rounded"};
          int style_idx = static_cast<int>(cfg.box_style);
          if (ImGui::Combo("Style", &style_idx, styles, 3))
            cfg.box_style = static_cast<nova::esp::BoxStyle>(style_idx);
          ImGui::ColorEdit4("Box Color", &cfg.box_color.x,
                            ImGuiColorEditFlags_NoInputs |
                                ImGuiColorEditFlags_AlphaBar);
        }
        ImGui::Checkbox("Name ESP", &cfg.name_esp);
        if (cfg.name_esp) {
          ImGui::SameLine(200);
          ImGui::ColorEdit4("Name Color", &cfg.name_color.x,
                            ImGuiColorEditFlags_NoInputs);
        }
        ImGui::Checkbox("Health Bar", &cfg.health_esp);
        ImGui::Checkbox("Armor Bar", &cfg.guard_esp);
        ImGui::Checkbox("Distance", &cfg.distance_esp);
        ImGui::Checkbox("Resource Bar", &cfg.plus_ultra_esp);
        ImGui::Checkbox("Show Teammates", &cfg.show_teammates);
        ImGui::Checkbox("Show Local Player", &cfg.show_local_player);
        ImGui::Checkbox("Team Colors", &cfg.use_team_colors);
        if (cfg.use_team_colors) {
          ImGui::ColorEdit4("Enemy Color", &cfg.enemy_color.x,
                            ImGuiColorEditFlags_NoInputs |
                                ImGuiColorEditFlags_AlphaBar);
          ImGui::ColorEdit4("Teammate Color", &cfg.teammate_color.x,
                            ImGuiColorEditFlags_NoInputs |
                                ImGuiColorEditFlags_AlphaBar);
        }
        ImGui::SliderFloat("Max Distance (m)", &cfg.max_distance, 50.0f,
                           2000.0f, "%.0f");
        ImGui::Separator();
        ImGui::Checkbox("Glow Outline", &cfg.glow_outline);
        if (cfg.glow_outline) {
          ImGui::TextDisabled("Glow requires game-specific struct writes.");
          ImGui::TextDisabled("Wire this in esp.cpp -> apply glow to entity.");
        }
      }
      ImGui::EndTabItem();
    }

    // ── Combat Tab ───────────────────────────────────
    if (ImGui::BeginTabItem("Combat")) {
      ImGui::Checkbox("Aimbot", &state.aimbot_enabled);
      if (state.aimbot_enabled) {
        ImGui::SliderFloat("FOV", &state.aimbot_fov, 1.0f, 30.0f, "%.1f deg");
        ImGui::SliderFloat("Smoothing", &state.aimbot_smooth, 1.0f, 20.0f,
                           "%.1f");
        const char *activation_modes[] = {"Hold", "Toggle"};
        int mode_idx = static_cast<int>(state.aimbot_activation_mode);
        if (ImGui::Combo("Activation Mode", &mode_idx, activation_modes, 2)) {
          state.aimbot_activation_mode =
              static_cast<AimbotActivationMode>(mode_idx);
          state.aimbot_toggled_on = false;
          state.aimbot_active = false;
        }

        int key_idx = FindAimbotKeyIndex(state.aimbot_key);
        if (ImGui::BeginCombo("Aimbot Key", kAimbotKeyOptions[key_idx].label)) {
          for (int i = 0; i < static_cast<int>(sizeof(kAimbotKeyOptions) /
                                               sizeof(kAimbotKeyOptions[0]));
               ++i) {
            const bool selected = (i == key_idx);
            if (ImGui::Selectable(kAimbotKeyOptions[i].label, selected)) {
              state.aimbot_key = kAimbotKeyOptions[i].vk;
              state.aimbot_toggled_on = false;
              state.aimbot_active = false;
              state.aimbot_was_down = false;
            }
            if (selected)
              ImGui::SetItemDefaultFocus();
          }
          ImGui::EndCombo();
        }

        ImGui::TextDisabled("Status: %s",
                            state.aimbot_active ? "ACTIVE" : "IDLE");
        ImGui::TextDisabled("Lower smooth = snappier. 1.0 = instant.");
      }
      ImGui::EndTabItem();
    }

    // ── Misc Tab ─────────────────────────────────────
    if (ImGui::BeginTabItem("Misc")) {
      ImGui::Text("Driver: %s", driver_connected ? "Connected" : "Not loaded");
      if (target_pid)
        ImGui::Text("PID: %lu  |  Base: 0x%llX", target_pid, module_base);
      else
        ImGui::TextDisabled("Not attached to any process.");
      ImGui::Separator();
      ImGui::Checkbox("Show FPS", &state.show_fps);
      ImGui::Checkbox("Show Watermark", &state.show_watermark);
      ImGui::Checkbox("Show Debug Panel", &state.show_debug_panel);
      if (state.show_fps)
        ImGui::Text("FPS: %.0f", ImGui::GetIO().Framerate);
      ImGui::Separator();
      ImGui::TextDisabled("Hotkeys: F3/INSERT toggle menu, HOME unloads NOVA");
      ImGui::TextDisabled("Debug panel is draggable while menu is open.");
      ImGui::TextDisabled("Game: %s", nova::template_data::kGameName);
      ImGui::TextDisabled("Engine: %s %s", nova::template_data::kEngine,
                          nova::template_data::kVersion);
      ImGui::EndTabItem();
    }

    // ── Config Tab ───────────────────────────────────
    if (ImGui::BeginTabItem("Config")) {
      ImGui::InputText("Config File", state.config_path,
                       sizeof(state.config_path));
      if (ImGui::Button("Save Config"))
        SaveConfig(state, state.config_path);
      ImGui::SameLine();
      if (ImGui::Button("Load Config"))
        LoadConfig(state, state.config_path);
      ImGui::Separator();
      ImGui::TextDisabled("Configs are saved as JSON for easy editing.");
      ImGui::EndTabItem();
    }

    ImGui::EndTabBar();
  }
  ImGui::End();
}

void Toggle(MenuState &state) { state.visible = !state.visible; }

void SaveConfig(const MenuState &state, const char *path) {
  // Minimal JSON config save
  std::ofstream f(path);
  if (!f.is_open())
    return;
  const auto &c = state.esp_config;
  f << "{\n";
  f << "  \"esp_enabled\": " << (c.enabled ? "true" : "false") << ",\n";
  f << "  \"box_esp\": " << (c.box_esp ? "true" : "false") << ",\n";
  f << "  \"name_esp\": " << (c.name_esp ? "true" : "false") << ",\n";
  f << "  \"health_esp\": " << (c.health_esp ? "true" : "false") << ",\n";
  f << "  \"guard_esp\": " << (c.guard_esp ? "true" : "false") << ",\n";
  f << "  \"distance_esp\": " << (c.distance_esp ? "true" : "false") << ",\n";
  f << "  \"plus_ultra_esp\": " << (c.plus_ultra_esp ? "true" : "false")
    << ",\n";
  f << "  \"show_teammates\": " << (c.show_teammates ? "true" : "false")
    << ",\n";
  f << "  \"show_local_player\": " << (c.show_local_player ? "true" : "false")
    << ",\n";
  f << "  \"use_team_colors\": " << (c.use_team_colors ? "true" : "false")
    << ",\n";
  f << "  \"glow_outline\": " << (c.glow_outline ? "true" : "false") << ",\n";
  f << "  \"show_debug_panel\": " << (state.show_debug_panel ? "true" : "false")
    << ",\n";
  f << "  \"box_style\": " << static_cast<int>(c.box_style) << ",\n";
  f << "  \"max_distance\": " << c.max_distance << ",\n";
  f << "  \"aimbot_enabled\": " << (state.aimbot_enabled ? "true" : "false")
    << ",\n";
  f << "  \"aimbot_fov\": " << state.aimbot_fov << ",\n";
  f << "  \"aimbot_smooth\": " << state.aimbot_smooth << ",\n";
  f << "  \"aimbot_activation_mode\": "
    << static_cast<int>(state.aimbot_activation_mode) << ",\n";
  f << "  \"aimbot_key\": " << state.aimbot_key << "\n";
  f << "}\n";
}

void LoadConfig(MenuState &state, const char *path) {
  std::ifstream f(path);
  if (!f.is_open())
    return;

  std::string src((std::istreambuf_iterator<char>(f)),
                  std::istreambuf_iterator<char>());
  auto &c = state.esp_config;

  auto parse_bool = [&](const char *key, bool &out) {
    std::string token = std::string("\"") + key + "\"";
    size_t p = src.find(token);
    if (p == std::string::npos)
      return;
    p = src.find(':', p);
    if (p == std::string::npos)
      return;
    p = src.find_first_not_of(" \t\r\n", p + 1);
    if (p == std::string::npos)
      return;
    if (src.compare(p, 4, "true") == 0)
      out = true;
    if (src.compare(p, 5, "false") == 0)
      out = false;
  };

  auto parse_int = [&](const char *key, int &out) {
    std::string token = std::string("\"") + key + "\"";
    size_t p = src.find(token);
    if (p == std::string::npos)
      return;
    p = src.find(':', p);
    if (p == std::string::npos)
      return;
    p = src.find_first_of("-0123456789", p + 1);
    if (p == std::string::npos)
      return;
    out = std::atoi(src.c_str() + p);
  };

  auto parse_float = [&](const char *key, float &out) {
    std::string token = std::string("\"") + key + "\"";
    size_t p = src.find(token);
    if (p == std::string::npos)
      return;
    p = src.find(':', p);
    if (p == std::string::npos)
      return;
    p = src.find_first_of("-0123456789.", p + 1);
    if (p == std::string::npos)
      return;
    out = std::strtof(src.c_str() + p, nullptr);
  };

  parse_bool("esp_enabled", c.enabled);
  parse_bool("box_esp", c.box_esp);
  parse_bool("name_esp", c.name_esp);
  parse_bool("health_esp", c.health_esp);
  parse_bool("guard_esp", c.guard_esp);
  parse_bool("distance_esp", c.distance_esp);
  parse_bool("plus_ultra_esp", c.plus_ultra_esp);
  parse_bool("show_teammates", c.show_teammates);
  parse_bool("show_local_player", c.show_local_player);
  parse_bool("use_team_colors", c.use_team_colors);
  parse_bool("glow_outline", c.glow_outline);
  parse_bool("show_debug_panel", state.show_debug_panel);
  parse_float("max_distance", c.max_distance);
  parse_bool("aimbot_enabled", state.aimbot_enabled);
  parse_float("aimbot_fov", state.aimbot_fov);
  parse_float("aimbot_smooth", state.aimbot_smooth);
  int activation_mode = static_cast<int>(state.aimbot_activation_mode);
  parse_int("aimbot_activation_mode", activation_mode);
  if (activation_mode < 0 || activation_mode > 1)
    activation_mode = 0;
  state.aimbot_activation_mode =
      static_cast<AimbotActivationMode>(activation_mode);
  parse_int("aimbot_key", state.aimbot_key);
  state.aimbot_key = kAimbotKeyOptions[FindAimbotKeyIndex(state.aimbot_key)].vk;
  state.aimbot_active = false;
  state.aimbot_toggled_on = false;
  state.aimbot_was_down = false;

  int style_idx = static_cast<int>(c.box_style);
  parse_int("box_style", style_idx);
  if (style_idx < 0 || style_idx > 2)
    style_idx = 1;
  c.box_style = static_cast<nova::esp::BoxStyle>(style_idx);
}

} // namespace nova::menu
'''

def _render_admin_readme(
    game_name: str,
    meta: Dict[str, str],
    features: List[FeatureCandidate],
    *,
    sdk_snapshot_files: int = 0,
    offsets_snapshot_files: int = 0,
) -> str:
    engine = meta.get("engine") or "unknown"
    version = meta.get("unity_version") or meta.get("ue_version") or "unknown"
    dump_stamp = meta.get("dump_timestamp") or datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return f"""# {game_name} — Admin-Mode

External overlay with ESP, tabbed menu, and kernel driver integration.
Generated from the currently selected dump and SDK output.

> **WARNING**: This is for educational/research use only. Do NOT use on online games
> with active anti-cheat. This template is designed for games with EAC DRM-version
> or BattlEye (non-invasive mode). It will NOT work with Vanguard (boot-start driver).

## Snapshot

- Engine: `{engine}`
- Version: `{version}`
- Dump timestamp: `{dump_stamp}`
- Recovered feature cards: `{len(features)}`

## Quick Start

1. **Run `Build.bat`** — auto-clones ImGui, configures CMake, builds Release .exe
2. **Run `Launch.bat`** as Administrator — loads the kernel driver
3. **Run `cheat_client.exe`** — overlay appears on top of the game
4. Press **INSERT** to toggle the menu

## What You Get

- **External overlay** — transparent, click-through, topmost DX11 window
- **ESP framework** — Box (Full/Corner/Rounded), Name, Health Bar, Distance
- **Tabbed menu** — Visuals, Combat (placeholder), Misc, Config
- **Kernel driver client** — stealth IPC via shared memory (MmCopyMemory + CR3)
- **Config save/load** — JSON-based settings persistence
- **Game data header** — seeded from your dump with struct offsets

## What You Need To Wire

The template gives you the full architecture: background reader thread, entity cache,
ESP, aimbot, and menu. UE offsets are auto-populated from your dump. You may need to:

1. **Verify offsets** in `generated_feature_catalog.hpp` — auto-extracted from the dump
2. **Tune actor filtering** in `reader_thread.cpp` — adjust mesh/instigator checks
3. **Add game-specific stats** — health/guard/team reads in the reader thread
4. **Glow Outline** — if the game supports it, write to the glow struct in `esp.cpp`

The reader thread handles the full UE pointer chain (GWorld → GameInstance →
LocalPlayers → PlayerController → Pawn → CameraManager) using scatter reads.

## Bundled Snapshot

- `snapshot/Offsets` — `{offsets_snapshot_files}` dump files
- `snapshot/SDK` — `{sdk_snapshot_files}` SDK headers

## Driver Notes

- External overlay only — no DLL injection, no hooks
- Memory reads via kernel driver (MmCopyMemory on physical pages)
- Shared memory IPC via GUID-named section — no IOCTLs, no device objects
- Compatible with EAC DRM-version, BattlEye (non-invasive)
- **NOT compatible with Vanguard (boot-start driver blocks driver mappers)**
- Requires: Secure Boot OFF, Core Isolation (HVCI) OFF, Administrator

## Detection Vector Compliance

See `docs/DETECTION_VECTORS.md` in this repository for details:
- Section 2: MmCopyMemory physical reads only
- Section 5: PE header wipe + module name wipe
- Section 8: GUID-based section name
- Section 9: Handle closed after MapViewOfFile
- Section 12: Batch reads, minimal polling
- Section 15: No debug strings in release build
"""

def _write_admin_mode_sources(
    src_dir: str,
    game_name: str,
    meta: Dict[str, str],
    features: List[FeatureCandidate],
    packages: List[Tuple[str, int]],
) -> None:

    with open(
        os.path.join(src_dir, "math.hpp"), "w", encoding="utf-8", newline="\n"
    ) as f:
        f.write(_TPL_ADMIN_MATH_HPP)

    with open(
        os.path.join(src_dir, "overlay.hpp"), "w", encoding="utf-8", newline="\n"
    ) as f:
        f.write(_TPL_ADMIN_OVERLAY_HPP)

    with open(
        os.path.join(src_dir, "overlay.cpp"), "w", encoding="utf-8", newline="\n"
    ) as f:
        f.write(_TPL_ADMIN_OVERLAY_CPP)

    with open(
        os.path.join(src_dir, "esp.hpp"), "w", encoding="utf-8", newline="\n"
    ) as f:
        f.write(_TPL_ADMIN_ESP_HPP)

    with open(
        os.path.join(src_dir, "esp.cpp"), "w", encoding="utf-8", newline="\n"
    ) as f:
        f.write(_TPL_ADMIN_ESP_CPP)

    with open(
        os.path.join(src_dir, "menu.hpp"), "w", encoding="utf-8", newline="\n"
    ) as f:
        f.write(_TPL_ADMIN_MENU_HPP)

    with open(
        os.path.join(src_dir, "menu.cpp"), "w", encoding="utf-8", newline="\n"
    ) as f:
        f.write(_TPL_ADMIN_MENU_CPP)

    with open(
        os.path.join(src_dir, "entity_cache.hpp"), "w", encoding="utf-8", newline="\n"
    ) as f:
        f.write(_TPL_ADMIN_ENTITY_CACHE_HPP)

    with open(
        os.path.join(src_dir, "reader_thread.hpp"), "w", encoding="utf-8", newline="\n"
    ) as f:
        f.write(_TPL_ADMIN_READER_THREAD_HPP)

    with open(
        os.path.join(src_dir, "reader_thread.cpp"), "w", encoding="utf-8", newline="\n"
    ) as f:
        f.write(_TPL_ADMIN_READER_THREAD_CPP)

    with open(
        os.path.join(src_dir, "main.cpp"), "w", encoding="utf-8", newline="\n"
    ) as f:
        f.write(_TPL_ADMIN_MAIN_CPP)

def generate_imgui_template(
    dump_dir: str,
    sdk_dir: str,
    dest_root: str,
    *,
    game_name: str = "",
    project_name: str = "",
    mode: str = "trainer",
) -> str:
    if not os.path.exists(os.path.join(dump_dir, "ClassesInfo.json")):
        raise FileNotFoundError(
            "ClassesInfo.json not found in the selected dump directory"
        )

    game_name = (
        game_name
        or os.path.basename(os.path.dirname(os.path.normpath(dump_dir)))
        or "dump"
    )
    project_stem = _safe_stem(project_name or f"{game_name}_trainer_workbench")
    project_dir = os.path.join(dest_root, project_stem)
    src_dir = os.path.join(project_dir, "src")
    data_dir = os.path.join(project_dir, "data")
    vendor_dir = os.path.join(project_dir, "third_party")
    snapshot_dir = os.path.join(project_dir, "snapshot")
    snapshot_offsets_dir = os.path.join(snapshot_dir, "Offsets")
    snapshot_sdk_dir = os.path.join(snapshot_dir, "SDK")
    bin_dir = os.path.join(project_dir, "bin")
    os.makedirs(src_dir, exist_ok=True)
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(vendor_dir, exist_ok=True)
    os.makedirs(snapshot_dir, exist_ok=True)
    os.makedirs(bin_dir, exist_ok=True)

    meta = _read_offsets_meta(dump_dir)
    features = _build_feature_catalog(dump_dir)
    packages = _build_package_summary(sdk_dir)
    engine_type = _detect_engine_type(meta)
    window_class = _window_class_for_engine(engine_type)
    ue_offsets = _extract_engine_offsets(dump_dir, engine_type) if mode == "admin" else {}
    offsets_snapshot_files = _copy_snapshot_tree(dump_dir, snapshot_offsets_dir)
    sdk_snapshot_files = _copy_snapshot_tree(sdk_dir, snapshot_sdk_dir)

    with open(
        os.path.join(project_dir, "CMakeLists.txt"), "w", encoding="utf-8", newline="\n"
    ) as handle:
        handle.write(_TPL_ADMIN_CMAKELISTS if mode == "admin" else _TPL_CMAKELISTS)
    with open(
        os.path.join(project_dir, "README.md"), "w", encoding="utf-8", newline="\n"
    ) as handle:
        if mode == "admin":
            handle.write(
                _render_admin_readme(
                    game_name,
                    meta,
                    features,
                    sdk_snapshot_files=sdk_snapshot_files,
                    offsets_snapshot_files=offsets_snapshot_files,
                )
            )
        else:
            handle.write(
                _render_template_readme(
                    game_name,
                    meta,
                    features,
                    sdk_snapshot_files=sdk_snapshot_files,
                    offsets_snapshot_files=offsets_snapshot_files,
                )
            )
    with open(
        os.path.join(vendor_dir, "README.md"), "w", encoding="utf-8", newline="\n"
    ) as handle:
        handle.write(_TPL_VENDOR_README)
    with open(
        os.path.join(src_dir, "main.cpp"), "w", encoding="utf-8", newline="\n"
    ) as handle:
        handle.write(_TPL_MAIN_CPP)
    with open(
        os.path.join(src_dir, "trainer_ui.hpp"), "w", encoding="utf-8", newline="\n"
    ) as handle:
        handle.write(_TPL_TRAINER_UI_HPP)
    with open(
        os.path.join(src_dir, "trainer_ui.cpp"), "w", encoding="utf-8", newline="\n"
    ) as handle:
        handle.write(_TPL_TRAINER_UI_CPP)
    with open(
        os.path.join(src_dir, "generated_feature_catalog.hpp"),
        "w",
        encoding="utf-8",
        newline="\n",
    ) as handle:
        handle.write(
            _render_generated_catalog_header(game_name, meta, features, packages,
                                             ue_offsets=ue_offsets,
                                             engine_type=engine_type,
                                             window_class=window_class)
        )
    with open(
        os.path.join(data_dir, "trainer_manifest.json"),
        "w",
        encoding="utf-8",
        newline="\n",
    ) as handle:
        json.dump(
            _render_manifest(game_name, meta, features, packages), handle, indent=2
        )
    with open(
        os.path.join(data_dir, "trainer_manifest.schema.json"),
        "w",
        encoding="utf-8",
        newline="\n",
    ) as handle:
        json.dump(_render_manifest_schema(), handle, indent=2)

    with open(
        os.path.join(src_dir, "driver.h"), "w", encoding="utf-8", newline="\n"
    ) as handle:
        handle.write(_TPL_DRIVER_H)
    with open(
        os.path.join(src_dir, "driver.cpp"), "w", encoding="utf-8", newline="\n"
    ) as handle:
        handle.write(_TPL_DRIVER_CPP)

    bin_src = os.path.join(_PROJECT_ROOT, "bin")
    for binary in ("gsd_mapper.exe", "wdfsvc64.sys"):
        src_path = os.path.join(bin_src, binary)
        if os.path.isfile(src_path):
            shutil.copy2(src_path, os.path.join(bin_dir, binary))
    with open(
        os.path.join(project_dir, "Launch.bat"), "w", encoding="utf-8", newline="\r\n"
    ) as handle:
        handle.write(_TPL_LAUNCH_BAT)

    with open(
        os.path.join(project_dir, "Build.bat"), "w", encoding="utf-8", newline="\r\n"
    ) as handle:
        handle.write(_TPL_BUILD_BAT)

    cloned = _try_clone_imgui(vendor_dir)
    if not cloned:
        pass

    if mode == "admin":
        _write_admin_mode_sources(src_dir, game_name, meta, features, packages)

    return project_dir
