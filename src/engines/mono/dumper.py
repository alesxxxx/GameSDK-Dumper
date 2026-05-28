
import glob
import os
from typing import Optional

from src.engines.mono.assembly_parser import parse_managed_dir
from src.engines.mono.mono_scanner import find_mono_module, find_root_domain
from src.engines.mono.executor import MonoExecutor
from src.core.models import SDKDump

def find_managed_dir(
    process_name: str,
    managed_path: Optional[str] = None,
    log=None,
) -> Optional[str]:
    if log is None:
        log = print

    if managed_path and os.path.isdir(managed_path):
        return os.path.abspath(managed_path)

    game_dir = process_name.replace(".exe", "")

    try:
        from src.engines.ue.detector import _find_exe_from_process
        exe_path = _find_exe_from_process(process_name)
        if exe_path:
            log(f"  [OK] Exe path: {exe_path}")
            exe_dir = os.path.dirname(exe_path)
            data_dir_name = os.path.basename(exe_path).replace(".exe", "") + "_Data"
            candidate = os.path.join(exe_dir, data_dir_name, "Managed")
            log(f"  Checking: {candidate}")
            if os.path.isdir(candidate):
                return os.path.abspath(candidate)

            if os.path.isdir(exe_dir):
                for item in os.listdir(exe_dir):
                    if item.endswith("_Data"):
                        candidate = os.path.join(exe_dir, item, "Managed")
                        log(f"  Checking: {candidate}")
                        if os.path.isdir(candidate):
                            return os.path.abspath(candidate)
        else:
            log(f"  [--] Could not resolve exe path for {process_name}")
    except Exception as e:
        log(f"  [--] Exe path resolution error: {e}")

    candidate = os.path.join("games", game_dir, "Managed")
    if os.path.isdir(candidate):
        return os.path.abspath(candidate)

    log(f"  Searching for Assembly-CSharp.dll recursively...")
    pattern = os.path.join("**", "*_Data", "Managed", "Assembly-CSharp.dll")
    matches = glob.glob(pattern, recursive=True)
    if matches:
        return os.path.abspath(os.path.dirname(matches[0]))

    pattern2 = os.path.join("**", "Managed", "Assembly-CSharp.dll")
    matches2 = glob.glob(pattern2, recursive=True)
    if matches2:
        return os.path.abspath(os.path.dirname(matches2[0]))

    log(
        f"[!!] Could not find Managed/ directory.\n"
        f"     Expected locations:\n"
        f"       - games/{game_dir}/Managed/\n"
        f"       - <game>_Data/Managed/\n"
        f"     Use --managed <path> to specify the directory explicitly."
    )
    return None

def dump_mono(
    handle: int,
    pid: int,
    process_name: str,
    managed_path: Optional[str] = None,
    progress_callback=None,
    log=None,
) -> SDKDump:
    if log is None:
        log = print

    log(f"  Finding Managed directory for {process_name}...")
    managed_dir = find_managed_dir(process_name, managed_path, log=log)
    if not managed_dir:
        log("[!!] Mono: Cannot proceed without Managed/ directory")
        return SDKDump()

    log(f"  [OK] Managed: {managed_dir}")
    log(f"  Parsing .NET assemblies from disk...")

    types = parse_managed_dir(managed_dir, log=log)
    if not types:
        log("  [!!] No types found in assemblies")
        return SDKDump()

    log(f"  [OK] {len(types)} types parsed from disk")

    log(f"  Finding Mono runtime in process memory...")
    mono_base, mono_size, mono_name = find_mono_module(pid)
    domain_ptr = 0

    if mono_base:
        log(f"  [OK] {mono_name}: 0x{mono_base:X} ({mono_size // 1024} KB)")
        domain_ptr = find_root_domain(handle, mono_base, mono_size)
        if domain_ptr:
            log(f"  [OK] Root domain: 0x{domain_ptr:X}")
        else:
            log(
                "  [--] Could not find Mono root domain.\n"
                "       Field offsets will be estimated (names still available)."
            )
    else:
        log(
            "  [--] Mono runtime module not found.\n"
            "       Dumping from disk metadata only (no field offsets)."
        )

    log(f"  Walking {len(types)} types...")
    executor = MonoExecutor(types, handle, domain_ptr, mono_base)
    dump = executor.walk_types(progress_callback=progress_callback, log=log)

    return dump


def dump_mono_walker(
    handle: int,
    pid: int,
    process_name: str,
    managed_path: Optional[str] = None,
    progress_callback=None,
) -> SDKDump:
    from src.engines.mono.walker import MonoWalker, MonoWalkResult
    from src.core.models import StructInfo, MemberInfo, EnumInfo

    walker = MonoWalker(handle, pid)
    if not walker.attach() or not walker.domain_ptr:
        print("[--] MonoWalker: Falling back to disk-based dump_mono()")
        return dump_mono(handle, pid, process_name, managed_path, progress_callback)

    result = walker.walk_all(read_fields=True, progress_callback=progress_callback)

    dump = SDKDump()
    dump.object_count = len(result.classes)

    _TYPE_SIZES = {
        "System.Boolean": 1, "System.Byte": 1, "System.SByte": 1,
        "System.Char": 2, "System.Int16": 2, "System.UInt16": 2,
        "System.Int32": 4, "System.UInt32": 4, "System.Single": 4,
        "System.Int64": 8, "System.UInt64": 8, "System.Double": 8,
        "System.IntPtr": 8, "System.String": 8,
        "bool": 1, "int": 4, "float": 4, "double": 8, "long": 8, "string": 8,
    }

    for cls in result.classes:
        if not cls.fields:
            continue

        members = []
        max_offset = 0
        for f in cls.fields:
            size = _TYPE_SIZES.get(f.name, 8)
            members.append(MemberInfo(
                name=f.name,
                offset=f.offset,
                size=size,
                type_name="MonoField",
            ))
            if f.offset + size > max_offset:
                max_offset = f.offset + size

        parent = cls.parent_name
        if parent in ("Object", "System.Object", "MonoBehaviour",
                      "ValueType", "System.ValueType"):
            parent = ""

        dump.structs.append(StructInfo(
            name=cls.name,
            full_name=cls.full_name,
            address=cls.class_ptr,
            size=max_offset if max_offset > 0 else len(cls.fields) * 8,
            super_name=parent,
            is_class=True,
            package=cls.namespace,
            members=members,
        ))

    return dump
