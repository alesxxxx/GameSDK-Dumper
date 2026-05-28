import math
import os
import struct
from typing import Dict, List, Optional


def _file_entropy(path: str, chunk_size: int = 8192) -> float:
    try:
        with open(path, "rb") as f:
            data = f.read(chunk_size)
    except OSError:
        return 0.0
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    length = len(data)
    for c in counts:
        if c == 0:
            continue
        p = c / length
        entropy -= p * math.log2(p)
    return entropy


def _detect_engine_from_disk(path: str) -> Dict:
    from src.core.pe_parser import (
        extract_ue_build_info,
        get_pe_sections,
        get_ue_version_from_pe,
        get_unity_version_from_pe,
        get_version_info,
        scan_strings_on_disk,
    )

    result = {
        "engine": "unknown",
        "engine_version": "",
        "confidence": "low",
        "method": "none",
        "details": {},
    }

    version_info = get_version_info(path)
    if version_info:
        result["details"]["version_info"] = version_info

    # UE detection
    ue_version = get_ue_version_from_pe(path)
    if ue_version:
        major = int(ue_version.split(".")[0])
        result["engine"] = "ue5" if major >= 5 else "ue4"
        result["engine_version"] = ue_version
        result["confidence"] = "high"
        result["method"] = "pe_version_info"
        return result

    ue_strings = scan_strings_on_disk(path, "++UE", ".rdata")
    if not ue_strings:
        ue_strings = scan_strings_on_disk(path, "UnrealEngine", ".rdata")
    if ue_strings:
        matched = ue_strings[0][1]
        info = extract_ue_build_info(matched)
        if info:
            result["engine"], result["engine_version"] = info
        else:
            result["engine"] = "ue5" if "UE5" in matched or "+5." in matched else "ue4"
        result["confidence"] = "high" if result["engine_version"] else "medium"
        result["method"] = "pe_string_scan"
        result["details"]["matched_string"] = matched
        return result

    # Unity detection
    unity_version = get_unity_version_from_pe(path)
    if unity_version:
        result["engine"] = "unity"
        result["engine_version"] = unity_version
        result["confidence"] = "high"
        result["method"] = "pe_version_info"
        return result

    # IL2CPP hint (GameAssembly.dll neighbor or il2cpp_data folder)
    file_dir = os.path.dirname(path)
    base_name = os.path.basename(path)
    neighbor_gameassembly = os.path.join(file_dir, "GameAssembly.dll")
    if os.path.isfile(neighbor_gameassembly):
        result["engine"] = "unity_il2cpp"
        result["confidence"] = "high"
        result["method"] = "neighbor_module"
        result["details"]["hint"] = "GameAssembly.dll found next to executable"
        return result

    # Source / Source 2 detection
    source_strings = scan_strings_on_disk(path, "ValveSource", ".rdata")
    if not source_strings:
        source_strings = scan_strings_on_disk(path, "Source2", ".rdata")
    if source_strings:
        matched = source_strings[0][1]
        result["engine"] = "source2" if "Source2" in matched else "source"
        result["confidence"] = "medium"
        result["method"] = "pe_string_scan"
        result["details"]["matched_string"] = matched
        return result

    # Name heuristic for UE shipping builds
    pname_lower = base_name.lower()
    if "shipping" in pname_lower or "win64" in pname_lower:
        result["engine"] = "ue_unknown"
        result["confidence"] = "low"
        result["method"] = "filename_heuristic"
        result["details"]["hint"] = "Win64-Shipping naming is common for UE4/UE5"
        return result

    return result


def _pe_imports(path: str) -> List[str]:
    try:
        import pefile
    except ImportError:
        return []
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        imports = []
        directory = getattr(pe, "DIRECTORY_ENTRY_IMPORT", None)
        if directory:
            for entry in directory:
                dll_name = entry.dll.decode("utf-8", errors="replace") if entry.dll else ""
                if dll_name:
                    imports.append(dll_name)
        return imports
    except Exception:
        return []


def _pe_exports(path: str, limit: int = 500) -> List[Dict]:
    try:
        import pefile
    except ImportError:
        return []
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        )
        exports = []
        directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if directory:
            for exp in directory.symbols:
                if exp.name:
                    exports.append({
                        "name": exp.name.decode("utf-8", errors="replace"),
                        "rva": int(exp.address),
                        "ordinal": int(exp.ordinal),
                    })
                if len(exports) >= limit:
                    break
        return exports
    except Exception:
        return []


def _pe_machine_type(path: str) -> str:
    try:
        with open(path, "rb") as f:
            dos = f.read(0x40)
            if len(dos) < 0x40 or dos[:2] != b"MZ":
                return "unknown"
            e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
            f.seek(e_lfanew + 4)
            machine = struct.unpack_from("<H", f.read(2))[0]
            mapping = {
                0x8664: "x64",
                0x14C: "x86",
                0xAA64: "ARM64",
            }
            return mapping.get(machine, f"0x{machine:04X}")
    except Exception:
        return "unknown"


def analyze_binary(path: str) -> Dict:
    from src.core.pe_parser import get_pe_sections

    path = os.path.abspath(path)
    if not os.path.isfile(path):
        return {"ok": False, "error": f"file not found: {path}"}

    sections = get_pe_sections(path)
    file_size = os.path.getsize(path)
    engine_info = _detect_engine_from_disk(path)
    imports = _pe_imports(path)
    exports = _pe_exports(path)

    # Derive compiler/linker hints from imports
    compiler_hint = "unknown"
    if any("vcruntime" in i.lower() for i in imports):
        compiler_hint = "msvc"
    elif any("libc" in i.lower() for i in imports):
        compiler_hint = "clang/gcc"

    is_dotnet = any(i.lower() == "mscoree.dll" for i in imports)

    return {
        "ok": True,
        "path": path,
        "module_name": os.path.basename(path),
        "file_size": file_size,
        "machine": _pe_machine_type(path),
        "entropy": round(_file_entropy(path), 3),
        "compiler_hint": compiler_hint,
        "is_dotnet": is_dotnet,
        "engine": engine_info,
        "sections": sections,
        "imports": imports,
        "export_count": len(exports),
        "exports": exports,
    }
