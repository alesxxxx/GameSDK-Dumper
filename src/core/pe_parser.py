
import ctypes
import ctypes.wintypes as wt
import os
import re
import struct
from typing import Dict, List, Optional, Tuple

_version = ctypes.WinDLL("version", use_last_error=True)

_version.GetFileVersionInfoSizeW.argtypes = [wt.LPCWSTR, ctypes.POINTER(wt.DWORD)]
_version.GetFileVersionInfoSizeW.restype = wt.DWORD

_version.GetFileVersionInfoW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p]
_version.GetFileVersionInfoW.restype = wt.BOOL

_version.VerQueryValueW.argtypes = [ctypes.c_void_p, wt.LPCWSTR, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wt.UINT)]
_version.VerQueryValueW.restype = wt.BOOL

def _get_version_string(filepath: str, key: str) -> Optional[str]:
    dummy = wt.DWORD(0)
    size = _version.GetFileVersionInfoSizeW(filepath, ctypes.byref(dummy))
    if size == 0:
        return None

    buf = ctypes.create_string_buffer(size)
    if not _version.GetFileVersionInfoW(filepath, 0, size, buf):
        return None

    lp_translate = ctypes.c_void_p()
    cb_translate = wt.UINT(0)
    if not _version.VerQueryValueW(buf, r"\VarFileInfo\Translation",
                                    ctypes.byref(lp_translate), ctypes.byref(cb_translate)):
        return None

    if cb_translate.value < 4:
        return None

    lang = ctypes.cast(lp_translate, ctypes.POINTER(ctypes.c_uint16))[0]
    codepage = ctypes.cast(lp_translate, ctypes.POINTER(ctypes.c_uint16))[1]

    sub_block = f"\\StringFileInfo\\{lang:04x}{codepage:04x}\\{key}"

    lp_value = ctypes.c_void_p()
    cb_value = wt.UINT(0)
    if not _version.VerQueryValueW(buf, sub_block, ctypes.byref(lp_value), ctypes.byref(cb_value)):
        return None

    if cb_value.value == 0:
        return None

    return ctypes.wstring_at(lp_value, cb_value.value - 1)

def get_version_info(filepath: str) -> Dict[str, str]:
    keys = [
        "ProductVersion", "FileVersion", "FileDescription",
        "ProductName", "CompanyName", "InternalName",
        "OriginalFilename", "LegalCopyright",
    ]
    result = {}
    for k in keys:
        val = _get_version_string(filepath, k)
        if val and val.strip():
            result[k] = val.strip()
    return result

def get_ue_version_from_pe(filepath: str) -> Optional[str]:
    info = get_version_info(filepath)

    for key in ("ProductVersion", "FileVersion", "FileDescription"):
        val = info.get(key, "")
        if not val:
            continue

        m = re.search(r'\+\+UE(\d)\+Release-(\d+\.\d+)', val)
        if m:
            return m.group(2)

        parts = val.split(".")
        if len(parts) >= 2:
            try:
                major = int(parts[0])
                minor = int(parts[1])
                if major in (4, 5) and 0 <= minor <= 99:
                    return f"{major}.{minor}"
            except ValueError:
                pass

        m = re.search(r'(?:UE|Unreal)[^\d]*(\d+\.\d+)', val)
        if m:
            return m.group(1)

    return None

_UNITY_VERSION_RE = re.compile(r"\b(20\d{2}\.\d+\.\d+(?:a|b|f|p|x)\d+)\b")
_UE_RELEASE_RE = re.compile(r"\+\+UE(?P<major>[45])\+Release-(?P<version>\d+\.\d+)", re.IGNORECASE)
_UE_TEXT_VERSION_RE = re.compile(
    r"(?:Unreal(?:\s+Engine)?|UE)\s*[-+_/]?\s*(?P<version>(?P<major>[45])\.\d+)",
    re.IGNORECASE,
)
_UE_MAJOR_HINT_RE = re.compile(r"(?:\+\+)?UE(?P<major>[45])\b", re.IGNORECASE)

def _extract_unity_version(text: str) -> Optional[str]:
    if not text:
        return None
    match = _UNITY_VERSION_RE.search(text)
    return match.group(1) if match else None

def extract_ue_build_info(text: str) -> Optional[Tuple[str, str]]:
    if not text:
        return None

    match = _UE_RELEASE_RE.search(text)
    if match:
        major = match.group("major")
        version = match.group("version")
        return ("ue5" if major == "5" else "ue4", version)

    match = _UE_TEXT_VERSION_RE.search(text)
    if match:
        major = match.group("major")
        version = match.group("version")
        return ("ue5" if major == "5" else "ue4", version)

    match = _UE_MAJOR_HINT_RE.search(text)
    if match:
        major = match.group("major")
        return ("ue5" if major == "5" else "ue4", "")

    return None

def _scan_file_for_unity_version(filepath: str, limit: int = 8 * 1024 * 1024) -> Optional[str]:
    try:
        with open(filepath, "rb") as f:
            data = f.read(limit)
    except OSError:
        return None

    try:
        text = data.decode("latin-1", errors="ignore")
    except Exception:
        return None
    return _extract_unity_version(text)

def get_unity_version_from_pe(filepath: str) -> Optional[str]:
    if not filepath or not os.path.isfile(filepath):
        return None

    info = get_version_info(filepath)
    for key in (
        "ProductVersion",
        "FileVersion",
        "FileDescription",
        "ProductName",
        "InternalName",
    ):
        value = info.get(key, "")
        version = _extract_unity_version(value)
        if version:
            return version

    version = _scan_file_for_unity_version(filepath)
    if version:
        return version

    file_dir = os.path.dirname(filepath)
    for neighbor in ("UnityPlayer.dll", os.path.basename(filepath)):
        neighbor_path = os.path.join(file_dir, neighbor)
        if not os.path.isfile(neighbor_path) or os.path.normcase(neighbor_path) == os.path.normcase(filepath):
            continue

        info = get_version_info(neighbor_path)
        for key in (
            "ProductVersion",
            "FileVersion",
            "FileDescription",
            "ProductName",
            "InternalName",
        ):
            value = info.get(key, "")
            version = _extract_unity_version(value)
            if version:
                return version

        version = _scan_file_for_unity_version(neighbor_path)
        if version:
            return version

    return None

def get_pe_sections(filepath: str) -> List[Dict]:
    sections = []

    with open(filepath, "rb") as f:
        dos_magic = f.read(2)
        if dos_magic != b"MZ":
            return sections

        f.seek(0x3C)
        e_lfanew = struct.unpack_from("<I", f.read(4))[0]

        f.seek(e_lfanew)
        pe_sig = f.read(4)
        if pe_sig != b"PE\x00\x00":
            return sections

        coff = f.read(20)
        machine = struct.unpack_from("<H", coff, 0)[0]
        num_sections = struct.unpack_from("<H", coff, 2)[0]
        optional_header_size = struct.unpack_from("<H", coff, 16)[0]

        f.seek(e_lfanew + 4 + 20 + optional_header_size)

        for _ in range(num_sections):
            sec_data = f.read(40)
            if len(sec_data) < 40:
                break

            name_bytes = sec_data[0:8]
            name = name_bytes.split(b"\x00")[0].decode("ascii", errors="replace")
            virtual_size = struct.unpack_from("<I", sec_data, 8)[0]
            virtual_address = struct.unpack_from("<I", sec_data, 12)[0]
            raw_size = struct.unpack_from("<I", sec_data, 16)[0]
            raw_offset = struct.unpack_from("<I", sec_data, 20)[0]
            characteristics = struct.unpack_from("<I", sec_data, 36)[0]

            sections.append({
                "name": name,
                "virtual_address": virtual_address,
                "virtual_size": virtual_size,
                "raw_offset": raw_offset,
                "raw_size": raw_size,
                "characteristics": characteristics,
                "executable": bool(characteristics & 0x20000000),
                "writable": bool(characteristics & 0x80000000),
                "readable": bool(characteristics & 0x40000000),
            })

    return sections

def get_pe_rdata_data_scan_ranges(handle: int, module_base: int) -> List[Tuple[int, int]]:
    from src.core.memory import read_bytes

    dos = read_bytes(handle, module_base, 0x40)
    if len(dos) < 0x40 or dos[:2] != b"MZ":
        return []

    e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
    pe_sig = read_bytes(handle, module_base + e_lfanew, 4)
    if len(pe_sig) < 4 or pe_sig != b"PE\x00\x00":
        return []

    coff = read_bytes(handle, module_base + e_lfanew + 4, 20)
    if len(coff) < 20:
        return []
    num_sections = struct.unpack_from("<H", coff, 2)[0]
    opt_header_size = struct.unpack_from("<H", coff, 16)[0]

    sec_table_off = e_lfanew + 4 + 20 + opt_header_size
    sec_table = read_bytes(handle, module_base + sec_table_off, num_sections * 40)
    if len(sec_table) < num_sections * 40:
        return []

    ranges: List[Tuple[int, int]] = []
    for i in range(num_sections):
        off = i * 40
        sec_data = sec_table[off : off + 40]
        name_bytes = sec_data[0:8]
        name = name_bytes.split(b"\x00")[0].decode("ascii", errors="replace")
        virtual_size = struct.unpack_from("<I", sec_data, 8)[0]
        virtual_address = struct.unpack_from("<I", sec_data, 12)[0]
        if name not in (".rdata", ".data"):
            continue
        if virtual_size == 0:
            continue
        start = module_base + virtual_address
        end = start + virtual_size
        ranges.append((start, end))

    return ranges

def get_pe_text_scan_ranges(handle: int, module_base: int) -> List[Tuple[int, int]]:
    from src.core.memory import read_bytes

    dos = read_bytes(handle, module_base, 0x40)
    if len(dos) < 0x40 or dos[:2] != b"MZ":
        return []

    e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
    pe_sig = read_bytes(handle, module_base + e_lfanew, 4)
    if len(pe_sig) < 4 or pe_sig != b"PE\x00\x00":
        return []

    coff = read_bytes(handle, module_base + e_lfanew + 4, 20)
    if len(coff) < 20:
        return []
    num_sections = struct.unpack_from("<H", coff, 2)[0]
    opt_header_size = struct.unpack_from("<H", coff, 16)[0]

    sec_table_off = e_lfanew + 4 + 20 + opt_header_size
    sec_table = read_bytes(handle, module_base + sec_table_off, num_sections * 40)
    if len(sec_table) < num_sections * 40:
        return []

    ranges: List[Tuple[int, int]] = []
    for i in range(num_sections):
        off = i * 40
        sec_data = sec_table[off : off + 40]
        name_bytes = sec_data[0:8]
        name = name_bytes.split(b"\x00")[0].decode("ascii", errors="replace")
        virtual_size = struct.unpack_from("<I", sec_data, 8)[0]
        virtual_address = struct.unpack_from("<I", sec_data, 12)[0]
        characteristics = struct.unpack_from("<I", sec_data, 36)[0]
        
        if ".text" not in name and not (characteristics & 0x20000000):
            continue
        if virtual_size == 0:
            continue
        start = module_base + virtual_address
        end = start + virtual_size
        ranges.append((start, end))

    return ranges

def get_image_base(filepath: str) -> int:
    with open(filepath, "rb") as f:
        magic = f.read(2)
        if magic != b"MZ":
            return 0

        f.seek(0x3C)
        e_lfanew = struct.unpack_from("<I", f.read(4))[0]

        f.seek(e_lfanew)
        if f.read(4) != b"PE\x00\x00":
            return 0

        f.seek(e_lfanew + 4 + 20)

        opt_magic = struct.unpack_from("<H", f.read(2))[0]

        if opt_magic == 0x20B:
            f.seek(e_lfanew + 4 + 20 + 24)
            return struct.unpack_from("<Q", f.read(8))[0]
        elif opt_magic == 0x10B:
            f.seek(e_lfanew + 4 + 20 + 28)
            return struct.unpack_from("<I", f.read(4))[0]

    return 0

def get_pe_timestamp(filepath: str) -> int:
    try:
        with open(filepath, "rb") as f:
            if f.read(2) != b"MZ":
                return 0
            f.seek(0x3C)
            e_lfanew = struct.unpack_from("<I", f.read(4))[0]
            f.seek(e_lfanew)
            if f.read(4) != b"PE\x00\x00":
                return 0
            coff = f.read(20)
            if len(coff) < 8:
                return 0
            return struct.unpack_from("<I", coff, 4)[0]
    except (OSError, struct.error):
        return 0

def get_pe_export_names(filepath: str) -> List[str]:
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except OSError:
        return []

    if len(data) < 0x40 or data[:2] != b"MZ":
        return []

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 4 > len(data) or data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
        return []

    coff_off = e_lfanew + 4
    if coff_off + 20 > len(data):
        return []
    opt_size = struct.unpack_from("<H", data, coff_off + 16)[0]

    opt_off = coff_off + 20
    if opt_off + 4 > len(data):
        return []
    opt_magic = struct.unpack_from("<H", data, opt_off)[0]

    if opt_magic == 0x20B:
        dd_off = opt_off + 112
    elif opt_magic == 0x10B:
        dd_off = opt_off + 96
    else:
        return []

    if dd_off + 8 > len(data):
        return []
    export_rva, export_size = struct.unpack_from("<II", data, dd_off)
    if export_rva == 0 or export_size == 0:
        return []

    sec_table_off = opt_off + opt_size
    num_sections = struct.unpack_from("<H", data, coff_off + 2)[0]

    def rva_to_offset(rva: int) -> int:
        for si in range(num_sections):
            base = sec_table_off + si * 40
            if base + 40 > len(data):
                break
            va   = struct.unpack_from("<I", data, base + 12)[0]
            vsz  = struct.unpack_from("<I", data, base + 8)[0]
            roff = struct.unpack_from("<I", data, base + 20)[0]
            if va <= rva < va + vsz:
                return roff + (rva - va)
        return -1

    exp_off = rva_to_offset(export_rva)
    if exp_off < 0 or exp_off + 40 > len(data):
        return []

    num_names      = struct.unpack_from("<I", data, exp_off + 24)[0]
    names_rva      = struct.unpack_from("<I", data, exp_off + 32)[0]
    names_file_off = rva_to_offset(names_rva)
    if names_file_off < 0 or num_names > 1_000_000:
        return []

    names: List[str] = []
    for i in range(num_names):
        ptr_off = names_file_off + i * 4
        if ptr_off + 4 > len(data):
            break
        name_rva = struct.unpack_from("<I", data, ptr_off)[0]
        name_off = rva_to_offset(name_rva)
        if name_off < 0 or name_off >= len(data):
            continue
        end = data.index(b"\x00", name_off) if b"\x00" in data[name_off:name_off+256] else name_off
        names.append(data[name_off:end].decode("ascii", errors="replace"))

    return names

def scan_strings_on_disk(filepath: str, search: str, section_name: str = ".rdata",
                         max_results: int = 10) -> List[Tuple[int, str]]:
    sections = get_pe_sections(filepath)
    target_sec = None
    for s in sections:
        if s["name"] == section_name:
            target_sec = s
            break

    if not target_sec:
        return []

    results = []
    search_lower = search.lower()

    with open(filepath, "rb") as f:
        f.seek(target_sec["raw_offset"])
        data = f.read(target_sec["raw_size"])

    i = 0
    while i < len(data) and len(results) < max_results:
        if 0x20 <= data[i] < 0x7F:
            start = i
            while i < len(data) and 0x20 <= data[i] < 0x7F:
                i += 1
            if i < len(data) and data[i] == 0x00:
                length = i - start
                if length >= 4:
                    text = data[start:i].decode("ascii", errors="replace")
                    if search_lower in text.lower():
                        rva = target_sec["virtual_address"] + start
                        results.append((rva, text))
        i += 1

    return results
