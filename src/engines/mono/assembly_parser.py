
import importlib.util
import os
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

@dataclass
class FieldInfo:
    name: str
    type_name: str
    token: int = 0

@dataclass
class MethodInfo:
    name: str
    return_type: str
    token: int = 0

@dataclass
class TypeInfo:
    name: str
    namespace: str
    full_name: str
    parent_name: str = ""
    is_enum: bool = False
    is_class: bool = True
    fields: List[FieldInfo] = field(default_factory=list)
    methods: List[MethodInfo] = field(default_factory=list)
    enum_values: List[Tuple[str, int]] = field(default_factory=list)

_HAS_DNFILE = importlib.util.find_spec("dnfile") is not None

def _parse_with_dnfile(path: str, log=None) -> List[TypeInfo]:
    if log is None: log = print
    import dnfile

    def _get_index(val) -> Optional[int]:
        if val is None:
            return None
        if isinstance(val, int):
            return val
        if hasattr(val, "row_index"):
            return val.row_index
        if hasattr(val, "value"):
            return val.value
        if hasattr(val, "index"):
            return val.index
        try:
            return int(val)
        except Exception:
            try:
                return int(getattr(val, "__int__")())
            except Exception:
                pass
        return None

    pe = dnfile.dnPE(path)
    types: List[TypeInfo] = []

    if not hasattr(pe, "net") or pe.net is None:
        return types
    if not hasattr(pe.net, "mdtables") or pe.net.mdtables is None:
        return types

    td_table = getattr(pe.net.mdtables, "TypeDef", None)
    if td_table is None:
        return types

    fd_table = getattr(pe.net.mdtables, "Field", None)
    md_table = getattr(pe.net.mdtables, "MethodDef", None)

    td_rows = list(td_table)
    fd_rows = list(fd_table) if fd_table else []
    md_rows = list(md_table) if md_table else []

    _logged_fieldlist_type = False
    for i, row in enumerate(td_rows):
        name = str(getattr(row, "TypeName", "")) or ""
        namespace = str(getattr(row, "TypeNamespace", "")) or ""
        full_name = f"{namespace}.{name}" if namespace else name

        if not name or name.startswith("<") or name == "<Module>":
            continue

        parent_name = ""
        extends = getattr(row, "Extends", None)
        if extends and hasattr(extends, "row"):
            parent_row = extends.row
            if parent_row and hasattr(parent_row, "TypeName"):
                parent_name = str(parent_row.TypeName)

        is_enum = parent_name == "Enum" or parent_name == "System.Enum"

        # ---------------- Fields ----------------
        fields = []
        enum_values = []
        
        field_list_obj = getattr(row, "FieldList", None)
        if not _logged_fieldlist_type:
            _logged_fieldlist_type = True
            try:
                log(f"  FieldList type: {type(field_list_obj).__name__}")
                log(f"    is_list={isinstance(field_list_obj, list)}")
                log(f"    has_iter={hasattr(field_list_obj, '__iter__')}")
                log(f"    has_row_index={hasattr(field_list_obj, 'row_index')}")
                log(f"    has_value={hasattr(field_list_obj, 'value')}")
                log(f"    has_table={hasattr(field_list_obj, 'table')}")
                log(f"    repr={repr(field_list_obj)[:200]}")
                log(f"    dir={[a for a in dir(field_list_obj) if not a.startswith('_')]}")
            except Exception:
                pass
        if isinstance(field_list_obj, list) or (hasattr(field_list_obj, "__iter__") and not hasattr(field_list_obj, "row_index") and not isinstance(field_list_obj, str) and not hasattr(field_list_obj, "value") and not hasattr(field_list_obj, "table")):
            # Native dnfile resolved list of Field rows or indices
            for fi, fd_obj in enumerate(field_list_obj):
                fd_row = fd_obj
                if hasattr(fd_obj, "row_index") and not hasattr(fd_obj, "Name"):
                    # Elements are MDTableIndex references, dereference them
                    actual_idx = fd_obj.row_index - 1
                    if 0 <= actual_idx < len(fd_rows):
                        fd_row = fd_rows[actual_idx]
                elif isinstance(fd_obj, int):
                    actual_idx = fd_obj - 1
                    if 0 <= actual_idx < len(fd_rows):
                        fd_row = fd_rows[actual_idx]

                fname = str(getattr(fd_row, "Name", "")) or ""
                if not fname:
                    continue
                ftype = _get_field_type_str(fd_row)
                fields.append(FieldInfo(name=fname, type_name=ftype))

                if is_enum and fname != "value__":
                    const_val = getattr(fd_row, "Constant", None)
                    if const_val is not None:
                        try:
                            enum_values.append((fname, int(const_val)))
                        except (TypeError, ValueError):
                            enum_values.append((fname, fi))
                    else:
                        enum_values.append((fname, fi))
        else:
            # Fallback to index-based for older dnfile or unresolved references
            field_start = getattr(row, "FieldList", None)
            start_num = _get_index(field_start)
            if start_num is not None:
                f_start_idx = start_num - 1
            else:
                f_start_idx = len(fd_rows)

            f_end_idx = len(fd_rows)
            for j in range(i + 1, len(td_rows)):
                nxt = getattr(td_rows[j], "FieldList", None)
                nxt_num = _get_index(nxt)
                if nxt_num is not None:
                    f_end_idx = nxt_num - 1
                    break

            for fi in range(f_start_idx, min(f_end_idx, len(fd_rows))):
                fd_row = fd_rows[fi]
                fname = str(getattr(fd_row, "Name", "")) or ""
                if not fname:
                    continue
                ftype = _get_field_type_str(fd_row)
                fields.append(FieldInfo(name=fname, type_name=ftype))

                if is_enum and fname != "value__":
                    const_val = getattr(fd_row, "Constant", None)
                    if const_val is not None:
                        try:
                            enum_values.append((fname, int(const_val)))
                        except (TypeError, ValueError):
                            enum_values.append((fname, fi - f_start_idx))
                    else:
                        enum_values.append((fname, fi - f_start_idx))

        # ---------------- Methods ----------------
        methods = []
        method_list_obj = getattr(row, "MethodList", None)
        if isinstance(method_list_obj, list) or (hasattr(method_list_obj, "__iter__") and not hasattr(method_list_obj, "row_index") and not isinstance(method_list_obj, str) and not hasattr(method_list_obj, "value")):
            # Native dnfile resolved list of Method rows or indices
            for md_obj in method_list_obj:
                md_row = md_obj
                if hasattr(md_obj, "row_index") and not hasattr(md_obj, "Name"):
                    actual_idx = md_obj.row_index - 1
                    if 0 <= actual_idx < len(md_rows):
                        md_row = md_rows[actual_idx]
                elif isinstance(md_obj, int):
                    actual_idx = md_obj - 1
                    if 0 <= actual_idx < len(md_rows):
                        md_row = md_rows[actual_idx]

                mname = str(getattr(md_row, "Name", "")) or ""
                if mname:
                    methods.append(MethodInfo(name=mname, return_type=""))
        else:
            method_start = getattr(row, "MethodList", None)
            start_m_num = _get_index(method_start)
            if start_m_num is not None:
                m_start_idx = start_m_num - 1
            else:
                m_start_idx = len(md_rows)

            m_end_idx = len(md_rows)
            for j in range(i + 1, len(td_rows)):
                nxt = getattr(td_rows[j], "MethodList", None)
                nxt_num = _get_index(nxt)
                if nxt_num is not None:
                    m_end_idx = nxt_num - 1
                    break

            for mi in range(m_start_idx, min(m_end_idx, len(md_rows))):
                md_row = md_rows[mi]
                mname = str(getattr(md_row, "Name", "")) or ""
                if mname:
                    methods.append(MethodInfo(name=mname, return_type=""))


        is_class = parent_name not in ("ValueType", "Enum", "System.ValueType", "System.Enum")

        types.append(TypeInfo(
            name=name,
            namespace=namespace,
            full_name=full_name,
            parent_name=parent_name,
            is_enum=is_enum,
            is_class=is_class,
            fields=fields,
            methods=methods,
            enum_values=enum_values,
        ))

    return types

def _get_field_type_str(fd_row) -> str:
    sig = getattr(fd_row, "Signature", None)
    if sig and hasattr(sig, "Type") and sig.Type:
        return str(sig.Type)
    return "Unknown"

def _parse_manual(path: str) -> List[TypeInfo]:
    with open(path, "rb") as f:
        data = f.read()

    if len(data) < 0x80 or data[:2] != b"MZ":
        return []

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 4 > len(data) or data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
        return []

    coff_off = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff_off + 2)[0]
    opt_header_size = struct.unpack_from("<H", data, coff_off + 16)[0]

    opt_off = coff_off + 20
    opt_magic = struct.unpack_from("<H", data, opt_off)[0]
    if opt_magic == 0x20B:
        dd_offset = opt_off + 112 + 14 * 8
    elif opt_magic == 0x10B:
        dd_offset = opt_off + 96 + 14 * 8
    else:
        return []

    if dd_offset + 8 > len(data):
        return []

    cli_rva, cli_size = struct.unpack_from("<II", data, dd_offset)
    if cli_rva == 0:
        return []

    sec_off = coff_off + 20 + opt_header_size
    sections = []
    for i in range(num_sections):
        so = sec_off + i * 40
        if so + 40 > len(data):
            break
        vsize = struct.unpack_from("<I", data, so + 8)[0]
        va = struct.unpack_from("<I", data, so + 12)[0]
        raw_size = struct.unpack_from("<I", data, so + 16)[0]
        raw_off = struct.unpack_from("<I", data, so + 20)[0]
        sections.append((va, vsize, raw_off, raw_size))

    def rva_to_offset(rva: int) -> int:
        for va, vs, ro, rs in sections:
            if va <= rva < va + max(vs, rs):
                return ro + (rva - va)
        return 0

    cli_off = rva_to_offset(cli_rva)
    if cli_off == 0 or cli_off + 72 > len(data):
        return []

    meta_rva = struct.unpack_from("<I", data, cli_off + 8)[0]
    meta_size = struct.unpack_from("<I", data, cli_off + 12)[0]
    meta_off = rva_to_offset(meta_rva)
    if meta_off == 0 or meta_off + meta_size > len(data):
        return []

    if data[meta_off:meta_off + 4] != b"BSJB":
        return []

    ver_len = struct.unpack_from("<I", data, meta_off + 12)[0]
    ver_len_aligned = (ver_len + 3) & ~3
    flags = struct.unpack_from("<H", data, meta_off + 16 + ver_len_aligned)[0]
    num_streams = struct.unpack_from("<H", data, meta_off + 18 + ver_len_aligned)[0]

    streams = {}
    stream_pos = meta_off + 20 + ver_len_aligned
    for _ in range(num_streams):
        if stream_pos + 8 > len(data):
            break
        s_off = struct.unpack_from("<I", data, stream_pos)[0]
        s_size = struct.unpack_from("<I", data, stream_pos + 4)[0]
        name_start = stream_pos + 8
        name_end = data.find(b"\x00", name_start, name_start + 32)
        if name_end < 0:
            break
        s_name = data[name_start:name_end].decode("ascii", errors="replace")
        streams[s_name] = (meta_off + s_off, s_size)
        name_total = name_end - name_start + 1
        name_total_aligned = (name_total + 3) & ~3
        stream_pos = name_start + name_total_aligned

    strings_off, strings_size = streams.get("#Strings", (0, 0))
    tilde_off, tilde_size = streams.get("#~", (0, 0))
    if not strings_off or not tilde_off:
        return []

    def read_string(idx: int) -> str:
        if idx < 0 or strings_off + idx >= len(data):
            return ""
        end = data.find(b"\x00", strings_off + idx)
        if end < 0:
            return ""
        return data[strings_off + idx:end].decode("utf-8", errors="replace")

    if tilde_off + 24 > len(data):
        return []

    heap_sizes = data[tilde_off + 6]
    string_idx_size = 4 if (heap_sizes & 0x01) else 2
    guid_idx_size = 4 if (heap_sizes & 0x02) else 2
    blob_idx_size = 4 if (heap_sizes & 0x04) else 2

    valid_mask = struct.unpack_from("<Q", data, tilde_off + 8)[0]
    sorted_mask = struct.unpack_from("<Q", data, tilde_off + 16)[0]

    row_counts = {}
    row_pos = tilde_off + 24
    for table_id in range(64):
        if valid_mask & (1 << table_id):
            if row_pos + 4 > len(data):
                break
            row_counts[table_id] = struct.unpack_from("<I", data, row_pos)[0]
            row_pos += 4

    td_count = row_counts.get(0x02, 0)
    fd_count = row_counts.get(0x04, 0)

    if td_count == 0:
        return []

    typedef_or_ref_size = 2
    field_idx_size = 2 if fd_count < 0x10000 else 4
    method_idx_size = 2 if row_counts.get(0x06, 0) < 0x10000 else 4

    td_row_size = 4 + string_idx_size + string_idx_size + typedef_or_ref_size + field_idx_size + method_idx_size
    fd_row_size = 2 + string_idx_size + blob_idx_size

    table_data_pos = row_pos

    for table_id in range(0x02):
        if table_id in row_counts:
            pass

    types = []
    print(
        f"[DEBUG] Mono: manual .NET parser found {td_count} types, "
        f"{fd_count} fields (install 'dnfile' for full parsing)"
    )

    return types

def parse_assembly(path: str, log=None) -> List[TypeInfo]:
    if log is None: log = print
    if _HAS_DNFILE:
        try:
            return _parse_with_dnfile(path, log=log)
        except Exception as e:
            try:
                import traceback
                log(f"  [!!] dnfile failed for {path}: {e}")
                log(f"  {traceback.format_exc()}")
            except Exception:
                log(f"[DEBUG] Mono: dnfile parse failed for {path}: {e}")
            return _parse_manual(path)
    return _parse_manual(path)

def parse_managed_dir(managed_dir: str, game_only: bool = True, log=None) -> List[TypeInfo]:
    if log is None:
        log = print
    all_types: List[TypeInfo] = []

    if not _HAS_DNFILE:
        try:
            import tkinter.messagebox
            tkinter.messagebox.showerror(
                "Dependency Missing",
                "The 'dnfile' python package is strictly required to parse Mono assemblies.\n\n"
                "Please run 'pip install dnfile' in your terminal, or re-run Build.bat to bundle it automatically."
            )
        except Exception:
            pass
        log("[!!] FATAL: dnfile not installed! Cannot parse managed .NET assemblies.")
        return all_types

    if not os.path.isdir(managed_dir):
        log(f"[!!] Managed directory not found: {managed_dir}")
        return all_types

    priority = ["Assembly-CSharp.dll", "Assembly-CSharp-firstpass.dll"]
    dll_files = []
    for p in priority:
        fp = os.path.join(managed_dir, p)
        if os.path.isfile(fp):
            dll_files.append(fp)

    if not game_only:
        skip_prefixes = ("System.", "Unity.", "UnityEngine.", "mscorlib", "Mono.",
                         "netstandard", "Microsoft.", "Newtonsoft.")
        for f in sorted(os.listdir(managed_dir)):
            if not f.endswith(".dll"):
                continue
            if any(f.startswith(p) for p in skip_prefixes):
                continue
            fp = os.path.join(managed_dir, f)
            if fp not in dll_files:
                dll_files.append(fp)

    if not dll_files:
        log(f"[!!] No Assembly-CSharp.dll found in {managed_dir}")
        all_dlls = [f for f in os.listdir(managed_dir) if f.endswith(".dll")]
        log(f"  Available DLLs ({len(all_dlls)}): {', '.join(all_dlls[:10])}{'...' if len(all_dlls) > 10 else ''}")
        return all_types

    for fp in dll_files:
        basename = os.path.basename(fp)
        size_mb = os.path.getsize(fp) / 1024 / 1024
        log(f"  Parsing {basename} ({size_mb:.1f} MB)...")
        try:
            types = parse_assembly(fp, log=log)
            if types:
                log(f"  [OK] {basename}: {len(types)} types")
                all_types.extend(types)
            else:
                log(f"  [--] {basename}: 0 types returned")
        except Exception as e:
            import traceback
            log(f"  [!!] {basename}: {e}")
            log(f"  {traceback.format_exc()}")

    return all_types

