
import struct
import time
from typing import List, Tuple, Optional

from src.core.memory import read_bytes, read_uint64, read_uint32, read_int32
from src.core.scanner import scan_pattern, resolve_rip
from src.core.debug import dbg

def _parse_pe_sections(handle: int, base: int) -> List[Tuple[str, int, int, int]]:
    hdr = read_bytes(handle, base, 0x1000)
    if not hdr or len(hdr) < 0x100:
        return []
    try:
        e_lfanew = struct.unpack_from('<I', hdr, 0x3C)[0]
        if e_lfanew > 0x800 or e_lfanew + 24 > len(hdr):
            return []
        if hdr[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
            return []
        num_sections = struct.unpack_from('<H', hdr, e_lfanew + 6)[0]
        opt_hdr_size = struct.unpack_from('<H', hdr, e_lfanew + 20)[0]
        sections_start = e_lfanew + 24 + opt_hdr_size
        
        machine_type = struct.unpack_from('<H', hdr, e_lfanew + 4)[0]
        is_32bit = (machine_type == 0x014C)
        
        from src.core.memory import set_architecture
        set_architecture(is_32bit)

        needed = sections_start + num_sections * 40
        if needed > len(hdr):
            hdr = read_bytes(handle, base, needed) or hdr

        sections = []
        for i in range(min(num_sections, 32)):
            off = sections_start + i * 40
            if off + 40 > len(hdr):
                break
            name = hdr[off:off + 8].split(b'\x00')[0].decode('ascii', errors='ignore')
            vsize = struct.unpack_from('<I', hdr, off + 8)[0]
            rva = struct.unpack_from('<I', hdr, off + 12)[0]
            chars = struct.unpack_from('<I', hdr, off + 36)[0]
            if vsize > 0 and rva > 0:
                sections.append((name, base + rva, vsize, chars))
        return sections
    except (struct.error, OSError):
        return []

def _get_data_sections(handle: int, base: int) -> List[Tuple[str, int, int]]:
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    result = []
    for name, va, vsize, chars in _parse_pe_sections(handle, base):
        if not (chars & IMAGE_SCN_MEM_EXECUTE):
            result.append((name, va, vsize))
    return result

_REGISTRATION_SIGS = [
    {
        "name": "PUSHx3_CALL_32",
        "pattern": "68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ??",
        "is_32bit": True,
        "code_reg_off": 11,
        "meta_reg_off": 6,
    },
    {
        "name": "PUSHx2_CALL_32",
        "pattern": "68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ??",
        "is_32bit": True,
        "code_reg_off": 6,
        "meta_reg_off": 1,
    },
    {
        "name": "LEA_LEA_CALL",
        "pattern": "48 8D 0D ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ??",
        "rcx_disp_off": 3, "rcx_insn_size": 7,
        "rdx_disp_off": 10, "rdx_insn_size": 14,
    },
    {
        "name": "MOV_MOV_CALL",
        "pattern": "48 8B 0D ?? ?? ?? ?? 48 8B 15 ?? ?? ?? ?? E8 ?? ?? ?? ??",
        "rcx_disp_off": 3, "rcx_insn_size": 7,
        "rdx_disp_off": 10, "rdx_insn_size": 14,
    },
    {
        "name": "LEA_LEA_INDIRECT",
        "pattern": "48 8D 0D ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ??",
        "rcx_disp_off": 3, "rcx_insn_size": 7,
        "rdx_disp_off": 10, "rdx_insn_size": 14,
    },
    {
        "name": "LEA_RDX_LEA_RCX_CALL",
        "pattern": "48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ??",
        "rcx_disp_off": 10, "rcx_insn_size": 14,
        "rdx_disp_off": 3, "rdx_insn_size": 7,
    },
    {
        "name": "LEA_R8_LEA_R9_CALL",
        "pattern": "4C 8D 05 ?? ?? ?? ?? 4C 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ??",
        "rcx_disp_off": 3, "rcx_insn_size": 7,
        "rdx_disp_off": 10, "rdx_insn_size": 14,
    },
    {
        "name": "LEA_RAX_STORE_LEA_LEA",
        "pattern": "48 8D 05 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ??",
        "rcx_disp_off": 17, "rcx_insn_size": 21,
        "rdx_disp_off": 24, "rdx_insn_size": 28,
    },
    {
        "name": "LEA_LEA_JMP",
        "pattern": "48 8D 0D ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? E9 ?? ?? ?? ??",
        "rcx_disp_off": 3, "rcx_insn_size": 7,
        "rdx_disp_off": 10, "rdx_insn_size": 14,
    },
]

def _resolve_pair(handle: int, match_addr: int, sig: dict) -> Tuple[int, int]:
    if sig.get("is_32bit"):
        data = read_bytes(handle, match_addr, 20)
        if not data: return 0, 0
        import struct
        code_reg = struct.unpack_from('<I', data, sig["code_reg_off"])[0]
        meta_reg = struct.unpack_from('<I', data, sig["meta_reg_off"])[0]
        return code_reg, meta_reg

    is_mov = "MOV" in sig["name"] and "LEA_MOV" not in sig["name"]
    rcx_addr = resolve_rip(handle, match_addr, sig["rcx_disp_off"], sig["rcx_insn_size"])
    rdx_addr = resolve_rip(handle, match_addr, sig["rdx_disp_off"], sig["rdx_insn_size"])
    
    if is_mov:
        from src.core.memory import read_pointer
        if rcx_addr: rcx_addr = read_pointer(handle, rcx_addr)
        if rdx_addr: rdx_addr = read_pointer(handle, rdx_addr)
    return rcx_addr, rdx_addr

def _classify_registrations(
    handle: int, addr_a: int, addr_b: int, expected_type_count: int,
) -> Tuple[int, int]:
    if not addr_a and not addr_b:
        return 0, 0
    for candidate_meta, candidate_code in ((addr_a, addr_b), (addr_b, addr_a)):
        if not candidate_meta:
            continue
        for probe_off in range(0, 0x90, 0x10):
            val = read_int32(handle, candidate_meta + probe_off)
            if val > 0 and abs(val - expected_type_count) < expected_type_count * 0.2:
                return candidate_code, candidate_meta
    val_a = read_int32(handle, addr_a) if addr_a else 0
    val_b = read_int32(handle, addr_b) if addr_b else 0
    if val_b > val_a and 100 < val_b < 1_000_000:
        return addr_a, addr_b
    if val_a > val_b and 100 < val_a < 1_000_000:
        return addr_b, addr_a
    return addr_b, addr_a

def _is_valid_pointer(val: int, base: int = 0, end: int = 0) -> bool:
    from src.core.memory import IS_32BIT
    if val < 0x10000:
        return False
    if IS_32BIT:
        return val <= 0x7FFFFFFF
    return val <= 0x7FFFFFFFFFFF

def _validate_meta_reg_candidate(
    handle: int,
    candidate_addr: int,
    match_offset: int,
    expected_type_count: int,
    base: int,
    module_end: int,
) -> bool:
    from src.core.memory import IS_32BIT, POINTER_SIZE
    struct_start = candidate_addr - match_offset
    raw = read_bytes(handle, struct_start, 0x100)
    if not raw or len(raw) < 0x40:
        return False

    valid_ptrs = 0
    valid_counts = 0
    type_count_matches = 0

    step = POINTER_SIZE
    fmt = '<I' if IS_32BIT else '<Q'
    val_size = POINTER_SIZE

    for i in range(0, min(len(raw) - val_size, 0xA0), step):
        val = struct.unpack_from(fmt, raw, i)[0]

        if _is_valid_pointer(val):
            valid_ptrs += 1
        elif 0 < val < 1_000_000:
            valid_counts += 1
            if abs(val - expected_type_count) < 10:
                type_count_matches += 1

    if type_count_matches >= 1 and valid_ptrs >= 4 and valid_counts >= 3:
        return True

    return False

def _score_meta_reg_candidate(
    handle: int,
    candidate_addr: int,
    expected_type_count: int,
    base: int,
    module_end: int,
) -> int:
    from src.core.memory import IS_32BIT, POINTER_SIZE

    if not candidate_addr or expected_type_count <= 0:
        return 0

    raw = read_bytes(handle, candidate_addr, 0xB0)
    if not raw or len(raw) < 0x40:
        return 0

    fmt = "<I" if IS_32BIT else "<Q"
    score = 0
    valid_ptrs = 0
    valid_counts = 0
    exact_matches = 0

    for off in range(0, min(len(raw) - POINTER_SIZE, 0x90), POINTER_SIZE):
        val = struct.unpack_from(fmt, raw, off)[0]
        if _is_valid_pointer(val):
            valid_ptrs += 1
            score += 1
        elif 0 < val < 1_000_000:
            valid_counts += 1
            if val == expected_type_count:
                exact_matches += 1
                score += 6
            elif abs(val - expected_type_count) <= max(8, expected_type_count // 100):
                score += 3

    if exact_matches == 0 or valid_ptrs < 4 or valid_counts < 3:
        return 0
    return score

def _score_code_reg_candidate(
    handle: int,
    candidate_addr: int,
    image_count: int,
    base: int,
    module_end: int,
) -> int:
    from src.core.memory import IS_32BIT, POINTER_SIZE, read_pointer

    if not candidate_addr or image_count <= 0:
        return 0

    if IS_32BIT:
        offsets_to_try = ((0x20, 0x24), (0x24, 0x28), (0x28, 0x2C), (0x2C, 0x30))
    else:
        offsets_to_try = ((0x3C, 0x40), (0x40, 0x48), (0x44, 0x4C), (0x48, 0x50))
    best = 0

    for count_off, ptr_off in offsets_to_try:
        count = read_int32(handle, candidate_addr + count_off)
        if count <= 0 or abs(count - image_count) > max(4, image_count):
            continue

        ptr_array = read_pointer(handle, candidate_addr + ptr_off)
        if not _is_valid_pointer(ptr_array):
            continue

        sample_count = min(image_count, 6)
        raw = read_bytes(handle, ptr_array, sample_count * POINTER_SIZE)
        if not raw or len(raw) < POINTER_SIZE:
            continue

        fmt = f"<{len(raw) // POINTER_SIZE}{'I' if IS_32BIT else 'Q'}"
        module_ptrs = struct.unpack_from(fmt, raw)
        valid_module_ptrs = sum(1 for ptr in module_ptrs[:sample_count] if _is_valid_pointer(ptr))
        score = valid_module_ptrs + (6 if count == image_count else 3)
        if valid_module_ptrs >= min(sample_count, 3):
            best = max(best, score)

    return best

def _structural_scan_meta_reg(
    handle: int,
    base: int,
    size: int,
    expected_type_count: int,
) -> int:
    from src.core.memory import IS_32BIT, POINTER_SIZE

    if expected_type_count < 100:
        return 0

    data_sections = _get_data_sections(handle, base)
    if not data_sections:
        fallback_start = base + int(size * 0.7)
        data_sections = [('.fallback', fallback_start, int(size * 0.3))]

    module_end = base + size
    ptr_sz = POINTER_SIZE
    pack_fmt = '<I' if IS_32BIT else '<Q'
    target_bytes = struct.pack(pack_fmt, expected_type_count)

    dbg("structural_scan_meta_reg: typeDefCount=%d, %s, %d data sections",
        expected_type_count, '32-bit' if IS_32BIT else '64-bit', len(data_sections) if data_sections else 0)
    print(f"[DEBUG] IL2CPP: Structural scan for MetadataRegistration "
          f"(typeDefCount={expected_type_count}, {'32' if IS_32BIT else '64'}-bit)...")

    total_scanned = 0
    for sec_name, sec_va, sec_size in data_sections:
        print(f"[DEBUG] IL2CPP:   scanning section {sec_name!r} "
              f"(VA=0x{sec_va:X}, size={sec_size // 1024} KB)")

        from src.core.memory import USE_DRIVER as _USE_DRIVER
        CHUNK = 1024 * 1024 if _USE_DRIVER else 2 * 1024 * 1024
        OVERLAP = 256
        offset = 0
        match_count = 0
        MAX_MATCHES_PER_SECTION = 200

        while offset < sec_size:
            read_size = min(CHUNK, sec_size - offset)
            data = read_bytes(handle, sec_va + offset, read_size)
            if not data:
                dbg("structural_scan: read_bytes returned empty at 0x%X", sec_va + offset)
                offset += CHUNK - OVERLAP
                continue

            search_pos = 0
            while True:
                idx = data.find(target_bytes, search_pos)
                if idx == -1:
                    break

                if idx % ptr_sz != 0:
                    search_pos = idx + 1
                    continue

                match_count += 1
                if match_count > MAX_MATCHES_PER_SECTION:
                    break

                candidate_va = sec_va + offset + idx

                for struct_offset in (0x50, 0x60, 0x40, 0x30, 0x48, 0x58, 0x70, 0x20, 0x10, 0x00,
                                      0x28, 0x18, 0x38, 0x08):
                    if _validate_meta_reg_candidate(
                        handle, candidate_va, struct_offset,
                        expected_type_count, base, module_end,
                    ):
                        meta_reg = candidate_va - struct_offset
                        dbg("structural_scan: MetadataRegistration FOUND at 0x%X (count at +0x%X)",
                            meta_reg, struct_offset)
                        print(f"[OK] IL2CPP: MetadataRegistration found at 0x{meta_reg:X} "
                              f"(count at +0x{struct_offset:X} in section {sec_name!r})")
                        return meta_reg

                search_pos = idx + ptr_sz

            offset += CHUNK - OVERLAP
            del data
            total_scanned += read_size

        if match_count > MAX_MATCHES_PER_SECTION:
            print(f"[DEBUG] IL2CPP:   section {sec_name!r} had too many false matches, skipping rest")

    print("[DEBUG] IL2CPP: Structural scan in-section failed, trying heap pointers (limited)...")

    heap_checks = 0
    MAX_HEAP_CHECKS = 200

    for sec_name, sec_va, sec_size in data_sections:
        if heap_checks >= MAX_HEAP_CHECKS:
            break
        CHUNK = 2 * 1024 * 1024
        offset = 0
        while offset < sec_size and heap_checks < MAX_HEAP_CHECKS:
            read_size = min(CHUNK, sec_size - offset)
            data = read_bytes(handle, sec_va + offset, read_size)
            if not data:
                offset += CHUNK
                continue

            for i in range(0, len(data) - ptr_sz, ptr_sz * 64):
                if heap_checks >= MAX_HEAP_CHECKS:
                    break
                ptr = struct.unpack_from(pack_fmt, data, i)[0]
                if not _is_valid_pointer(ptr):
                    continue
                if base <= ptr < module_end:
                    continue

                heap_checks += 1
                heap_data = read_bytes(handle, ptr, 0x100)
                if not heap_data or len(heap_data) < 0x80:
                    continue

                for field_off in range(0, 0x80, ptr_sz):
                    if field_off + ptr_sz > len(heap_data):
                        break
                    val = struct.unpack_from(pack_fmt, heap_data, field_off)[0]
                    if val == expected_type_count:
                        if _validate_meta_reg_candidate(
                            handle, ptr + field_off, field_off,
                            expected_type_count, base, module_end,
                        ):
                            meta_reg = ptr
                            print(f"[OK] IL2CPP: MetadataRegistration (heap) found at "
                                  f"0x{meta_reg:X} (via ptr in {sec_name!r})")
                            return meta_reg

            offset += CHUNK
            del data

    print("[DEBUG] IL2CPP: Structural scan found no MetadataRegistration")
    return 0

def _structural_scan_code_reg(
    handle: int,
    base: int,
    size: int,
    image_count: int,
) -> int:
    from src.core.memory import IS_32BIT, POINTER_SIZE, read_pointer

    if image_count < 1:
        return 0

    data_sections = _get_data_sections(handle, base)
    if not data_sections:
        fallback_start = base + int(size * 0.7)
        data_sections = [('.fallback', fallback_start, int(size * 0.3))]

    module_end = base + size
    ptr_sz = POINTER_SIZE
    pack_fmt = '<I' if IS_32BIT else '<Q'
    target_bytes = struct.pack(pack_fmt, image_count)

    print(f"[DEBUG] IL2CPP: Structural scan for CodeRegistration "
          f"(imageCount={image_count}, {'32' if IS_32BIT else '64'}-bit)...")

    candidates = []

    for sec_name, sec_va, sec_size in data_sections:
        from src.core.memory import USE_DRIVER as _USE_DRIVER
        CHUNK = 1024 * 1024 if _USE_DRIVER else 2 * 1024 * 1024
        offset = 0

        while offset < sec_size:
            read_size = min(CHUNK, sec_size - offset)
            data = read_bytes(handle, sec_va + offset, read_size)
            if not data:
                offset += CHUNK
                continue

            search_pos = 0
            while True:
                idx = data.find(target_bytes, search_pos)
                if idx == -1:
                    break
                if idx % ptr_sz != 0:
                    search_pos = idx + 1
                    continue

                candidate_va = sec_va + offset + idx

                next_val = 0
                if idx + 2 * ptr_sz <= len(data):
                    next_val = struct.unpack_from(pack_fmt, data, idx + ptr_sz)[0]

                if _is_valid_pointer(next_val):
                    array_sample = read_bytes(handle, next_val, image_count * ptr_sz)
                    if array_sample and len(array_sample) >= min(image_count, 4) * ptr_sz:
                        valid_module_ptrs = 0
                        for mi in range(min(image_count, 8)):
                            if mi * ptr_sz + ptr_sz > len(array_sample):
                                break
                            mp = struct.unpack_from(pack_fmt, array_sample, mi * ptr_sz)[0]
                            if _is_valid_pointer(mp):
                                valid_module_ptrs += 1

                        if valid_module_ptrs >= min(image_count, 4):
                            if IS_32BIT:
                                offsets_to_try = (0x24, 0x20, 0x28, 0x2C, 0x1C, 0x18, 0x30, 0x10, 0x14)
                            else:
                                offsets_to_try = (0x48, 0x40, 0x50, 0x58, 0x38, 0x30, 0x60)
                            for struct_offset in offsets_to_try:
                                cr_start = candidate_va - struct_offset
                                first_val = read_uint32(handle, cr_start)
                                if first_val and 0 < first_val < 1_000_000:
                                    candidates.append((cr_start, valid_module_ptrs, struct_offset))

                search_pos = idx + ptr_sz

            offset += CHUNK
            del data

    if candidates:
        best = max(candidates, key=lambda x: x[1])
        print(f"[OK] IL2CPP: CodeRegistration found at 0x{best[0]:X} "
              f"(moduleCount at +0x{best[2]:X}, {best[1]} valid module ptrs)")
        return best[0]

    print("[DEBUG] IL2CPP: Trying heap pointer fallback for CodeRegistration (limited)...")
    heap_checks = 0
    MAX_HEAP_CHECKS = 500

    for sec_name, sec_va, sec_size in data_sections:
        if heap_checks >= MAX_HEAP_CHECKS:
            break
        CHUNK = 2 * 1024 * 1024
        offset = 0
        while offset < sec_size and heap_checks < MAX_HEAP_CHECKS:
            read_size = min(CHUNK, sec_size - offset)
            data = read_bytes(handle, sec_va + offset, read_size)
            if not data:
                offset += CHUNK
                continue

            for i in range(0, len(data) - ptr_sz, ptr_sz):
                if heap_checks >= MAX_HEAP_CHECKS:
                    break
                ptr = struct.unpack_from(pack_fmt, data, i)[0]
                if not _is_valid_pointer(ptr) or (base <= ptr < module_end):
                    continue

                heap_checks += 1
                heap_data = read_bytes(handle, ptr, 0x80)
                if not heap_data or len(heap_data) < 0x60:
                    continue

                for field_off in range(0, 0x60, ptr_sz):
                    if field_off + ptr_sz > len(heap_data):
                        break
                    val = struct.unpack_from(pack_fmt, heap_data, field_off)[0]
                    if val == image_count:
                        if field_off + 2 * ptr_sz <= len(heap_data):
                            next_v = struct.unpack_from(pack_fmt, heap_data, field_off + ptr_sz)[0]
                            if _is_valid_pointer(next_v):
                                arr = read_bytes(handle, next_v, min(image_count, 4) * ptr_sz)
                                if arr:
                                    vp = sum(1 for mi in range(min(image_count, 4))
                                             if mi * ptr_sz + ptr_sz <= len(arr) and
                                             _is_valid_pointer(struct.unpack_from(pack_fmt, arr, mi * ptr_sz)[0]))
                                    if vp >= min(image_count, 3):
                                        print(f"[OK] IL2CPP: CodeRegistration (heap) at 0x{ptr:X}")
                                        return ptr

            offset += CHUNK
            del data

    print("[DEBUG] IL2CPP: Structural scan found no CodeRegistration")
    return 0

def _find_s_global_metadata(handle: int, base: int, size: int) -> int:
    from src.core.memory import IS_32BIT

    if IS_32BIT:
        return 0

    patterns = [
        "48 8D 0D ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 8D 05",
        "48 89 05 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ??",
    ]
    for pat in patterns:
        hits = scan_pattern(handle, base, size, pat)
        for hit in hits:
            addr = resolve_rip(handle, hit + 7, disp_offset=3, instruction_size=7)
            if addr:
                return addr
    return 0

def find_registrations(
    handle: int,
    base: int,
    size: int,
    expected_type_count: int = 0,
    image_count: int = 0,
) -> dict:
    import gc

    _parse_pe_sections(handle, base)

    from src.core.memory import IS_32BIT, POINTER_SIZE, read_pointer
    from src.core.memory import USE_DRIVER as _USE_DRIVER

    dbg("find_registrations: base=0x%X size=0x%X types=%d images=%d",
        base, size, expected_type_count, image_count)
    print(f"[DEBUG] IL2CPP: Scanning (types={expected_type_count}, images={image_count}, 32-bit={IS_32BIT})...")

    if _USE_DRIVER:
        dbg("find_registrations: driver mode detected, using bulk_read_mode")
        from src.core.driver import bulk_read_mode
        with bulk_read_mode():
            return _find_registrations_inner(
                handle, base, size, expected_type_count, image_count, gc
            )
    else:
        return _find_registrations_inner(
            handle, base, size, expected_type_count, image_count, gc
        )

def _find_registrations_inner(
    handle: int,
    base: int,
    size: int,
    expected_type_count: int,
    image_count: int,
    gc,
) -> dict:
    from src.core.memory import IS_32BIT, POINTER_SIZE, read_pointer

    scan_start = time.time()
    code_reg, meta_reg, cg_mods, field_offs = 0, 0, 0, 0
    best_aob = None
    module_end = base + size

    dbg("Phase 1: AOB signature scan starting")
    print("[DEBUG] IL2CPP: Phase 1 — AOB signature scan...")
    for sig in _REGISTRATION_SIGS:
        sig_is_32bit = sig.get("is_32bit", False)
        if IS_32BIT != sig_is_32bit:
            continue

        hits = scan_pattern(handle, base, size, sig["pattern"], max_results=5)
        for hit in hits:
            a, b = _resolve_pair(handle, hit, sig)
            if not a or not b:
                continue

            cand_code, cand_meta = _classify_registrations(handle, a, b, expected_type_count)
            meta_score = _score_meta_reg_candidate(
                handle, cand_meta, expected_type_count, base, module_end,
            )
            code_score = 0
            if image_count > 0:
                code_score = _score_code_reg_candidate(
                    handle, cand_code, image_count, base, module_end,
                )

            if meta_score <= 0:
                continue

            total_score = meta_score + code_score
            if best_aob is None or total_score > best_aob[0]:
                best_aob = (
                    total_score,
                    cand_code if code_score > 0 else 0,
                    cand_meta,
                    sig["name"],
                )

    if best_aob:
        best_score, code_reg, meta_reg, sig_name = best_aob
        print(
            f"[OK] IL2CPP: Phase 1 validated registrations via {sig_name}: "
            f"Code=0x{code_reg:X} Meta=0x{meta_reg:X} score={best_score}"
        )
        dbg(
            "Phase 1: VALIDATED via %s Code=0x%X Meta=0x%X score=%d",
            sig_name, code_reg, meta_reg, best_score,
        )

    if meta_reg:
        return {
            "code_registration": code_reg,
            "metadata_registration": meta_reg,
            "s_global_metadata": _find_s_global_metadata(handle, base, size),
            "codegen_modules": 0,
            "field_offsets": 0,
            "is_32bit": IS_32BIT,
            "is_relative_pointers": False,
        }

    if expected_type_count > 100:
        dbg("Phase 2: Structural scan starting (MetadataRegistration)")
        print("[DEBUG] IL2CPP: Phase 2 — Structural scan (MetadataRegistration)...")
        meta_reg = _structural_scan_meta_reg(handle, base, size, expected_type_count)
        if not meta_reg:
            gc.collect()
            dbg("Phase 2: MetadataRegistration structural scan failed, gc.collect()")
        if image_count > 0:
            dbg("Phase 2: Structural scan (CodeRegistration)")
            print("[DEBUG] IL2CPP: Phase 2 — Structural scan (CodeRegistration)...")
            code_reg = _structural_scan_code_reg(handle, base, size, image_count)
            if not code_reg:
                gc.collect()

    if meta_reg:
        print(f"[OK] IL2CPP: Structural scan succeeded — skipping heuristic array scans")
        s_global_meta = _find_s_global_metadata(handle, base, size)
        return {
            "code_registration": code_reg,
            "metadata_registration": meta_reg,
            "s_global_metadata": s_global_meta,
            "codegen_modules": cg_mods,
            "field_offsets": field_offs,
            "is_32bit": IS_32BIT,
            "is_relative_pointers": False,
        }

    print("[DEBUG] IL2CPP: Phase 3 — Lightweight heuristic scan...")
    data_sections = _get_data_sections(handle, base)
    module_end = base + size

    ptr_fmt = '<I' if IS_32BIT else '<Q'
    ptr_sz = POINTER_SIZE

    def _is_vptr(p):
        return base <= p < module_end

    best_cgm_score, best_cgm_cand = 0, 0
    images_bytes = image_count * ptr_sz
    if image_count > 0 and images_bytes > 0:
        cgm_candidates = []
        found_perfect = False
        batch_fmt_char = 'I' if IS_32BIT else 'Q'

        for sec_name, va, vsize in data_sections:
            if found_perfect:
                break
            CHUNK = 2 * 1024 * 1024
            for chunk_off in range(0, vsize, CHUNK - images_bytes):
                if found_perfect:
                    break
                read_sz = min(CHUNK, vsize - chunk_off)
                if read_sz < images_bytes:
                    break
                bdata = read_bytes(handle, va + chunk_off, read_sz)
                if not bdata or len(bdata) < images_bytes:
                    continue

                n_ptrs = len(bdata) // ptr_sz
                if n_ptrs < image_count:
                    del bdata
                    continue
                all_ptrs = struct.unpack_from(f'<{n_ptrs}{batch_fmt_char}', bdata)
                del bdata

                check_limit = min(image_count, 8)
                score_threshold = min(image_count, 4)
                scan_end = n_ptrs - image_count
                stride = 8
                for i in range(0, scan_end, stride):
                    if not _is_vptr(all_ptrs[i]):
                        continue
                    refine_start = max(0, i - stride + 1)
                    refine_end = min(scan_end, i + stride)
                    for j in range(refine_start, refine_end):
                        if not _is_vptr(all_ptrs[j]):
                            continue
                        score = sum(1 for k in range(check_limit)
                                    if _is_vptr(all_ptrs[j + k]))
                        if score >= score_threshold:
                            cgm_candidates.append((score, va + chunk_off + j * ptr_sz))
                            if score >= check_limit or len(cgm_candidates) >= 50:
                                found_perfect = True
                                break
                    if found_perfect:
                        break

                del all_ptrs
                gc.collect()

        cgm_candidates.sort(key=lambda x: -x[0])
        for local_score, cand_va in cgm_candidates[:5]:
            rpm_score = 0
            for idx in range(min(image_count, 5)):
                c_ptr = read_pointer(handle, cand_va + idx * ptr_sz)
                if not _is_vptr(c_ptr):
                    continue
                m_count_val = read_int32(handle, c_ptr + (4 if IS_32BIT else 8))
                if 0 <= m_count_val < 100000:
                    rpm_score += 1
            if rpm_score > best_cgm_score:
                best_cgm_score, best_cgm_cand = rpm_score, cand_va

    if best_cgm_score >= 3:
        cg_mods = best_cgm_cand
        print(f"[OK] IL2CPP: Found g_Il2CppCodeGenModules at 0x{cg_mods:X} (score={best_cgm_score}/5)")

    best_fot_score, best_fot_cand = 0, 0
    if expected_type_count > 100:
        array_bytes = expected_type_count * ptr_sz
        test_indices = list(range(min(10, expected_type_count)))
        batch_fmt_char = 'I' if IS_32BIT else 'Q'

        fot_candidates = []
        for sec_name, va, vsize in data_sections:
            if vsize < array_bytes or array_bytes > vsize:
                continue
            CHUNK = min(max(array_bytes + 4096, 4 * 1024 * 1024), vsize)
            for chunk_off in range(0, vsize - array_bytes + 1, max(CHUNK - array_bytes, 1)):
                read_sz = min(CHUNK, vsize - chunk_off)
                if read_sz < array_bytes:
                    break
                bdata = read_bytes(handle, va + chunk_off, read_sz)
                if not bdata or len(bdata) < array_bytes:
                    continue

                n_ptrs = len(bdata) // ptr_sz
                all_ptrs = struct.unpack_from(f'<{n_ptrs}{batch_fmt_char}', bdata)
                del bdata

                step = 64
                for i in range(0, n_ptrs - expected_type_count, step):
                    score = 0
                    for ti in test_indices[:5]:
                        p = all_ptrs[i + ti]
                        if _is_vptr(p) or p == 0:
                            score += 1
                    if score >= 3:
                        fot_candidates.append((score, va + chunk_off + i * ptr_sz))
                    if len(fot_candidates) >= 20:
                        break

                del all_ptrs
                if len(fot_candidates) >= 20:
                    break
            if len(fot_candidates) >= 20:
                break

        gc.collect()

        fot_candidates.sort(key=lambda x: -x[0])
        for local_score, cand_va in fot_candidates[:10]:
            rpm_score = 0
            for ti in test_indices:
                t_ptr = read_pointer(handle, cand_va + ti * ptr_sz)
                if t_ptr == 0:
                    rpm_score += 1
                elif _is_vptr(t_ptr) or t_ptr > 0x10000:
                    first_off = read_int32(handle, t_ptr)
                    if 0x08 <= first_off <= 0x2000:
                        rpm_score += 1
            if rpm_score > best_fot_score:
                best_fot_score, best_fot_cand = rpm_score, cand_va

    if best_fot_score >= 5:
        field_offs = best_fot_cand
        print(f"[OK] IL2CPP: Found g_FieldOffsetTable at 0x{field_offs:X} (score={best_fot_score}/10)")

    s_global_meta = _find_s_global_metadata(handle, base, size)

    return {
        "code_registration": code_reg,
        "metadata_registration": meta_reg,
        "s_global_metadata": s_global_meta,
        "codegen_modules": cg_mods,
        "field_offsets": field_offs,
        "is_32bit": IS_32BIT,
        "is_relative_pointers": False,
    }
