import logging
import struct
from typing import Optional

from src.core.memory import read_bytes

logger = logging.getLogger(__name__)


def find_schema_system_ptr(handle: int, module_base: int, module_size: int) -> Optional[int]:
    """Locate the CSchemaSystem instance via pattern scan on schemasystem.dll.

    Uses the same approach as a2x/cs2-dumper (schemas.rs):
        Pattern: 4C 8D 35 ?? ?? ?? ?? 0F 28 45
        This is:  lea r14, [rip + disp32]  ;  movaps xmm0, ...
    The RIP-relative operand resolves directly to the CSchemaSystem instance
    (NOT a pointer that needs a second dereference).

    We also try a secondary pattern used in older builds:
        Pattern: 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 05
        This is:  lea rcx, [rip + disp32]  ; call ...
    """
    try:
        buf = read_bytes(handle, module_base, module_size)
    except Exception as e:
        logger.error(f"Failed to read schemasystem.dll memory: {e}")
        return None

    if buf is None or len(buf) < 16:
        logger.error("schemasystem.dll buffer too small or unreadable")
        return None

    # --- Primary pattern (current CS2 builds) ---
    # 4C 8D 35 [rel32] 0F 28 45
    primary = bytes([0x4C, 0x8D, 0x35])
    suffix_primary = bytes([0x0F, 0x28, 0x45])

    result = _scan_rip_relative(buf, module_base, primary, suffix_primary, instr_len=7, suffix_offset=7)
    if result is not None:
        logger.info(f"Schema system found via primary pattern at 0x{result:X}")
        return result

    # --- Secondary pattern (alternative / older builds) ---
    # 48 8D 0D [rel32] E8
    secondary = bytes([0x48, 0x8D, 0x0D])
    suffix_secondary = bytes([0xE8])

    result = _scan_rip_relative(buf, module_base, secondary, suffix_secondary, instr_len=7, suffix_offset=7)
    if result is not None:
        logger.info(f"Schema system found via secondary pattern at 0x{result:X}")
        return result

    # --- Tertiary pattern (mov cs:SchemaSystem, rax — from our original code) ---
    # 48 89 05 [rel32] 4C 8D 45
    tertiary = bytes([0x48, 0x89, 0x05])
    suffix_tertiary = bytes([0x4C, 0x8D, 0x45])

    result = _scan_rip_relative(buf, module_base, tertiary, suffix_tertiary, instr_len=7, suffix_offset=7)
    if result is not None:
        logger.info(f"Schema system found via tertiary pattern at 0x{result:X}")
        return result

    logger.error("All CSchemaSystem patterns failed.")
    return None


def _scan_rip_relative(
    buf: bytes,
    module_base: int,
    prefix: bytes,
    suffix: bytes,
    instr_len: int,
    suffix_offset: int,
) -> Optional[int]:
    """Scan for prefix + rel32 + suffix and resolve the RIP-relative address."""
    offset = 0
    plen = len(prefix)
    slen = len(suffix)

    while offset < len(buf) - (suffix_offset + slen):
        idx = buf.find(prefix, offset)
        if idx == -1:
            break

        # Check that the suffix bytes match at the expected position
        if buf[idx + suffix_offset: idx + suffix_offset + slen] == suffix:
            # Read the 4-byte signed displacement immediately after the prefix
            rel32 = struct.unpack_from("<i", buf, idx + plen)[0]
            # RIP points to the instruction AFTER this one (base + idx + instr_len)
            resolved = module_base + idx + instr_len + rel32
            return resolved

        offset = idx + 1

    return None
