"""
Focused analysis around key chat and trace findings.
Disassembles specific regions found by the fast scanner.
"""
import sys, struct, re
from pathlib import Path

import pefile
from capstone import *
from capstone.x86_const import *

CS2_CLIENT_DLL = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game\csgo\bin\win64\client.dll")

pe = pefile.PE(str(CS2_CLIENT_DLL))
with open(CS2_CLIENT_DLL, 'rb') as f:
    data = f.read()

img_base = pe.OPTIONAL_HEADER.ImageBase
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def va_to_file_offset(va):
    rva = va - img_base
    return pe.get_offset_from_rva(rva)

def disasm_around(va, before=64, after=128):
    off = va_to_file_offset(va)
    if off is None or off < 0:
        return []
    start = max(0, off - before)
    end = min(len(data), off + after)
    code = data[start:end]
    base = va - before
    return list(md.disasm(code, base, len(code)))

def print_region(title, va, before=64, after=192):
    print(f"\n{'='*70}")
    print(f"[{title}] VA 0x{va:012X}")
    print(f"{'='*70}")
    for insn in disasm_around(va, before, after):
        marker = " <== TARGET" if insn.address == va else ""
        hex_bytes = ' '.join(f'{b:02X}' for b in insn.bytes)
        print(f"  0x{insn.address:012X}: {hex_bytes:24s} {insn.mnemonic:8s} {insn.op_str:50s}{marker}")

# ========================================================================
# KEY CHAT REFERENCES
# ========================================================================

# The 'say' string is referenced here - likely console command registration
print_region("say COMMAND REF #1", 0x180AF9003, before=48, after=256)
print_region("say COMMAND REF #2", 0x180CF8E65, before=48, after=256)

# The actual 'say "' string reference - likely the command handler
print_region("say \" handler", 0x180E13884, before=64, after=256)

# SubmitChatText - Panorama UI function
print_region("SubmitChatText reference", 0x180D0B477, before=48, after=256)

# PlayerChat reference
print_region("PlayerChat reference", 0x180CEAFB7, before=48, after=256)

# HudChat.Message reference
print_region("HudChat.Message reference", 0x1810C171E, before=48, after=256)

# ========================================================================
# TRACE RAY CANDIDATES
# ========================================================================

text_sec = None
for s in pe.sections:
    if s.Name.startswith(b'.text'):
        text_sec = s
        break

text_data = data[text_sec.PointerToRawData:text_sec.PointerToRawData + text_sec.SizeOfRawData]
text_va = text_sec.VirtualAddress

# Find TraceRay pattern matches
trace_pat = rb'\x48\x89\x5C\x24.\x48\x89\x4C\x24.\x55\x57'
for i, m in enumerate(re.finditer(trace_pat, text_data)):
    if i >= 3:
        break
    rva = text_va + m.start()
    va = img_base + rva
    print_region(f"TraceRay CANDIDATE #{i+1}", va, before=32, after=256)

# ========================================================================
# CATEGORIZE POSITION SEARCH
# ========================================================================

# Find 'CategorizePosition' string references
cat_offsets = []
for offset in range(len(data) - 18):
    if data[offset:offset+18] == b'CategorizePosition':
        cat_offsets.append(offset)

print(f"\n{'='*70}")
print(f"[CategorizePosition STRINGS: {len(cat_offsets)} found]")
print(f"{'='*70}")
for off in cat_offsets[:5]:
    rva = pe.get_rva_from_offset(off)
    va = img_base + rva
    print(f"  String at offset 0x{off:08X} (VA 0x{va:012X})")

# ========================================================================
# FALL VELOCITY / DAMAGE SEARCH
# ========================================================================

fall_offsets = []
for offset in range(len(data) - 12):
    if data[offset:offset+12] == b'fall velocity':
        fall_offsets.append(offset)
    if data[offset:offset+11] == b'fall damage':
        fall_offsets.append(offset)

print(f"\n{'='*70}")
print(f"[FALL-RELATED STRINGS]")
print(f"{'='*70}")
for off in fall_offsets:
    rva = pe.get_rva_from_offset(off)
    va = img_base + rva
    s = data[off:off+32].split(b'\x00')[0].decode('ascii', errors='ignore')
    print(f"  '{s}' at VA 0x{va:012X}")

pe.close()
print("\n[*] Analysis complete!")
