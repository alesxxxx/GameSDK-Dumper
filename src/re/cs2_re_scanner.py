"""
CS2 client.dll scanner for chat, trace, and movement function signatures.
Uses capstone for disassembly and pefile for PE parsing.
"""

import sys
import struct
import re
from pathlib import Path

try:
    import pefile
    from capstone import *
    from capstone.x86_const import *
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install with: pip install pefile capstone")
    sys.exit(1)

# CS2 client.dll path
CS2_CLIENT_DLL = Path(r"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game\csgo\bin\win64\client.dll")
if not CS2_CLIENT_DLL.exists():
    # Try alternate paths
    alt_paths = [
        Path(r"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game\bin\win64\client.dll"),
        Path(r"C:\Program Files\Steam\steamapps\common\Counter-Strike Global Offensive\game\bin\win64\client.dll"),
    ]
    for p in alt_paths:
        if p.exists():
            CS2_CLIENT_DLL = p
            break

if not CS2_CLIENT_DLL.exists():
    print(f"ERROR: client.dll not found at {CS2_CLIENT_DLL}")
    sys.exit(1)

print(f"[*] Loading {CS2_CLIENT_DLL}")
print(f"[*] File size: {CS2_CLIENT_DLL.stat().st_size / (1024*1024):.1f} MB")

# Load PE
pe = pefile.PE(str(CS2_CLIENT_DLL))

# Get .text section info
text_section = None
for section in pe.sections:
    if section.Name.startswith(b'.text'):
        text_section = section
        break

if not text_section:
    print("ERROR: .text section not found")
    sys.exit(1)

# Read the full file data
with open(CS2_CLIENT_DLL, 'rb') as f:
    file_data = f.read()

image_base = pe.OPTIONAL_HEADER.ImageBase
text_va = text_section.VirtualAddress
text_raw = text_section.PointerToRawData
text_size = text_section.SizeOfRawData
text_data = file_data[text_raw:text_raw + text_size]

print(f"[*] .text section: VA=0x{text_va:X}, Raw=0x{text_raw:X}, Size=0x{text_size:X}")
print(f"[*] Image base: 0x{image_base:X}")

# Initialize capstone
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# ========================================================================
# 1. STRING SCANNER - Find interesting strings in the binary
# ========================================================================

def find_strings(data, min_len=4):
    """Extract ASCII and Unicode strings from binary data."""
    strings = []
    # ASCII strings
    ascii_pattern = re.compile(rb'[\x20-\x7E]{' + str(min_len).encode() + rb',}')
    for m in ascii_pattern.finditer(data):
        strings.append((m.start(), 'ascii', m.group().decode('ascii', errors='ignore')))
    return strings

print("\n" + "="*70)
print("[1] SCANNING FOR INTERESTING STRINGS")
print("="*70)

# Interesting string patterns for our targets
CHAT_STRINGS = [b'say', b'say_team', b'chat', b'message', b'Chat', b'Message']
TRACE_STRINGS = [b'TraceRay', b'trace', b'Trace', b'CGameTrace', b'mask_', b'MASK_']
MOVEMENT_STRINGS = [b'CategorizePosition', b'categorize', b'onground', b'fall', b'velocity',
                   b'PlayerMove', b'PM_', b'ProcessMovement', b'edge', b'jump']

all_interesting = set()

# Scan entire file for strings
print("[*] Extracting strings...")
string_hits = {}
for s in CHAT_STRINGS + TRACE_STRINGS + MOVEMENT_STRINGS:
    string_hits[s.decode()] = []

for offset in range(len(file_data)):
    for s in CHAT_STRINGS + TRACE_STRINGS + MOVEMENT_STRINGS:
        end = offset + len(s)
        if end <= len(file_data) and file_data[offset:end] == s:
            # Extract surrounding context
            start = max(0, offset - 16)
            end_ctx = min(len(file_data), offset + len(s) + 16)
            ctx = file_data[start:end_ctx]
            # Try to get readable context
            readable = ''
            for b in ctx:
                if 32 <= b <= 126:
                    readable += chr(b)
                else:
                    readable += '.'
            string_hits[s.decode()].append((offset, readable))

for category, strings in [("CHAT", CHAT_STRINGS), ("TRACE", TRACE_STRINGS), ("MOVEMENT", MOVEMENT_STRINGS)]:
    print(f"\n--- {category} STRINGS ---")
    for s in strings:
        hits = string_hits[s.decode()]
        if hits:
            print(f"  '{s.decode()}' - {len(hits)} occurrences")
            # Show first few
            for offset, ctx in hits[:3]:
                rva = pe.get_rva_from_offset(offset)
                va = image_base + rva if rva else offset
                print(f"    Offset 0x{offset:X} (VA ~0x{va:X}): ...{ctx}...")

# ========================================================================
# 2. PATTERN SCANNER - Search for known/interesting byte patterns
# ========================================================================

print("\n" + "="*70)
print("[2] SCANNING FOR BYTE PATTERNS")
print("="*70)

PATTERNS = {
    # From UC forum - known working CS2 patterns
    "TraceRay": rb'\x48\x89\x5C\x24.\x48\x89\x4C\x24.\x55\x57',
    "CreateMove": rb'\x48\x8B\xC4\x4C\x89\x40.\x48\x89\x48.\x55\x53\x41\x54',
    "CCSGOInput": rb'\x48\x8B\x0D....\x48\x8B\x01\xFF\x50.\x8B\xDF',
    "GetViewAngles": rb'\x4C\x8B\xC1\x85\xD2\x74\x08\x48\x8D\x05....\xC3',
    "SetViewAngles": rb'\x85\xD2\x75.\x48\x63\x81',
    
    # Chat-related: looking for command processing
    "ConsoleCommand_say": rb'say\x00',
    "ConsoleCommand_say_team": rb'say_team\x00',
    
    # Trace-related patterns
    "TraceFilterSimple": rb'TraceFilterSimple',
    "EngineTrace": rb'EngineTrace',
    
    # Movement-related
    "CategorizePosition": rb'CategorizePosition',
    "ProcessMovement": rb'ProcessMovement',
    
    # Force jump (from UC forum)
    "ForceJump": rb'\x48\x8B\x05....\x48\x8D\x1D....\x48\x89\x45',
}

for name, pattern in PATTERNS.items():
    matches = list(re.finditer(pattern, file_data))
    print(f"\n  {name}: {len(matches)} match(es)")
    for m in matches[:3]:  # Show first 3
        offset = m.start()
        rva = pe.get_rva_from_offset(offset)
        va = image_base + rva if rva else 0
        print(f"    Offset 0x{offset:X} | RVA 0x{rva:X} | VA 0x{va:X}")
        
        # Show hex dump
        hex_bytes = ' '.join(f'{b:02X}' for b in file_data[offset:offset+min(16, len(m.group()))])
        print(f"    Bytes: {hex_bytes}")

# ========================================================================
# 3. DISASSEMBLY SCANNER - Find code references to string data
# ========================================================================

print("\n" + "="*70)
print("[3] SCANNING CODE FOR RIP-RELATIVE STRING REFERENCES")
print("="*70)

def find_rip_refs_to_strings():
    """
    In x64, strings are referenced via RIP-relative addressing:
    lea reg, [rip + disp32]
    mov reg, [rip + disp32]
    
    We scan the .text section for these patterns and check if they
    point to interesting strings.
    """
    refs = []
    
    # Disassemble .text section in chunks
    chunk_size = 0x10000
    for chunk_start in range(0, len(text_data), chunk_size):
        chunk_end = min(chunk_start + chunk_size, len(text_data))
        chunk = text_data[chunk_start:chunk_end]
        
        for insn in md.disasm(chunk, image_base + text_va + chunk_start, chunk_end - chunk_start):
            # Look for LEA or MOV with RIP-relative addressing
            if insn.id in (X86_INS_LEA, X86_INS_MOV) and insn.op_count > 1:
                for op in insn.operands:
                    if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                        # RIP-relative addressing
                        target_va = insn.address + insn.size + op.mem.disp
                        target_offset = pe.get_offset_from_rva(target_va - image_base)
                        
                        if target_offset and 0 <= target_offset < len(file_data):
                            # Check what's at the target
                            data = file_data[target_offset:target_offset+32]
                            # Check if it's a string
                            ascii_str = ''
                            for b in data:
                                if 32 <= b <= 126:
                                    ascii_str += chr(b)
                                else:
                                    break
                            
                            if len(ascii_str) >= 3:
                                # Check if it's an interesting string
                                lower = ascii_str.lower()
                                for interest in ['say', 'chat', 'message', 'trace', 'categorize', 'onground', 'fall', 'jump', 'edge', 'velocity']:
                                    if interest in lower:
                                        refs.append({
                                            'insn_addr': insn.address,
                                            'target_va': target_va,
                                            'target_offset': target_offset,
                                            'string': ascii_str,
                                            'instruction': f"{insn.mnemonic} {insn.op_str}",
                                            'interest': interest
                                        })
                                        break
    return refs

print("[*] Disassembling .text and finding RIP-relative string refs...")
print("[*] This may take a minute...")

rip_refs = find_rip_refs_to_strings()

# Group by interest
by_interest = {}
for ref in rip_refs:
    interest = ref['interest']
    if interest not in by_interest:
        by_interest[interest] = []
    by_interest[interest].append(ref)

for interest in sorted(by_interest.keys()):
    refs = by_interest[interest]
    print(f"\n  --- '{interest}' references ({len(refs)} found) ---")
    for ref in refs[:5]:  # Show first 5
        print(f"    0x{ref['insn_addr']:X}: {ref['instruction']}")
        print(f"      -> '{ref['string']}' at 0x{ref['target_va']:X}")

# ========================================================================
# 4. SPECIFIC PATTERN SEARCHES FOR KEY FUNCTIONS
# ========================================================================

print("\n" + "="*70)
print("[4] SPECIFIC FUNCTION PATTERN SEARCHES")
print("="*70)

def scan_for_function_prologues():
    """Scan for function prologues that might be our targets."""
    
    # Common x64 function prologues
    prologues = {
        "sub_rsp_xx": rb'\x48\x83\xEC',  # sub rsp, imm8
        "push_rbp": rb'\x55\x48\x8B\xEC',  # push rbp; mov rbp, rsp
        "push rbx": rb'\x53\x48\x83\xEC',  # push rbx; sub rsp, imm8
        "mov_rdi_rsp": rb'\x48\x89\x7C\x24',  # mov [rsp+off], rdi
    }
    
    print("\n  Function prologue statistics:")
    for name, pattern in prologues.items():
        count = len(list(re.finditer(pattern, text_data)))
        print(f"    {name}: ~{count} occurrences")

def find_trace_ray_candidates():
    """Look for functions that might be TraceRay based on patterns."""
    print("\n  TraceRay candidates:")
    
    # The known pattern
    pattern = rb'\x48\x89\x5C\x24.\x48\x89\x4C\x24.\x55\x57'
    matches = list(re.finditer(pattern, text_data))
    
    for m in matches:
        offset = text_raw + m.start()
        rva = pe.get_rva_from_offset(offset)
        va = image_base + rva
        print(f"    Candidate at VA 0x{va:X}")
        
        # Disassemble around it
        start = max(0, m.start() - 32)
        end = min(len(text_data), m.start() + 128)
        code = text_data[start:end]
        base_addr = image_base + text_va + start
        
        disasm = []
        for insn in md.disasm(code, base_addr, len(code)):
            disasm.append(f"0x{insn.address:X}: {insn.mnemonic} {insn.op_str}")
            if insn.address >= va:
                break
        
        # Show first 10 instructions
        for line in disasm[:10]:
            print(f"      {line}")
        print()

scan_for_function_prologues()
find_trace_ray_candidates()

# ========================================================================
# 5. EXPORT SCANNER - Check DLL exports
# ========================================================================

print("\n" + "="*70)
print("[5] DLL EXPORTS")
print("="*70)

if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    exports = []
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name:
            exports.append(exp.name.decode() if isinstance(exp.name, bytes) else exp.name)
    
    interesting_exports = [e for e in exports if any(x in e.lower() for x in ['trace', 'chat', 'say', 'message', 'categorize', 'move'])]
    
    print(f"  Total exports: {len(exports)}")
    if interesting_exports:
        print(f"  Interesting exports:")
        for e in interesting_exports:
            print(f"    {e}")
    else:
        print("  No interesting exports found (CS2 uses mostly internal functions)")
else:
    print("  No export directory found")

# ========================================================================
# 6. SEARCH FOR CHAT-RELATED COMMAND PROCESSING
# ========================================================================

print("\n" + "="*70)
print("[6] CHAT COMMAND ANALYSIS")
print("="*70)

# The console command system in Source 2 processes "say" commands
# Let's look for the string "say" and see what references it
say_offsets = []
for offset in range(len(file_data) - 4):
    if file_data[offset:offset+4] == b'say\x00':
        say_offsets.append(offset)
    if file_data[offset:offset+9] == b'say_team\x00':
        say_offsets.append(offset)

print(f"[*] Found 'say'/'say_team' strings at {len(say_offsets)} locations")

# For each say string, try to find code references
for so in say_offsets[:5]:
    rva = pe.get_rva_from_offset(so)
    va = image_base + rva
    print(f"\n  String at offset 0x{so:X} (VA 0x{va:X})")
    
    # The string itself
    s = file_data[so:so+16]
    s_str = ''
    for b in s:
        if b == 0:
            break
        s_str += chr(b) if 32 <= b <= 126 else '.'
    print(f"  Content: '{s_str}'")
    
    # Scan code for RIP-relative references to this address
    # In x64, a RIP-relative LEA would be: opcode + modrm + disp32
    # disp32 = target - (current + instruction_size)
    target_rva = rva
    
    # We can't easily scan backwards for references, but we can note the location
    # for manual analysis in x64dbg
    print(f"  [Note] Set breakpoint in x64dbg at VA 0x{va:X} to find code references")

# ========================================================================
# 7. SAVE RESULTS
# ========================================================================

print("\n" + "="*70)
print("[7] SAVING DETAILED RESULTS")
print("="*70)

output_file = Path("cs2_re_scan_results.txt")
with open(output_file, 'w') as f:
    f.write("CS2 client.dll Reverse Engineering Scan Results\n")
    f.write("=" * 70 + "\n\n")
    f.write(f"File: {CS2_CLIENT_DLL}\n")
    f.write(f"Image Base: 0x{image_base:X}\n")
    f.write(f".text: VA=0x{text_va:X}, Size=0x{text_size:X}\n\n")
    
    f.write("[CHAT STRINGS]\n")
    for s in CHAT_STRINGS:
        hits = string_hits[s.decode()]
        if hits:
            f.write(f"  '{s.decode()}': {len(hits)} hits\n")
            for offset, ctx in hits:
                rva = pe.get_rva_from_offset(offset)
                va = image_base + rva if rva else offset
                f.write(f"    0x{offset:X} (VA ~0x{va:X}): {ctx}\n")
    
    f.write("\n[TRACE STRINGS]\n")
    for s in TRACE_STRINGS:
        hits = string_hits[s.decode()]
        if hits:
            f.write(f"  '{s.decode()}': {len(hits)} hits\n")
    
    f.write("\n[MOVEMENT STRINGS]\n")
    for s in MOVEMENT_STRINGS:
        hits = string_hits[s.decode()]
        if hits:
            f.write(f"  '{s.decode()}': {len(hits)} hits\n")
    
    f.write("\n[PATTERN MATCHES]\n")
    for name, pattern in PATTERNS.items():
        matches = list(re.finditer(pattern, file_data))
        f.write(f"  {name}: {len(matches)} matches\n")
        for m in matches[:3]:
            offset = m.start()
            rva = pe.get_rva_from_offset(offset)
            va = image_base + rva if rva else 0
            f.write(f"    0x{offset:X} | RVA 0x{rva:X} | VA 0x{va:X}\n")
    
    f.write("\n[RIP-RELATIVE STRING REFERENCES]\n")
    for interest in sorted(by_interest.keys()):
        refs = by_interest[interest]
        f.write(f"  '{interest}': {len(refs)} refs\n")
        for ref in refs[:10]:
            f.write(f"    0x{ref['insn_addr']:X}: {ref['instruction']} -> '{ref['string']}'\n")
    
    f.write("\n[SAY STRING LOCATIONS FOR MANUAL ANALYSIS]\n")
    for so in say_offsets:
        rva = pe.get_rva_from_offset(so)
        va = image_base + rva
        f.write(f"  0x{so:X} (VA 0x{va:X})\n")

print(f"[*] Results saved to {output_file}")

pe.close()
print("\n[*] Scan complete!")
