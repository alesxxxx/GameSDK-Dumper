"""
Fast targeted scanner for CS2 client.dll
Focus: Chat, TraceRay, EdgeBug/JumpBug
Uses capstone + pefile
"""
import sys, struct, re
from pathlib import Path

import pefile
from capstone import *
from capstone.x86_const import *

# Find client.dll
CS2_CLIENT_DLL = None
for p in [
    Path(r"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game\csgo\bin\win64\client.dll"),
    Path(r"C:\Program Files\Steam\steamapps\common\Counter-Strike Global Offensive\game\csgo\bin\win64\client.dll"),
    Path(r"D:\Steam\steamapps\common\Counter-Strike Global Offensive\game\csgo\bin\win64\client.dll"),
    Path(r"E:\Steam\steamapps\common\Counter-Strike Global Offensive\game\csgo\bin\win64\client.dll"),
]:
    if p.exists():
        CS2_CLIENT_DLL = p
        break

if not CS2_CLIENT_DLL:
    print("ERROR: client.dll not found")
    sys.exit(1)

print(f"[*] File: {CS2_CLIENT_DLL}")
print(f"[*] Size: {CS2_CLIENT_DLL.stat().st_size / (1024*1024):.1f} MB")

# Load
pe = pefile.PE(str(CS2_CLIENT_DLL))
with open(CS2_CLIENT_DLL, 'rb') as f:
    data = f.read()

img_base = pe.OPTIONAL_HEADER.ImageBase

# Get sections
text_sec = None
rdata_sec = None
for s in pe.sections:
    n = s.Name.rstrip(b'\x00').decode('ascii', errors='ignore')
    if n == '.text':
        text_sec = s
    elif n == '.rdata':
        rdata_sec = s

if not text_sec:
    print("ERROR: no .text section")
    sys.exit(1)

text_data = data[text_sec.PointerToRawData:text_sec.PointerToRawData + text_sec.SizeOfRawData]
text_va = text_sec.VirtualAddress

# Capstone
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# ========================================================================
# 1. FAST STRING SEARCH IN ENTIRE BINARY
# ========================================================================

def extract_all_strings(min_len=3):
    """Extract null-terminated ASCII strings."""
    strings = []
    i = 0
    while i < len(data):
        start = i
        while i < len(data) and 32 <= data[i] <= 126:
            i += 1
        length = i - start
        if length >= min_len and start > 0 and data[start-1] == 0:
            strings.append((start, data[start:i].decode('ascii', errors='ignore')))
        # Skip nulls and non-printable
        while i < len(data) and (data[i] == 0 or data[i] < 32 or data[i] > 126):
            i += 1
    return strings

print("\n[*] Extracting strings...")
all_strings = extract_all_strings(min_len=4)
print(f"[*] Found {len(all_strings)} strings")

# ========================================================================
# 2. FIND CHAT-RELATED STRINGS
# ========================================================================

CHAT_KEYWORDS = ['say', 'say_team', 'chat', 'message', 'chatmsg', 'hudchat', 'chathud', 'sendchat', 'chatmessage']
print("\n" + "="*70)
print("[CHAT STRINGS]")
print("="*70)

chat_strings = []
for offset, s in all_strings:
    lower = s.lower()
    for kw in CHAT_KEYWORDS:
        if kw in lower:
            rva = pe.get_rva_from_offset(offset)
            va = img_base + rva if rva else 0
            chat_strings.append((offset, va, s))
            print(f"  0x{offset:08X} | VA 0x{va:012X} | '{s}'")
            break

# ========================================================================
# 3. FIND TRACE-RELATED STRINGS
# ========================================================================

TRACE_KEYWORDS = ['traceray', 'tracefilter', 'enginetrace', 'gametrace', 'mask_playersolid', 'categorizeposition', 'categorize']
print("\n" + "="*70)
print("[TRACE/MOVEMENT STRINGS]")
print("="*70)

trace_strings = []
for offset, s in all_strings:
    lower = s.lower()
    for kw in TRACE_KEYWORDS:
        if kw in lower:
            rva = pe.get_rva_from_offset(offset)
            va = img_base + rva if rva else 0
            trace_strings.append((offset, va, s))
            print(f"  0x{offset:08X} | VA 0x{va:012X} | '{s}'")
            break

# ========================================================================
# 4. PATTERN SCANNING IN .TEXT
# ========================================================================

print("\n" + "="*70)
print("[BYTE PATTERN MATCHES IN .TEXT]")
print("="*70)

PATTERNS = {
    "TraceRay (known)": rb'\x48\x89\x5C\x24.\x48\x89\x4C\x24.\x55\x57',
    "CreateMove (known)": rb'\x48\x8B\xC4\x4C\x89\x40.\x48\x89\x48.\x55\x53\x41\x54',
    "CCSGOInput (known)": rb'\x48\x8B\x0D....\x48\x8B\x01\xFF\x50.\x8B\xDF',
    "GetViewAngles (known)": rb'\x4C\x8B\xC1\x85\xD2\x74\x08\x48\x8D\x05....\xC3',
    "SetViewAngles (known)": rb'\x85\xD2\x75.\x48\x63\x81',
    "sub_rsp_frame": rb'\x48\x83\xEC',  # Common prologue
    "mov_stack_1": rb'\x48\x89\x5C\x24',  # mov [rsp+off], rbx
    "mov_stack_2": rb'\x48\x89\x74\x24',  # mov [rsp+off], rsi
    "mov_stack_3": rb'\x48\x89\x7C\x24',  # mov [rsp+off], rdi
}

pattern_results = {}
for name, pat in PATTERNS.items():
    matches = []
    for m in re.finditer(pat, text_data):
        raw_off = text_sec.PointerToRawData + m.start()
        rva = text_va + m.start()
        va = img_base + rva
        matches.append((va, raw_off, m.group()))
    pattern_results[name] = matches
    if matches:
        print(f"\n  {name}: {len(matches)} matches")
        for va, raw_off, bytes_found in matches[:3]:
            hex_str = ' '.join(f'{b:02X}' for b in bytes_found[:16])
            print(f"    VA 0x{va:012X} | Raw 0x{raw_off:08X} | {hex_str}")

# ========================================================================
# 5. DISASSEMBLE AROUND TRACE-RAY CANDIDATES
# ========================================================================

print("\n" + "="*70)
print("[DISASSEMBLY: TraceRay CANDIDATES]")
print("="*70)

trace_ray_matches = pattern_results.get("TraceRay (known)", [])
for i, (va, raw_off, _) in enumerate(trace_ray_matches[:5]):
    print(f"\n  Candidate #{i+1} at VA 0x{va:012X}")
    
    # Get code around it
    text_off = raw_off - text_sec.PointerToRawData
    start = max(0, text_off - 48)
    end = min(len(text_data), text_off + 128)
    code = text_data[start:end]
    base = img_base + text_va + start
    
    for insn in md.disasm(code, base, len(code)):
        marker = " <== PATTERN" if insn.address == va else ""
        print(f"    0x{insn.address:012X}: {insn.mnemonic:8s} {insn.op_str:40s}{marker}")
        if insn.address > va + 64:
            break

# ========================================================================
# 6. RIP-RELATIVE REFERENCE SCANNER (FASTER VERSION)
# ========================================================================

print("\n" + "="*70)
print("[RIP-RELATIVE STRING REFERENCES IN .TEXT]")
print("="*70)

def find_rip_refs_fast(target_strings, max_refs=5):
    """Find RIP-relative LEA/MOV instructions referencing our target strings."""
    
    # Build a map of string RVAs for quick lookup
    string_rvas = {}
    for offset, va, s in target_strings:
        rva = va - img_base
        string_rvas[rva] = s
    
    refs = {}
    # Scan .text for RIP-relative instructions
    # In x64, RIP-relative uses: mod=00, r/m=101 (disp32 follows)
    # We scan for common opcodes: 48 8D 05 (LEA rax, [rip+disp32])
    #                          48 8D 0D (LEA rcx, [rip+disp32])
    #                          48 8D 15 (LEA rdx, [rip+disp32])
    #                          48 8B 05 (MOV rax, [rip+disp32])
    #                          48 8B 0D (MOV rcx, [rip+disp32])
    
    rip_prefixes = {
        b'\x48\x8D\x05': 'LEA rax',
        b'\x48\x8D\x0D': 'LEA rcx',
        b'\x48\x8D\x15': 'LEA rdx',
        b'\x48\x8D\x1D': 'LEA rbx',
        b'\x48\x8B\x05': 'MOV rax',
        b'\x48\x8B\x0D': 'MOV rcx',
        b'\x48\x8B\x15': 'MOV rdx',
        b'\x48\x8B\x1D': 'MOV rbx',
    }
    
    for prefix, desc in rip_prefixes.items():
        for m in re.finditer(re.escape(prefix) + rb'.{4}', text_data):
            text_off = m.start()
            raw_off = text_sec.PointerToRawData + text_off
            rva = text_va + text_off
            va = img_base + rva
            
            # Extract disp32 (little-endian)
            disp = struct.unpack('<i', m.group()[3:7])[0]
            target_rva = rva + 7 + disp  # 7 = instruction size
            target_va = img_base + target_rva
            
            # Check if this points to one of our strings
            for str_rva, str_text in string_rvas.items():
                # Allow small tolerance for alignment
                if abs(target_rva - str_rva) <= 4:
                    key = str_text[:40]
                    if key not in refs:
                        refs[key] = []
                    if len(refs[key]) < max_refs:
                        refs[key].append({
                            'va': va,
                            'target_va': img_base + str_rva,
                            'disp': disp,
                            'desc': desc,
                            'raw_off': raw_off
                        })
                    break
    
    return refs

print("[*] Scanning .text for RIP-relative references...")
chat_refs = find_rip_refs_fast(chat_strings, max_refs=10)
trace_refs = find_rip_refs_fast(trace_strings, max_refs=10)

print("\n  --- CHAT STRING CODE REFERENCES ---")
for s, refs in sorted(chat_refs.items(), key=lambda x: -len(x[1])):
    print(f"\n  '{s}': {len(refs)} code refs")
    for ref in refs[:5]:
        print(f"    0x{ref['va']:012X}: {ref['desc']} [rip+0x{ref['disp']:08X}] -> 0x{ref['target_va']:012X}")

print("\n  --- TRACE/MOVEMENT STRING CODE REFERENCES ---")
for s, refs in sorted(trace_refs.items(), key=lambda x: -len(x[1])):
    print(f"\n  '{s}': {len(refs)} code refs")
    for ref in refs[:5]:
        print(f"    0x{ref['va']:012X}: {ref['desc']} [rip+0x{ref['disp']:08X}] -> 0x{ref['target_va']:012X}")

# ========================================================================
# 7. FIND 'say' COMMAND PROCESSING
# ========================================================================

print("\n" + "="*70)
print("[SAY COMMAND ANALYSIS]")
print("="*70)

# Find exact "say\x00" and "say_team\x00" strings
say_locations = []
for offset in range(len(data) - 9):
    if data[offset:offset+4] == b'say\x00':
        say_locations.append((offset, 'say'))
    if data[offset:offset+9] == b'say_team\x00':
        say_locations.append((offset, 'say_team'))

print(f"[*] Found {len(say_locations)} 'say'/'say_team' null-terminated strings")

# Find RIP references to these exact locations
for offset, cmd in say_locations:
    rva = pe.get_rva_from_offset(offset)
    va = img_base + rva
    
    # Search for references to this VA in .text
    target_bytes = struct.pack('<I', rva - img_base)  # This is wrong, we need disp32, not RVA
    
    # Actually: disp32 = target_rva - (current_rva + 7)
    # So: target_rva = current_rva + 7 + disp32
    # We need to find all disp32 where target_rva ≈ our string's rva
    
    refs_to_this = []
    for prefix in [b'\x48\x8D\x05', b'\x48\x8D\x0D', b'\x48\x8B\x05', b'\x48\x8B\x0D']:
        for m in re.finditer(re.escape(prefix) + rb'.{4}', text_data):
            text_off = m.start()
            insn_rva = text_va + text_off
            disp = struct.unpack('<i', m.group()[3:7])[0]
            calc_target = insn_rva + 7 + disp
            
            if abs(calc_target - rva) <= 2:
                insn_va = img_base + insn_rva
                refs_to_this.append(insn_va)
    
    print(f"\n  '{cmd}' string at VA 0x{va:012X}")
    print(f"    {len(refs_to_this)} code references found:")
    for ref_va in refs_to_this[:8]:
        print(f"      Referenced at VA 0x{ref_va:012X}")

# ========================================================================
# 8. SAVE RESULTS
# ========================================================================

output = Path("cs2_targeted_scan_results.txt")
with open(output, 'w') as f:
    f.write("CS2 Targeted Reverse Engineering Scan\n")
    f.write(f"File: {CS2_CLIENT_DLL}\n")
    f.write(f"Image Base: 0x{img_base:012X}\n\n")
    
    f.write("=== CHAT STRINGS ===\n")
    for offset, va, s in chat_strings:
        f.write(f"0x{offset:08X} | VA 0x{va:012X} | {s}\n")
    
    f.write("\n=== TRACE/MOVEMENT STRINGS ===\n")
    for offset, va, s in trace_strings:
        f.write(f"0x{offset:08X} | VA 0x{va:012X} | {s}\n")
    
    f.write("\n=== PATTERN MATCHES ===\n")
    for name, matches in pattern_results.items():
        if matches:
            f.write(f"\n{name}: {len(matches)} matches\n")
            for va, raw_off, _ in matches[:5]:
                f.write(f"  VA 0x{va:012X} | Raw 0x{raw_off:08X}\n")
    
    f.write("\n=== CHAT CODE REFERENCES ===\n")
    for s, refs in chat_refs.items():
        f.write(f"\n'{s}': {len(refs)} refs\n")
        for ref in refs[:10]:
            f.write(f"  0x{ref['va']:012X}: {ref['desc']} -> 0x{ref['target_va']:012X}\n")
    
    f.write("\n=== TRACE CODE REFERENCES ===\n")
    for s, refs in trace_refs.items():
        f.write(f"\n'{s}': {len(refs)} refs\n")
        for ref in refs[:10]:
            f.write(f"  0x{ref['va']:012X}: {ref['desc']} -> 0x{ref['target_va']:012X}\n")
    
    f.write("\n=== SAY COMMAND LOCATIONS ===\n")
    for offset, cmd in say_locations:
        rva = pe.get_rva_from_offset(offset)
        va = img_base + rva
        f.write(f"0x{offset:08X} | VA 0x{va:012X} | {cmd}\n")

print(f"\n[*] Results saved to {output}")
pe.close()
print("[*] Done!")
