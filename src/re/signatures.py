import json
import re
import struct
from dataclasses import asdict, dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


_HEX_TOKEN_RE = re.compile(r"^[0-9A-Fa-f]{2}$")


@dataclass
class SignatureEntry:
    name: str
    module: str
    kind: str = "pattern"
    pattern: str = ""
    fallbacks: List[str] = field(default_factory=list)
    symbol: str = ""
    resolve: str = "direct"
    disp_offset: int = 3
    instruction_size: int = 7
    extra_offset: int = 0
    required: bool = False
    description: str = ""
    source: str = ""


@dataclass
class SignatureHit:
    rva: int
    va: int
    file_offset: int = -1
    section: str = ""
    resolved_rva: Optional[int] = None
    resolved_va: Optional[int] = None


@dataclass
class ValidationResult:
    entry: SignatureEntry
    found: bool
    hits: List[SignatureHit] = field(default_factory=list)
    score: str = "failed"
    error: str = ""
    evidence: Dict[str, object] = field(default_factory=dict)


@dataclass
class StringResult:
    rva: int
    va: int
    file_offset: int
    value: str
    encoding: str = "ascii"
    section: str = ""


@dataclass
class XrefResult:
    source_rva: int
    source_va: int
    target_rva: int
    target_va: int
    instruction: str = ""
    section: str = ""


@dataclass
class CandidateSignature:
    module: str
    rva: int
    va: int
    pattern: str
    length: int
    hit_count: int
    score: str
    reason: str = ""


def to_jsonable(value):
    if hasattr(value, "__dataclass_fields__"):
        return asdict(value)
    if isinstance(value, list):
        return [to_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {key: to_jsonable(item) for key, item in value.items()}
    return value


def dump_json(value) -> str:
    return json.dumps(to_jsonable(value), indent=2)


def parse_ida_pattern(pattern: str) -> Tuple[List[int], List[bool]]:
    """Parse IDA-style patterns using ``?`` or ``??`` wildcards."""
    bytes_out: List[int] = []
    mask: List[bool] = []
    for token in pattern.strip().split():
        if token in {"?", "??"}:
            bytes_out.append(0)
            mask.append(False)
        elif _HEX_TOKEN_RE.match(token):
            bytes_out.append(int(token, 16))
            mask.append(True)
        else:
            raise ValueError(f"invalid pattern token {token!r} in {pattern!r}")
    if not bytes_out:
        raise ValueError("pattern must contain at least one byte")
    return bytes_out, mask


def normalize_pattern(pattern: str) -> str:
    bytes_out, mask = parse_ida_pattern(pattern)
    return " ".join(f"{byte:02X}" if is_fixed else "?" for byte, is_fixed in zip(bytes_out, mask))


def looks_like_ida_pattern(value: str) -> bool:
    tokens = value.strip().split()
    if len(tokens) < 2:
        return False
    return all(token in {"?", "??"} or bool(_HEX_TOKEN_RE.match(token)) for token in tokens)


def _prefix_for_pattern(pattern_bytes: Sequence[int], mask: Sequence[bool]) -> bytes:
    fixed = []
    for byte, is_fixed in zip(pattern_bytes, mask):
        if not is_fixed:
            break
        fixed.append(byte)
    if fixed:
        return bytes(fixed)
    for byte, is_fixed in zip(pattern_bytes, mask):
        if is_fixed:
            return bytes([byte])
    return b""


def _matches_at(data: bytes, offset: int, pattern_bytes: Sequence[int], mask: Sequence[bool]) -> bool:
    for idx, byte in enumerate(pattern_bytes):
        if mask[idx] and data[offset + idx] != byte:
            return False
    return True


def scan_ida_pattern(data: bytes, pattern: str, max_results: int = 50) -> List[int]:
    pattern_bytes, mask = parse_ida_pattern(pattern)
    pat_len = len(pattern_bytes)
    if len(data) < pat_len:
        return []

    prefix = _prefix_for_pattern(pattern_bytes, mask)
    results: List[int] = []
    search_end = len(data) - pat_len + 1
    pos = 0

    if not prefix:
        while pos < search_end and len(results) < max_results:
            if _matches_at(data, pos, pattern_bytes, mask):
                results.append(pos)
            pos += 1
        return results

    while pos < search_end and len(results) < max_results:
        found = data.find(prefix, pos)
        if found < 0 or found >= search_end:
            break
        # If the fixed prefix starts after one or more wildcard bytes, test a
        # small window of possible starts around the found byte.
        start_min = max(0, found - len(pattern_bytes) + 1)
        tested = False
        for start in range(start_min, found + 1):
            if start >= pos and start < search_end and _matches_at(data, start, pattern_bytes, mask):
                results.append(start)
                tested = True
                break
        pos = (found + 1) if not tested else (results[-1] + 1)

    return results


def resolve_relative_from_image(
    data: bytes,
    match_rva: int,
    match_offset: int,
    image_base: int,
    *,
    disp_offset: int,
    instruction_size: int,
    extra_offset: int = 0,
) -> Optional[Tuple[int, int]]:
    disp_at = match_offset + disp_offset
    if disp_at < 0 or disp_at + 4 > len(data):
        return None
    disp = struct.unpack_from("<i", data, disp_at)[0]
    target_rva = match_rva + instruction_size + disp + extra_offset
    return target_rva, image_base + target_rva


def score_hit_count(hit_count: int, *, section_quality: bool = True, cross_build: bool = True) -> str:
    if hit_count <= 0:
        return "failed"
    if hit_count == 1 and section_quality and cross_build:
        return "strong"
    if hit_count <= 3 and section_quality:
        return "usable"
    return "broad"


def format_bytes_as_pattern(data: bytes, mask: Optional[Iterable[bool]] = None) -> str:
    if mask is None:
        return " ".join(f"{byte:02X}" for byte in data)
    return " ".join(f"{byte:02X}" if fixed else "?" for byte, fixed in zip(data, mask))


def mask_volatile_x64_bytes(code: bytes) -> List[bool]:
    """Return a conservative fixed-byte mask for x86-64 signature generation.

    This intentionally uses byte-level heuristics instead of requiring Capstone.
    It masks the bytes that most commonly change between builds: rel32 call/jmp
    displacements, RIP-relative displacements, immediate stack sizes, and
    conditional branch displacements.
    """
    mask = [True] * len(code)
    i = 0
    while i < len(code):
        b0 = code[i]

        # call/jmp rel32
        if b0 in (0xE8, 0xE9) and i + 5 <= len(code):
            for j in range(i + 1, i + 5):
                mask[j] = False
            i += 5
            continue

        # jcc rel32
        if b0 == 0x0F and i + 6 <= len(code) and 0x80 <= code[i + 1] <= 0x8F:
            for j in range(i + 2, i + 6):
                mask[j] = False
            i += 6
            continue

        # short jumps/branches
        if b0 in (0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
                  0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0xEB) and i + 2 <= len(code):
            mask[i + 1] = False
            i += 2
            continue

        # sub/add rsp, imm8 or imm32
        if i + 4 <= len(code) and code[i:i + 3] in (b"\x48\x83\xEC", b"\x48\x83\xC4"):
            mask[i + 3] = False
            i += 4
            continue
        if i + 7 <= len(code) and code[i:i + 3] in (b"\x48\x81\xEC", b"\x48\x81\xC4"):
            for j in range(i + 3, i + 7):
                mask[j] = False
            i += 7
            continue

        # Common RIP-relative forms:
        # REX 8B/8D/89/39/3B/0F10/0F11 ... modrm with r/m=101
        if i + 7 <= len(code) and code[i] in (0x48, 0x4C, 0x49, 0x44):
            op_index = i + 1
            if code[op_index] in (0x8B, 0x8D, 0x89, 0x39, 0x3B):
                modrm = code[op_index + 1]
                if (modrm & 0xC7) == 0x05:
                    for j in range(op_index + 2, op_index + 6):
                        mask[j] = False
                    i += 7
                    continue
            if i + 8 <= len(code) and code[op_index] == 0x0F and code[op_index + 1] in (0x10, 0x11):
                modrm = code[op_index + 2]
                if (modrm & 0xC7) == 0x05:
                    for j in range(op_index + 3, op_index + 7):
                        mask[j] = False
                    i += 8
                    continue

        # Non-REX RIP-relative forms.
        if i + 6 <= len(code) and code[i] in (0x8B, 0x8D, 0x89, 0x39, 0x3B):
            modrm = code[i + 1]
            if (modrm & 0xC7) == 0x05:
                for j in range(i + 2, i + 6):
                    mask[j] = False
                i += 6
                continue

        i += 1
    return mask


def generate_masked_patterns(
    module: str,
    image_base: int,
    data: bytes,
    rva: int,
    file_offset: int,
    lengths: Sequence[int] = (16, 24, 32, 40),
) -> List[CandidateSignature]:
    candidates: List[CandidateSignature] = []
    for length in lengths:
        if file_offset < 0 or file_offset + length > len(data):
            continue
        chunk = data[file_offset:file_offset + length]
        pattern = format_bytes_as_pattern(chunk, mask_volatile_x64_bytes(chunk))
        hit_count = len(scan_ida_pattern(data, pattern, max_results=1000))
        candidates.append(
            CandidateSignature(
                module=module,
                rva=rva,
                va=image_base + rva,
                pattern=pattern,
                length=length,
                hit_count=hit_count,
                score=score_hit_count(hit_count),
                reason="unique masked byte window" if hit_count == 1 else f"{hit_count} matches in module",
            )
        )
    return candidates
