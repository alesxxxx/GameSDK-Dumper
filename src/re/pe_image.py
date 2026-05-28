import os
import re
import struct
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence

from src.re.signatures import (
    SignatureHit,
    StringResult,
    XrefResult,
    resolve_relative_from_image,
    scan_ida_pattern,
)


IMAGE_SCN_MEM_EXECUTE = 0x20000000


@dataclass
class PESection:
    name: str
    rva: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def is_executable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)

    def contains_rva(self, rva: int) -> bool:
        size = max(self.virtual_size, self.raw_size)
        return self.rva <= rva < self.rva + size


class PEImage:
    def __init__(self, path: str):
        try:
            import pefile
        except ImportError as exc:
            raise RuntimeError("pefile is required for offline signature research. Run: pip install pefile") from exc

        self.path = os.path.abspath(path)
        self.pe = pefile.PE(self.path, fast_load=False)
        with open(self.path, "rb") as handle:
            self.data = handle.read()
        self.image_base = int(self.pe.OPTIONAL_HEADER.ImageBase)
        self.sections: List[PESection] = []
        for section in self.pe.sections:
            name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            self.sections.append(
                PESection(
                    name=name,
                    rva=int(section.VirtualAddress),
                    virtual_size=int(section.Misc_VirtualSize),
                    raw_offset=int(section.PointerToRawData),
                    raw_size=int(section.SizeOfRawData),
                    characteristics=int(section.Characteristics),
                )
            )

    @property
    def module_name(self) -> str:
        return os.path.basename(self.path)

    def section_for_rva(self, rva: int) -> Optional[PESection]:
        for section in self.sections:
            if section.contains_rva(rva):
                return section
        return None

    def rva_to_offset(self, rva: int) -> int:
        try:
            return int(self.pe.get_offset_from_rva(rva))
        except Exception:
            section = self.section_for_rva(rva)
            if section is None:
                return -1
            return section.raw_offset + (rva - section.rva)

    def offset_to_rva(self, offset: int) -> int:
        try:
            return int(self.pe.get_rva_from_offset(offset))
        except Exception:
            for section in self.sections:
                if section.raw_offset <= offset < section.raw_offset + section.raw_size:
                    return section.rva + (offset - section.raw_offset)
        return -1

    def va_to_rva(self, va: int) -> int:
        return va - self.image_base

    def rva_to_va(self, rva: int) -> int:
        return self.image_base + rva

    def get_bytes_rva(self, rva: int, size: int) -> bytes:
        offset = self.rva_to_offset(rva)
        if offset < 0:
            return b""
        return self.data[offset:offset + size]

    def scan_pattern(self, pattern: str, max_results: int = 50) -> List[SignatureHit]:
        hits: List[SignatureHit] = []
        for offset in scan_ida_pattern(self.data, pattern, max_results=max_results):
            rva = self.offset_to_rva(offset)
            if rva < 0:
                continue
            section = self.section_for_rva(rva)
            hits.append(
                SignatureHit(
                    rva=rva,
                    va=self.rva_to_va(rva),
                    file_offset=offset,
                    section=section.name if section else "",
                )
            )
        return hits

    def resolve_hit(self, hit: SignatureHit, *, disp_offset: int, instruction_size: int, extra_offset: int = 0) -> None:
        resolved = resolve_relative_from_image(
            self.data,
            hit.rva,
            hit.file_offset,
            self.image_base,
            disp_offset=disp_offset,
            instruction_size=instruction_size,
            extra_offset=extra_offset,
        )
        if resolved is None:
            return
        hit.resolved_rva, hit.resolved_va = resolved

    def get_export(self, symbol: str) -> Optional[SignatureHit]:
        if not hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            try:
                self.pe.parse_data_directories(
                    directories=[
                        self.pefile_DIRECTORY_ENTRY_EXPORT,
                    ]
                )
            except Exception:
                pass
        directory = getattr(self.pe, "DIRECTORY_ENTRY_EXPORT", None)
        if not directory:
            return None
        for export in directory.symbols:
            if export.name is None:
                continue
            name = export.name.decode("utf-8", errors="replace")
            if name != symbol:
                continue
            rva = int(export.address)
            offset = self.rva_to_offset(rva)
            section = self.section_for_rva(rva)
            return SignatureHit(
                rva=rva,
                va=self.rva_to_va(rva),
                file_offset=offset,
                section=section.name if section else "",
            )
        return None

    @property
    def pefile_DIRECTORY_ENTRY_EXPORT(self):
        import pefile

        return pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]

    def find_strings(
        self,
        *,
        queries: Sequence[str] = (),
        min_len: int = 4,
        limit: int = 200,
        include_utf16: bool = True,
    ) -> List[StringResult]:
        results: List[StringResult] = []
        lower_queries = [q.lower() for q in queries if q]

        ascii_re = re.compile(rb"[\x20-\x7E]{" + str(max(1, min_len)).encode("ascii") + rb",}")
        for match in ascii_re.finditer(self.data):
            value = match.group(0).decode("ascii", errors="replace")
            if lower_queries and not any(query in value.lower() for query in lower_queries):
                continue
            rva = self.offset_to_rva(match.start())
            if rva < 0:
                continue
            section = self.section_for_rva(rva)
            results.append(
                StringResult(
                    rva=rva,
                    va=self.rva_to_va(rva),
                    file_offset=match.start(),
                    value=value,
                    encoding="ascii",
                    section=section.name if section else "",
                )
            )
            if len(results) >= limit:
                return results

        if not include_utf16:
            return results

        # Lightweight UTF-16LE scanner for printable ASCII-range text.
        i = 0
        while i + (min_len * 2) <= len(self.data) and len(results) < limit:
            start = i
            chars: List[str] = []
            while i + 1 < len(self.data):
                ch, zero = self.data[i], self.data[i + 1]
                if zero == 0 and 32 <= ch <= 126:
                    chars.append(chr(ch))
                    i += 2
                    continue
                break
            if len(chars) >= min_len:
                value = "".join(chars)
                if not lower_queries or any(query in value.lower() for query in lower_queries):
                    rva = self.offset_to_rva(start)
                    if rva >= 0:
                        section = self.section_for_rva(rva)
                        results.append(
                            StringResult(
                                rva=rva,
                                va=self.rva_to_va(rva),
                                file_offset=start,
                                value=value,
                                encoding="utf16le",
                                section=section.name if section else "",
                            )
                        )
            i = max(i + 2, start + 2)

        return results

    def _executable_ranges(self) -> Iterable[PESection]:
        for section in self.sections:
            if section.is_executable and section.raw_size:
                yield section

    def find_rip_xrefs(self, target_rvas: Sequence[int], *, tolerance: int = 0, limit: int = 200) -> List[XrefResult]:
        targets = list(target_rvas)
        if not targets:
            return []
        results: List[XrefResult] = []
        # Common x64 RIP-relative opcodes.  tuple(prefix, disp_offset, instr_len)
        forms = [
            (b"\x48\x8D\x05", 3, 7),
            (b"\x48\x8D\x0D", 3, 7),
            (b"\x48\x8D\x15", 3, 7),
            (b"\x48\x8D\x1D", 3, 7),
            (b"\x48\x8B\x05", 3, 7),
            (b"\x48\x8B\x0D", 3, 7),
            (b"\x48\x8B\x15", 3, 7),
            (b"\x48\x89\x05", 3, 7),
            (b"\x4C\x8D\x05", 3, 7),
            (b"\x4C\x8B\x05", 3, 7),
            (b"\x8B\x05", 2, 6),
            (b"\x8D\x05", 2, 6),
            (b"\x89\x05", 2, 6),
        ]
        for section in self._executable_ranges():
            chunk = self.data[section.raw_offset:section.raw_offset + section.raw_size]
            for prefix, disp_offset, instr_len in forms:
                pos = 0
                while len(results) < limit:
                    idx = chunk.find(prefix, pos)
                    if idx < 0 or idx + instr_len > len(chunk):
                        break
                    disp = struct.unpack_from("<i", chunk, idx + disp_offset)[0]
                    source_rva = section.rva + idx
                    target_rva = source_rva + instr_len + disp
                    if any(abs(target_rva - target) <= tolerance for target in targets):
                        results.append(
                            XrefResult(
                                source_rva=source_rva,
                                source_va=self.rva_to_va(source_rva),
                                target_rva=target_rva,
                                target_va=self.rva_to_va(target_rva),
                                instruction=f"{prefix.hex(' ').upper()} rel32",
                                section=section.name,
                            )
                        )
                    pos = idx + 1
        return results

    def disassemble(self, rva: int, *, before: int = 0, size: int = 160) -> List[Dict[str, object]]:
        try:
            from capstone import CS_ARCH_X86, CS_MODE_64, Cs
        except ImportError as exc:
            raise RuntimeError("capstone is required for disassembly. Run: pip install capstone") from exc
        start_rva = max(0, rva - before)
        start_offset = self.rva_to_offset(start_rva)
        if start_offset < 0:
            return []
        code = self.data[start_offset:start_offset + size]
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        rows = []
        for insn in md.disasm(code, self.rva_to_va(start_rva)):
            rows.append(
                {
                    "rva": insn.address - self.image_base,
                    "va": insn.address,
                    "bytes": bytes(insn.bytes).hex(" ").upper(),
                    "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str,
                }
            )
        return rows
