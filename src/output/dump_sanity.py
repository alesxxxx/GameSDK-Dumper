from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Tuple


class DumpSanityError(ValueError):
    pass


@dataclass
class DumpSanityReport:
    total_types: int = 0
    total_members: int = 0
    none_package_types: int = 0
    empty_package_types: int = 0
    size_violations: int = 0
    suspicious_members: int = 0
    unresolved_chain_offsets: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    suspected_layout_mismatch: bool = False

    @property
    def ok(self) -> bool:
        return not self.reasons

    def format_reasons(self) -> str:
        return "; ".join(self.reasons) if self.reasons else "dump passed sanity gates"


def _load_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {}


def _int_value(value, default: int = 0) -> int:
    try:
        if isinstance(value, str):
            return int(value, 0)
        return int(value)
    except (TypeError, ValueError):
        return default


def _v2_entries(offsets_dir: str) -> Iterable[dict]:
    for name in ("ClassesInfoV2.json", "StructsInfoV2.json"):
        payload = _load_json(os.path.join(offsets_dir, name))
        if payload.get("schema_version") != 2:
            continue
        for entry in payload.get("data", []) or []:
            if isinstance(entry, dict):
                yield entry


def _legacy_entries(offsets_dir: str) -> Iterable[Tuple[str, int, List[Tuple[str, int, int, int]]]]:
    for name in ("ClassesInfo.json", "StructsInfo.json"):
        payload = _load_json(os.path.join(offsets_dir, name))
        for entry in payload.get("data", []) or []:
            if not isinstance(entry, dict) or not entry:
                continue
            full_name, details = next(iter(entry.items()))
            if not isinstance(details, list):
                continue
            type_size = 0
            members: List[Tuple[str, int, int, int]] = []
            for item in details:
                if not isinstance(item, dict):
                    continue
                if "__MDKClassSize" in item:
                    type_size = _int_value(item.get("__MDKClassSize"))
                    continue
                for field_name, field_def in item.items():
                    if field_name.startswith("__"):
                        continue
                    if isinstance(field_def, list) and len(field_def) >= 3:
                        members.append(
                            (
                                str(field_name),
                                _int_value(field_def[1]),
                                _int_value(field_def[2]),
                                1,
                            )
                        )
            yield str(full_name), type_size, members


def _member_is_suspicious(name: str, offset: int, size: int, array_dim: int, flags: int = 0) -> bool:
    if offset == 0x202:
        return True
    if offset > 0x200000 or size > 0x100000 or array_dim > 4096:
        return True
    if name == "None" and size >= 0x8000:
        return True
    if 0x10000 <= flags < 0x7FFFFFFFFFFF:
        return True
    return False


def _load_legacy_data(offsets_dir: str) -> Tuple[list, list]:
    classes = _load_json(os.path.join(offsets_dir, "ClassesInfo.json")).get("data", [])
    structs = _load_json(os.path.join(offsets_dir, "StructsInfo.json")).get("data", [])
    return (
        classes if isinstance(classes, list) else [],
        structs if isinstance(structs, list) else [],
    )


def check_dump_dir_sanity(
    offsets_dir: str,
    *,
    require_chains: bool = True,
    min_types_for_strict: int = 100,
    min_members_for_strict: int = 25,
) -> DumpSanityReport:
    report = DumpSanityReport()

    v2_entries = list(_v2_entries(offsets_dir))
    if v2_entries:
        for entry in v2_entries:
            report.total_types += 1
            package = str(entry.get("package", "") or "")
            if package == "None":
                report.none_package_types += 1
            elif not package:
                report.empty_package_types += 1

            type_size = _int_value(entry.get("size"))
            for member in entry.get("members", []) or []:
                if not isinstance(member, dict):
                    continue
                report.total_members += 1
                offset = _int_value(member.get("offset"))
                member_size = _int_value(member.get("size"))
                array_dim = _int_value(member.get("array_dim"), 1)
                flags = _int_value(member.get("flags"))
                if offset + member_size > type_size:
                    report.size_violations += 1
                if _member_is_suspicious(
                    str(member.get("name", "") or ""),
                    offset,
                    member_size,
                    array_dim,
                    flags,
                ):
                    report.suspicious_members += 1
    else:
        for full_name, type_size, members in _legacy_entries(offsets_dir):
            report.total_types += 1
            package = full_name.split(".", 1)[0] if "." in full_name else ""
            if package == "None":
                report.none_package_types += 1
            elif not package:
                report.empty_package_types += 1
            for member_name, offset, member_size, array_dim in members:
                report.total_members += 1
                if offset + member_size > type_size:
                    report.size_violations += 1
                if _member_is_suspicious(member_name, offset, member_size, array_dim):
                    report.suspicious_members += 1

    if report.total_types >= min_types_for_strict:
        bad_pkg_count = report.none_package_types + report.empty_package_types
        bad_pkg_pct = bad_pkg_count / max(1, report.total_types) * 100.0
        if bad_pkg_pct >= 85.0:
            report.reasons.append(
                f"{bad_pkg_pct:.0f}% of exported types resolved to None/empty packages"
            )

    if report.total_members >= min_members_for_strict:
        violation_pct = report.size_violations / max(1, report.total_members) * 100.0
        if violation_pct > 5.0:
            report.reasons.append(
                f"{violation_pct:.0f}% of members exceed their owner PropertiesSize"
            )

        suspicious_pct = report.suspicious_members / max(1, report.total_members) * 100.0
        if violation_pct > 20.0 and suspicious_pct > 20.0:
            report.suspected_layout_mismatch = True
            report.reasons.append(
                "suspected UE FField layout mismatch (shifted offsets/huge ArrayDim or ElementSize)"
            )

    if require_chains and report.total_types >= min_types_for_strict:
        try:
            from src.output.utils import resolve_standard_chain

            classes_data, structs_data = _load_legacy_data(offsets_dir)
            chain = resolve_standard_chain(classes_data, structs_data)
            report.unresolved_chain_offsets = [
                key for key, value in chain.items() if value is None
            ]
            if len(report.unresolved_chain_offsets) >= 4:
                report.reasons.append(
                    "standard player pointer chain offsets are mostly unresolved"
                )
        except Exception as exc:
            report.reasons.append(f"could not validate pointer chain offsets: {exc}")

    return report


def assert_dump_dir_sane(offsets_dir: str, *, require_chains: bool = True) -> DumpSanityReport:
    report = check_dump_dir_sanity(offsets_dir, require_chains=require_chains)
    if not report.ok:
        raise DumpSanityError(report.format_reasons())
    return report
