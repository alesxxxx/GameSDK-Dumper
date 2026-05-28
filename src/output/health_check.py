
import os
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from src.core.models import SDKDump

@dataclass
class HealthReport:
    total_structs: int = 0
    total_enums: int = 0
    total_members: int = 0
    total_static_fields: int = 0
    structs_with_size_violations: List[Tuple[str, str, int, int, int]] = field(default_factory=list)
    structs_with_zero_members: List[str] = field(default_factory=list)
    enums_with_zero_values: List[str] = field(default_factory=list)
    gworld_valid: Optional[bool] = None
    gobjects_valid: Optional[bool] = None
    fname_sample: List[str] = field(default_factory=list)
    version_layout_match: Optional[bool] = None
    none_package_types: int = 0
    empty_package_types: int = 0
    suspicious_member_patterns: int = 0
    suspected_layout_mismatch: bool = False
    confidence_grade: str = ""
    confidence_reasons: List[str] = field(default_factory=list)

def run_health_check(
    dump: SDKDump,
    handle: int = 0,
    gobjects_ptr: int = 0,
    gnames_ptr: int = 0,
    gworld_addr: int = 0,
    module_base: int = 0,
    module_size: int = 0,
    ue_version: str = "",
    case_preserving: bool = False,
    item_size: int = 24,
) -> HealthReport:
    report = HealthReport()

    classes = [s for s in dump.structs if s.is_class]
    structs = [s for s in dump.structs if not s.is_class]

    report.total_structs = len(dump.structs)
    report.total_enums = len(dump.enums)
    report.total_members = sum(len(s.members) for s in dump.structs)

    for s in dump.structs:
        if s.package == "None":
            report.none_package_types += 1
        elif not s.package:
            report.empty_package_types += 1
        for m in s.members:
            if getattr(m, "is_static", False):
                report.total_static_fields += 1
                continue
            if m.offset + m.size > s.size:
                report.structs_with_size_violations.append(
                    (s.name, m.name, m.offset, m.size, s.size)
                )
            flags = int(getattr(m, "flags", 0) or 0)
            if (
                m.offset == 0x202
                or m.offset > 0x200000
                or m.size > 0x100000
                or int(getattr(m, "array_dim", 1) or 1) > 4096
                or (m.name == "None" and m.size >= 0x8000)
                or (0x10000 <= flags < 0x7FFFFFFFFFFF)
            ):
                report.suspicious_member_patterns += 1

    for s in dump.structs:
        if not s.members:
            report.structs_with_zero_members.append(s.name)

    for e in dump.enums:
        if not e.values:
            report.enums_with_zero_values.append(e.name)

    if handle and gworld_addr and gnames_ptr:
        try:
            from src.engines.ue.gworld import validate_gworld
            report.gworld_valid = validate_gworld(
                handle, gworld_addr, module_base, module_size,
                gnames_ptr, ue_version, case_preserving,
            )
        except Exception:
            report.gworld_valid = False

    if handle and gobjects_ptr:
        try:
            from src.engines.ue.gobjects import validate_gobjects
            report.gobjects_valid = validate_gobjects(
                handle, gobjects_ptr, gnames_ptr, ue_version,
                case_preserving, item_size,
            )
        except Exception:
            report.gobjects_valid = False

    if handle and gnames_ptr:
        try:
            from src.engines.ue.gnames import read_fname
            sample_indices = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
            for idx in sample_indices:
                name = read_fname(handle, gnames_ptr, idx, ue_version, case_preserving)
                report.fname_sample.append(name or "<empty>")
        except Exception:
            pass

    if ue_version:
        try:
            from src.engines.ue.version_matrix import get_version_config
            config = get_version_config(ue_version)
            confirmed = config.get("confirmed", False)
            report.version_layout_match = confirmed
            report._version_notes = config.get("notes", "")
        except Exception:
            pass

    score = 100
    reasons = []

    if report.total_structs == 0:
        score -= 80
        reasons.append("No structs found")
    elif report.total_structs < 50:
        score -= 30
        reasons.append(f"Very few structs ({report.total_structs})")

    if report.total_members == 0:
        score -= 40
        reasons.append("No members resolved")
    elif report.total_structs > 0:
        avg_members = report.total_members / report.total_structs
        if avg_members < 0.5:
            score -= 25
            reasons.append(f"Low member density ({avg_members:.1f} avg per struct)")

    sv_count = len(report.structs_with_size_violations)
    if sv_count > 0:
        sv_pct = sv_count / max(report.total_members, 1) * 100
        if sv_pct > 5:
            score -= 30
            reasons.append(f"High size violation rate ({sv_pct:.0f}%)")
        elif sv_pct > 1:
            score -= 15
            reasons.append(f"Some size violations ({sv_count})")
        else:
            score -= 5

    if report.total_members:
        suspicious_pct = report.suspicious_member_patterns / max(report.total_members, 1) * 100
        sv_pct = sv_count / max(report.total_members, 1) * 100
        if sv_pct > 20 and suspicious_pct > 20:
            report.suspected_layout_mismatch = True
            score -= 25
            reasons.append("Suspected UE FField layout mismatch")

    if report.total_structs:
        bad_pkg_count = report.none_package_types + report.empty_package_types
        bad_pkg_pct = bad_pkg_count / report.total_structs * 100
        if bad_pkg_pct >= 85:
            score -= 25
            reasons.append(f"Most types resolved to None/empty packages ({bad_pkg_pct:.0f}%)")

    zm_count = len(report.structs_with_zero_members)
    if report.total_structs > 0:
        zm_pct = zm_count / report.total_structs * 100
        if zm_pct > 50:
            score -= 25
            reasons.append(f"Majority of structs have zero members ({zm_pct:.0f}%)")
        elif zm_pct > 20:
            score -= 10
            reasons.append(f"Many zero-member structs ({zm_count})")

    if report.version_layout_match is False:
        score -= 10
        reasons.append("UE version layout unconfirmed (inferred)")
    elif report.version_layout_match is None and ue_version:
        score -= 15
        reasons.append("Could not verify version layout")

    if report.gworld_valid is False:
        score -= 10
        reasons.append("GWorld validation failed")
    if report.gobjects_valid is False:
        score -= 15
        reasons.append("GObjects validation failed")

    if report.fname_sample:
        empty_count = sum(1 for s in report.fname_sample if s in ("<empty>", "", "None"))
        valid_count = len(report.fname_sample) - empty_count
        if valid_count < 3:
            score -= 20
            reasons.append(f"FName resolution poor ({valid_count}/{len(report.fname_sample)} valid)")

    score = max(0, score)
    if score >= 80:
        report.confidence_grade = "HIGH"
    elif score >= 50:
        report.confidence_grade = "MEDIUM"
    elif score > 0:
        report.confidence_grade = "LOW"
    else:
        report.confidence_grade = "INCOMPLETE"
    report.confidence_reasons = reasons

    return report

def format_health_report(report: HealthReport, ue_version: str = "", pe_timestamp: int = 0) -> str:
    lines = []
    lines.append("")
    lines.append("\u2501\u2501\u2501 Dump Health \u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501")

    total_classes = report.total_structs
    member_line = f"  Structs/Classes: {total_classes:,}    Enums: {report.total_enums:,}    Members: {report.total_members:,}"
    if report.total_static_fields:
        member_line += f"  (static: {report.total_static_fields:,})"
    lines.append(member_line)

    sv_count = len(report.structs_with_size_violations)
    sv_prefix = "  " if sv_count == 0 else "  [!!] "
    lines.append(f"{sv_prefix}Size violations: {sv_count}")
    for sname, fname, off, sz, ssz in report.structs_with_size_violations[:5]:
        lines.append(f"        {sname}.{fname}: offset=0x{off:X} size={sz} > PropertiesSize={ssz}")

    zm_count = len(report.structs_with_zero_members)
    lines.append(f"  Zero-member structs: {zm_count}")

    ze_count = len(report.enums_with_zero_values)
    lines.append(f"  Zero-value enums: {ze_count}")

    bad_pkg_count = report.none_package_types + report.empty_package_types
    if bad_pkg_count:
        pkg_prefix = "  [!!] " if report.total_structs and bad_pkg_count / report.total_structs >= 0.85 else "  "
        lines.append(
            f"{pkg_prefix}None/empty packages: {bad_pkg_count}"
        )

    if report.suspected_layout_mismatch:
        lines.append("  [!!] Suspected UE FField layout mismatch")

    if report.gworld_valid is not None:
        gw_status = "YES" if report.gworld_valid else "NO"
        gw_prefix = "  " if report.gworld_valid else "  [!!] "
        lines.append(f"{gw_prefix}GWorld valid: {gw_status}")

    if report.gobjects_valid is not None:
        go_status = "YES" if report.gobjects_valid else "NO"
        go_prefix = "  " if report.gobjects_valid else "  [!!] "
        lines.append(f"{go_prefix}GObjects valid: {go_status}")

    if ue_version:
        match_status = ""
        if report.version_layout_match is not None:
            if report.version_layout_match:
                match_status = "  Layout confirmed (live-tested)"
            else:
                notes = getattr(report, "_version_notes", "")
                if notes:
                    match_status = f"  Layout inferred (untested for this version — {notes[:80]})"
                else:
                    match_status = "  Layout inferred (no live-tested game for this version yet)"
        lines.append(f"  UE version: {ue_version}{match_status}")

    if report.fname_sample:
        sample_str = ", ".join(report.fname_sample[:10])
        lines.append(f"  FName sample: [{sample_str}]")

    if pe_timestamp:
        try:
            from datetime import datetime, timezone
            pe_human = datetime.fromtimestamp(pe_timestamp, tz=timezone.utc).strftime("%Y-%m-%d")
            lines.append(f"  PE timestamp: {pe_timestamp} ({pe_human})")
        except (OSError, ValueError, OverflowError):
            pass

    lines.append("\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501")

    if report.confidence_grade:
        grade_icon = {
            "HIGH": "[OK]", "MEDIUM": "[??]", "LOW": "[!!]", "INCOMPLETE": "[!!]"
        }.get(report.confidence_grade, "[--]")
        lines.append(f"  {grade_icon} Dump confidence: {report.confidence_grade}")
        if report.confidence_grade == "HIGH":
            lines.append("      This dump is complete and trustworthy.")
        elif report.confidence_grade == "MEDIUM":
            lines.append("      Dump has data but some checks are uncertain.")
        elif report.confidence_grade == "LOW":
            lines.append("      Dump has significant issues — offsets may be unreliable.")
        else:
            lines.append("      Dump is incomplete or mostly empty.")
        for reason in report.confidence_reasons[:5]:
            lines.append(f"      - {reason}")

    problems = sv_count + (1 if report.gworld_valid is False else 0) + (1 if report.gobjects_valid is False else 0)
    if problems == 0 and report.confidence_grade in ("HIGH", ""):
        lines.append("  Dump looks clean. Redump if game updates.")
    elif problems == 0 and report.confidence_grade == "MEDIUM":
        lines.append("  No hard failures, but confidence is not full — verify key offsets manually.")
    else:
        lines.append(f"  [!!] {problems} problem(s) detected. Check warnings above.")

    lines.append("")
    return "\n".join(lines)

def build_health_guidance(report: HealthReport, ue_version: str = "") -> List[str]:
    guidance: List[str] = []

    avg_members = (report.total_members / report.total_structs) if report.total_structs else 0.0
    zero_member_pct = (
        len(report.structs_with_zero_members) / report.total_structs * 100
        if report.total_structs else 0.0
    )

    if report.total_structs == 0:
        guidance.append("No structs were exported. Re-run a full dump and confirm the engine path is resolving live data.")
    if report.total_members == 0:
        guidance.append("Members are empty. Check the field walk for the selected engine version before trusting any generated offsets.")
    elif avg_members < 0.5:
        guidance.append("Member density is still thin. Prioritize validating the highest-signal classes before building features on top.")
    if report.structs_with_size_violations:
        if report.suspected_layout_mismatch:
            guidance.append("Size violations match shifted FProperty reads. Re-run with runtime FField layout probing before trusting the SDK.")
        else:
            guidance.append("Size violations were found. Inspect the affected structs first because they can shift downstream offsets.")
    bad_pkg_count = report.none_package_types + report.empty_package_types
    if report.total_structs and bad_pkg_count > report.total_structs * 0.85:
        guidance.append("Most exported types landed in None/empty packages. Verify UObject outer/package resolution and UE layout selection.")
    if zero_member_pct > 50:
        guidance.append("A large share of exported types have no members. Filter template features toward classes that already carry real fields.")
    elif zero_member_pct > 20:
        guidance.append("There are still many shell types. Use the richer classes and components first when seeding feature cards.")
    if report.enums_with_zero_values:
        guidance.append("Some enums are empty. Recheck the enum/value path before generating switch-heavy helpers from them.")
    if report.gworld_valid is False or report.gobjects_valid is False:
        guidance.append("Live Unreal globals failed validation. Re-run the scan before leaning on global pointer chains.")
    if report.version_layout_match is False and ue_version:
        guidance.append(f"The {ue_version} layout is inferred rather than confirmed. Keep one or two anchor fields under review after each update.")

    if not guidance:
        guidance.append("The dump is in good shape. Keep a copy of the game build timestamp and regenerate after updates.")

    return guidance

def format_health_sidecar(report: HealthReport, ue_version: str = "", pe_timestamp: int = 0) -> str:
    lines = [format_health_report(report, ue_version=ue_version, pe_timestamp=pe_timestamp).rstrip(), ""]
    lines.append("How to improve this dump")
    lines.append("------------------------")
    for item in build_health_guidance(report, ue_version=ue_version):
        lines.append(f"- {item}")
    lines.append("")
    lines.append(
        f"Saved at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
    )
    lines.append("")
    return "\n".join(lines)

def write_health_sidecar(
    dump_dir: str,
    report: HealthReport,
    ue_version: str = "",
    pe_timestamp: int = 0,
    file_name: str = "health.txt",
) -> str:
    os.makedirs(dump_dir, exist_ok=True)
    path = os.path.join(dump_dir, file_name)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(format_health_sidecar(report, ue_version=ue_version, pe_timestamp=pe_timestamp))
    return path

def print_health_report(report: HealthReport, ue_version: str = "", pe_timestamp: int = 0) -> None:
    print(format_health_report(report, ue_version, pe_timestamp))
