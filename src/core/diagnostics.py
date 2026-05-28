
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class DiagEntry:
    target: str
    action: str
    result: str
    detail: str = ""

@dataclass
class ScanDiagnostics:
    entries: List[DiagEntry] = field(default_factory=list)
    confidence: dict = field(default_factory=dict)

    def tried(self, target: str, action: str, detail: str = ""):
        self.entries.append(DiagEntry(target, action, "tried", detail))

    def passed(self, target: str, action: str, detail: str = ""):
        self.entries.append(DiagEntry(target, action, "passed", detail))

    def failed(self, target: str, action: str, detail: str = ""):
        self.entries.append(DiagEntry(target, action, "failed", detail))

    def warn(self, detail: str, target: str = "General"):
        self.entries.append(DiagEntry(target, "warning", "warn", detail))

    def info(self, detail: str, target: str = "General"):
        self.entries.append(DiagEntry(target, "info", "info", detail))

    def set_confidence(self, target: str, level: float, reason: str = ""):
        self.confidence[target] = (min(1.0, max(0.0, level)), reason)

    def get_confidence(self, target: str) -> float:
        return self.confidence.get(target, (0.0, ""))[0]

    def get_confidence_reason(self, target: str) -> str:
        return self.confidence.get(target, (0.0, ""))[1]

    def has_failures(self) -> bool:
        return any(e.result == "failed" for e in self.entries)

    def format_report(self) -> List[str]:
        lines = []
        if not self.entries:
            return lines

        lines.append("--- Scan Diagnostics ---")

        targets_seen = []
        for e in self.entries:
            if e.target not in targets_seen:
                targets_seen.append(e.target)

        for target in targets_seen:
            target_entries = [e for e in self.entries if e.target == target]
            conf = self.confidence.get(target)

            if conf:
                conf_pct = int(conf[0] * 100)
                conf_label = (
                    "HIGH" if conf[0] >= 0.8 else
                    "MEDIUM" if conf[0] >= 0.5 else
                    "LOW" if conf[0] > 0 else
                    "NONE"
                )
                lines.append(f"  {target}  (confidence: {conf_label} {conf_pct}%"
                             + (f" — {conf[1]}" if conf[1] else "") + ")")
            else:
                lines.append(f"  {target}")

            for e in target_entries:
                icon = {
                    "passed": "[OK]",
                    "failed": "[!!]",
                    "tried":  "[ >]",
                    "warn":   "[??]",
                    "info":   "[--]",
                }.get(e.result, "[  ]")
                msg = f"    {icon} {e.action}"
                if e.detail:
                    msg += f": {e.detail}"
                lines.append(msg)

        failures = [e for e in self.entries if e.result == "failed"]
        if failures:
            lines.append("")
            lines.append("  Suggestions:")
            sig_failures = [e for e in failures if "signature" in e.action.lower() or "aob" in e.action.lower()]
            if sig_failures:
                lines.append("    - AOB signatures didn't match. This game may use a different compiler")
                lines.append("      (Clang vs MSVC) or a custom engine fork with modified struct layouts.")
                kernel_live = any(
                    "kernel live scan skips cached gobjects/gnames" in e.detail.lower()
                    for e in self.entries
                )
                if kernel_live:
                    lines.append("    - Kernel live scans do not use cached GObjects/GNames offsets.")
                    lines.append("      Re-run after live resolver coverage is updated for this build.")
                else:
                    lines.append("    - Try adding the game's known offsets to OffsetsInfo.json manually.")
            version_failures = [e for e in failures if "version" in e.target.lower()]
            if version_failures:
                lines.append("    - UE version could not be detected confidently.")
                lines.append("      Wrong version = wrong struct offsets = garbage output.")
            brute_failures = [e for e in failures if "brute" in e.action.lower()]
            if brute_failures:
                lines.append("    - Brute-force scan also failed. The game may have stripped or obfuscated")
                lines.append("      its GObjects/GNames globals.")

        lines.append("------------------------")
        return lines

    def format_summary(self) -> str:
        failed = [e for e in self.entries if e.result == "failed"]
        passed = [e for e in self.entries if e.result == "passed"]
        if not failed:
            return f"All checks passed ({len(passed)} validations)"
        targets_failed = list(set(e.target for e in failed))
        return f"{len(failed)} issue(s): {', '.join(targets_failed)}"
