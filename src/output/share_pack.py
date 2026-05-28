
from __future__ import annotations

import hashlib
import json
import os
import zipfile
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

def _app_data_root() -> str:
    root = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    directory = os.path.join(root, "GameSDKKit")
    os.makedirs(directory, exist_ok=True)
    return directory

def default_sharepacks_dir() -> str:
    directory = os.path.join(_app_data_root(), "sharepacks")
    os.makedirs(directory, exist_ok=True)
    return directory

def _safe_name(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in (value or "dump"))
    cleaned = cleaned.strip("_")
    return cleaned or "dump"

def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(64 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()

def _iter_offsets_files(offsets_dir: str) -> List[Tuple[str, str]]:
    files: List[Tuple[str, str]] = []
    for root, _, names in os.walk(offsets_dir):
        for name in sorted(names):
            abs_path = os.path.join(root, name)
            rel_path = os.path.relpath(abs_path, offsets_dir).replace("\\", "/")
            files.append((abs_path, rel_path))
    return files

def _load_json_file(path: str) -> Optional[object]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None

def _load_text_file(path: str, limit: int = 64 * 1024) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return ""

def _collect_known_offset_payloads(offsets_dir: str) -> Dict[str, object]:
    names = (
        "OffsetsInfo.json",
        "source2_offsets.json",
        "source2_prediction.json",
        "source2_buttons.json",
        "source2_interfaces.json",
        "source2_info.json",
    )
    payloads: Dict[str, object] = {}
    for name in names:
        payload = _load_json_file(os.path.join(offsets_dir, name))
        if payload is not None:
            payloads[name] = payload
    return payloads

def _build_partner_integration_notes(game_name: str, manifest: Dict[str, object]) -> str:
    trust = manifest.get("trust", {}) if isinstance(manifest.get("trust"), dict) else {}
    confidence = manifest.get("metadata", {}) if isinstance(manifest.get("metadata"), dict) else {}
    confidence_value = confidence.get("confidence") or confidence.get("health_confidence") or ""
    lines = [
        f"# {game_name} Partner Integration Notes",
        "",
        "## Intended Scope",
        "- Treat this package as single-player/offline creator handoff data.",
        "- Revalidate build fingerprints before consuming offsets or signatures.",
        "- Do not ship public trainer/export builds without an explicit partner policy decision.",
        "",
        "## Trust",
        f"- Status: {trust.get('status', 'Unknown')}",
        f"- Reason: {trust.get('reason', '')}",
    ]
    if confidence_value:
        lines.append(f"- Confidence: {confidence_value}")
    lines.extend(
        [
            "",
            "## C++ Consumption",
            "- Load `Partner/manifest.json` first and compare process/module fingerprints.",
            "- Use RVAs from `Partner/offsets.json` relative to the matching module base.",
            "- Prefer signatures when a fingerprint mismatch marks static offsets stale.",
            "- Treat `Partner/health_report.json` as a gate before enabling creator workflows.",
        ]
    )
    return "\n".join(lines) + "\n"

def _build_partner_export_files(
    *,
    offsets_dir: str,
    manifest: Dict[str, object],
    game_name: str,
    generated_at: str,
    files_meta: List[Dict[str, object]],
    extra_metadata: Optional[Dict[str, object]],
    build_fingerprints: Optional[List[Dict[str, object]]],
    signatures: Optional[List[Dict[str, object]]],
    health_report: Optional[Dict[str, object]],
    integration_notes: str,
) -> Dict[str, str]:
    metadata = dict(extra_metadata or {})
    fingerprints = list(build_fingerprints or metadata.get("build_fingerprints") or [])
    signature_list = list(signatures or metadata.get("signatures") or [])
    health_payload = dict(health_report or metadata.get("health_report") or {})

    health_txt = _load_text_file(os.path.join(offsets_dir, "health.txt"))
    if health_txt and "health_text" not in health_payload:
        health_payload["health_text"] = health_txt

    offset_payload = {
        "schema_version": 1,
        "generated_at": generated_at,
        "game": game_name,
        "offset_payloads": _collect_known_offset_payloads(offsets_dir),
        "files": files_meta,
    }

    partner_manifest = {
        "schema_version": 1,
        "generated_at": generated_at,
        "game": game_name,
        "source_manifest": manifest,
        "build_fingerprints": fingerprints,
        "signatures": signature_list,
        "health": {
            "summary": health_payload,
            "has_health_text": bool(health_txt),
        },
        "release_policy": {
            "scope": "single-player/offline creator handoff",
            "public_release_requires_partner_approval": True,
            "online_economy_leaderboard_multiplayer": "out_of_scope",
        },
    }

    notes = integration_notes or _build_partner_integration_notes(game_name, manifest)
    return {
        "Partner/manifest.json": json.dumps(partner_manifest, indent=2),
        "Partner/offsets.json": json.dumps(offset_payload, indent=2),
        "Partner/health_report.json": json.dumps(health_payload, indent=2),
        "Partner/integration_notes.md": notes,
    }

def create_share_pack(
    offsets_dir: str,
    *,
    game_name: str,
    trust_status: str,
    trust_reason: str,
    latest_update_date: str = "",
    health_state: str = "",
    source: str = "",
    sharepacks_dir: Optional[str] = None,
    extra_metadata: Optional[Dict[str, object]] = None,
    export_profile: str = "standard",
    build_fingerprints: Optional[List[Dict[str, object]]] = None,
    signatures: Optional[List[Dict[str, object]]] = None,
    health_report: Optional[Dict[str, object]] = None,
    integration_notes: str = "",
) -> Tuple[str, Dict[str, object]]:
    if not offsets_dir or not os.path.isdir(offsets_dir):
        raise FileNotFoundError(f"Offsets directory not found: {offsets_dir}")

    profile = (export_profile or "standard").strip().lower()
    if profile not in {"standard", "partner"}:
        raise ValueError("export_profile must be 'standard' or 'partner'")

    from src.output.dump_sanity import assert_dump_dir_sane

    assert_dump_dir_sane(offsets_dir, require_chains=True)

    out_dir = sharepacks_dir or default_sharepacks_dir()
    os.makedirs(out_dir, exist_ok=True)

    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%d_%H%M%S")
    zip_name = f"{_safe_name(game_name)}_{stamp}.zip"
    zip_path = os.path.join(out_dir, zip_name)

    files_meta: List[Dict[str, object]] = []
    source_files = _iter_offsets_files(offsets_dir)
    for abs_path, rel_path in source_files:
        try:
            size = int(os.path.getsize(abs_path))
        except OSError:
            size = 0
        files_meta.append(
            {
                "path": rel_path,
                "size": size,
                "sha256": _sha256_file(abs_path),
            }
        )

    manifest: Dict[str, object] = {
        "schema_version": 1,
        "export_profile": profile,
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "game": game_name,
        "trust": {
            "status": trust_status,
            "reason": trust_reason,
            "latest_update_date": latest_update_date,
            "health_state": health_state,
            "source": source,
        },
        "offsets_dir": os.path.abspath(offsets_dir),
        "files": files_meta,
    }
    if extra_metadata:
        manifest["metadata"] = dict(extra_metadata)

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for abs_path, rel_path in source_files:
            archive.write(abs_path, arcname=f"Offsets/{rel_path}")
        if profile == "partner":
            partner_files = _build_partner_export_files(
                offsets_dir=offsets_dir,
                manifest=manifest,
                game_name=game_name,
                generated_at=manifest["generated_at"],
                files_meta=files_meta,
                extra_metadata=extra_metadata,
                build_fingerprints=build_fingerprints,
                signatures=signatures,
                health_report=health_report,
                integration_notes=integration_notes,
            )
            for rel_path, content in partner_files.items():
                archive.writestr(rel_path, content)
        archive.writestr("share_manifest.json", json.dumps(manifest, indent=2))

    return zip_path, manifest

def create_partner_share_pack(
    offsets_dir: str,
    *,
    game_name: str,
    trust_status: str,
    trust_reason: str,
    latest_update_date: str = "",
    health_state: str = "",
    source: str = "",
    sharepacks_dir: Optional[str] = None,
    extra_metadata: Optional[Dict[str, object]] = None,
    build_fingerprints: Optional[List[Dict[str, object]]] = None,
    signatures: Optional[List[Dict[str, object]]] = None,
    health_report: Optional[Dict[str, object]] = None,
    integration_notes: str = "",
) -> Tuple[str, Dict[str, object]]:
    return create_share_pack(
        offsets_dir,
        game_name=game_name,
        trust_status=trust_status,
        trust_reason=trust_reason,
        latest_update_date=latest_update_date,
        health_state=health_state,
        source=source,
        sharepacks_dir=sharepacks_dir,
        extra_metadata=extra_metadata,
        export_profile="partner",
        build_fingerprints=build_fingerprints,
        signatures=signatures,
        health_report=health_report,
        integration_notes=integration_notes,
    )
