import json
import os
from typing import Dict, Iterable, List

from src.re.pack_parser import parse_signature_pack
from src.re.signatures import SignatureEntry


CS2_EXTENDED_SIGNATURE_PACK = r'''
// GameOverlayRenderer64.dll (steam)
#define PRESENT_PATTERN "48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 54 41 56 41 57 48 83 EC ? 41 8B E8"

// client.dll
#define CREATEMOVE_PATTERN "48 8B C4 4C 89 40 ? 48 89 48 ? 55 53 41 54"
#define OVERRIDEVIEW_PATTERN "40 57 48 83 EC ? 48 8B FA E8 ? ? ? ? BA"
#define DRAWSCOPEOVERLAY_PATTERN "48 8B C4 53 57 48 83 EC ? 48 8B FA"
#define DRAWLEGS_PATTERN "40 55 53 56 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? F2 0F 10 42"
#define VALIDATEINPUT_PATTERN "40 53 48 83 EC ? 48 8B D9 E8 ? ? ? ? 33 C0 C6 83 ? ? ? ? 00"
#define GETVIEWANGLES_PATTERN "4C 8B C1 85 D2 74 ? 48 8D 05"
#define SETVIEWANGLES_PATTERN "85 D2 75 ? 48 63 81"
#define DRAWSMOKEVERTEX_PATTERN "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC ? 48 8B 9C 24 ? ? ? ? 4D 8B F8"
#define GETCHATOBJECT_PATTERN "48 8B 05 ? ? ? ? C3 ? ? ? ? ? ? ? ? 48 8B 05 ? ? ? ? 48 8D 0D"
#define SENDCHATMESSAGE_PATTERN "4C 89 44 24 ? 4C 89 4C 24 ? 53 B8"
#define REGENERATEWEAPONSKINS_PATTERN "48 83 EC ? E8 ? ? ? ? 48 85 C0 0F 84 ? ? ? ? 48 8B 10"
#define LEVELINIT_PATTERN "40 55 56 41 56 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 0D"
#define LEVELSHUTDOWN_PATTERN "48 83 EC ? 48 8B 0D ? ? ? ? 48 8D 15 ? ? ? ? 45 33 C9 45 33 C0 ? ? ? FF 50 ? 48 85 C0 74 ? 48 8B 0D ? ? ? ? 48 8B D0 ? ? ? 41 FF 50 ? 48 83 C4"
#define FLASHOVERLAY_PATTERN "85 D2 0F 88 ? ? ? ? 48 89 4C 24 ? 55 56"
#define TRACESHAPE_PATTERN "48 89 5C 24 ? 48 89 4C 24 ? 55 57"
#define CHANGEMODEL_PATTERN "40 53 48 83 EC ? 48 8B D9 4C 8B C2 48 8B 0D ? ? ? ? 48 8D 54 24"
#define FRAMESTAGENOTIFY_PATTERN "48 89 5C 24 ? 48 89 6C 24 ? 57 48 83 EC ? 48 8B F9 33 ED"
#define ONADDENTITY_PATTERN "48 89 74 24 ? 57 48 83 EC ? 41 B9 ? ? ? ? 41 8B C0 41 23 C1 48 8B F2 41 83 F8 ? 48 8B F9 44 0F 45 C8 41 81 F9 ? ? ? ? 73 ? FF 81"
#define ONREMOVEENTITY_PATTERN "48 89 74 24 ? 57 48 83 EC ? 41 B9 ? ? ? ? 41 8B C0 41 23 C1 48 8B F2 41 83 F8 ? 48 8B F9 44 0F 45 C8 41 81 F9 ? ? ? ? 73 ? FF 89"
#define UPDATEGLOBALVARS_PATTERN "48 8B 0D ? ? ? ? 4C 8D 05 ? ? ? ? 48 85 D2"
#define FORCEBUTTONSDOWN_PATTERN "40 53 57 41 56 48 81 EC ? ? ? ? 48 83 79 ? 00"
#define DRAWCROSSHAIR_PATTERN "48 89 5C 24 ? 57 48 83 EC ? 48 8B D9 E8 ? ? ? ? 48 85 C0"
#define UPDATEPOSTPROCESSING_PATTERN "48 85 D2 0F 84 ? ? ? ? 48 89 5C 24 ? 57 48 83 EC ? ? ? 00 48 8B DA 48 8B F9 0F 84 ? ? ? ? 48 8D 15"
#define UPDATESKYBOX_PATTERN "48 89 5C 24 ? 57 48 83 EC ? 48 8B F9 E8 ? ? ? ? 48 8B 47"
#define CALCVIEWMODEL_PATTERN "40 55 53 56 41 56 41 57 48 8B EC"
#define EQUIPITEMINLOADOUT_PATTERN "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 89 54 24 ? 57 41 54 41 55 41 56 41 57 48 83 EC ? 0F B7 FA"
#define COMPUTERANDOMSEED_PATTERN "48 89 5C 24 ? 57 48 81 EC ? ? ? ? ? ? ? ? 48 8D 8C 24"
#define SETTYPEKV3_PATTERN "40 53 48 83 EC ? ? ? ? 41 B9 ? ? ? ? 49 83 CA"
#define DRAWTEAMINTRO_PATTERN "48 83 EC ? ? ? ? ? 44 38 89"
#define SHOWMESSAGEBOX_PATTERN "44 88 4C 24 ? 53 41 56"
#define SETPLAYERREADY_PATTERN "40 53 48 83 EC ? 48 8B DA 48 8D 15 ? ? ? ? 48 8B CB FF 15"
#define CREATEPARTICLEEFFECT_PATTERN "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? F3 0F 10 1D ? ? ? ? 41 8B F8 8B DA 4C 8D 05"
#define UNKNOWNPARTICLEFUNCTION_PATTERN "40 56 48 83 EC ? 41 8B F0"
#define CACHEPARTICLEEFFECT_PATTERN "4C 8B DC 53 48 81 EC ? ? ? ? F2 0F 10 05"
#define POPUPEVENTHANDLE_PATTERN "40 56 57 41 57 48 83 EC ? 48 8B 3D ? ? ? ? 4D 85 C0"
#define SETMESHGROUPMASK_PATTERN "40 53 48 83 EC ? ? ? ? 48 8B D9 4C 39 81"

// materialsystem2.dll
#define CREATEMATERIAL_PATTERN "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 41 56 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 8B F2"

// scenesystem.dll
#define CANIMATABLESCENEOBJECTDESCRENDER_PATTERN "48 8B C4 53 57 41 54"
#define DRAWLIGHTSCENE_PATTERN "? ? ? ? F2 0F 10 42 ? F2 0F 11 41 ? 8B 42 ? 89 41 ? F2 0F 10 42 ? F2 0F 11 41 ? 8B 42 ? 89 41 ? 8B 42 ? 89 41 ? 8B 42"
#define DRAWAGGREGATESCENEOBJECTARRAY_PATTERN "48 8B C4 48 89 50 ? 48 89 48 ? 55 53 56 57 41 54 41 55 41 56 41 57 48 8D A8 ? ? ? ? 48 81 EC ? ? ? ? 0F 29 70"
#define SKYBOXDRAWARRAY_PATTERN "45 85 C9 0F 8E ? ? ? ? 4C 8B DC"

// engine2.dll
#define GETASPECTRATIO_PATTERN "48 89 5C 24 ? 57 48 83 EC ? 8B FA 48 8D 0D"
#define ISINGAME_PATTERN "48 8B 05 ? ? ? ? 48 85 C0 74 ? 80 B8 ? ? ? ? 00 75 ? 83 B8 ? ? ? ? ? 7C"

// tier0.dll
#define LOADKV3_PROC_ADDRESS "?LoadKV3@@YA_NPEAVKeyValues3@@PEAVCUtlString@@PEBDAEBUKV3ID_t@@2I@Z"
'''


def _from_globals() -> List[SignatureEntry]:
    from src.engines.source2.globals import ALL_CS2_GLOBALS

    return [
        SignatureEntry(
            name=item.name,
            module=item.module,
            kind="pattern",
            pattern=item.pattern,
            resolve="literal_u32" if item.mode == "literal_u32" else "rip",
            disp_offset=item.disp_offset,
            instruction_size=item.instruction_size,
            extra_offset=item.extra_offset,
            description=item.description,
            source="source2.globals",
        )
        for item in ALL_CS2_GLOBALS
    ]


def _from_prediction() -> List[SignatureEntry]:
    from src.engines.source2.prediction_signatures import ALL_PREDICTION_SIGS

    return [
        SignatureEntry(
            name=item.name,
            module=item.module,
            kind="pattern",
            pattern=item.patterns[0],
            fallbacks=item.patterns[1:],
            resolve=item.resolve,
            disp_offset=item.disp_offset,
            instruction_size=item.instruction_size,
            extra_offset=item.extra_offset,
            description=item.description,
            source="source2.prediction_signatures",
        )
        for item in ALL_PREDICTION_SIGS
        if item.patterns
    ]


def _from_hooks() -> List[SignatureEntry]:
    from src.engines.source2.hook_signatures import ALL_HOOK_SIGS

    return [
        SignatureEntry(
            name=item.name,
            module=item.module,
            kind="pattern",
            pattern=item.patterns[0],
            fallbacks=item.patterns[1:],
            resolve=item.resolve,
            disp_offset=item.disp_offset,
            instruction_size=item.instruction_size,
            extra_offset=item.extra_offset,
            required=item.required,
            description=item.description,
            source="source2.hook_signatures",
        )
        for item in ALL_HOOK_SIGS
        if item.patterns
    ]


def extended_entries() -> List[SignatureEntry]:
    return parse_signature_pack(CS2_EXTENDED_SIGNATURE_PACK, source="cs2_extended")


def researched_signature_path(repo_root: str = ".") -> str:
    return os.path.join(repo_root, "src", "engines", "source2", "researched_signatures.json")


def load_researched_entries(path: str) -> List[SignatureEntry]:
    if not path or not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    entries = []
    for item in payload.get("signatures", []):
        entries.append(SignatureEntry(**item))
    return entries


def get_catalog_entries(preset: str = "all", *, include_researched: bool = True) -> List[SignatureEntry]:
    preset = (preset or "all").lower()
    entries: List[SignatureEntry] = []
    if preset in {"all", "tables", "globals"}:
        entries.extend(_from_globals())
    if preset in {"all", "tables", "prediction"}:
        entries.extend(_from_prediction())
    if preset in {"all", "tables", "hooks"}:
        entries.extend(_from_hooks())
    if preset in {"all", "extended"}:
        entries.extend(extended_entries())
    if include_researched and preset in {"all", "researched"}:
        entries.extend(load_researched_entries(researched_signature_path()))
    return dedupe_entries(entries)


def dedupe_entries(entries: Iterable[SignatureEntry]) -> List[SignatureEntry]:
    seen: Dict[tuple, SignatureEntry] = {}
    ordered: List[SignatureEntry] = []
    for entry in entries:
        key = (entry.kind, entry.module.lower(), entry.name.lower(), entry.pattern, entry.symbol)
        if key in seen:
            continue
        seen[key] = entry
        ordered.append(entry)
    return ordered
