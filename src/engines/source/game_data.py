
from dataclasses import dataclass, field
from typing import Dict, List

@dataclass
class SourceGameProfile:
    name: str
    process_names: List[str]
    client_module: str
    engine_module: str
    interface_version: str
    is_64bit: bool = True
    validation_netvars: Dict[str, Dict[str, str]] = field(default_factory=dict)

TF2 = SourceGameProfile(
    name="Team Fortress 2",
    process_names=["tf2.exe", "tf_win64.exe", "hl2.exe"],
    client_module="client.dll",
    engine_module="engine.dll",
    interface_version="VClient018",
    is_64bit=True,
    validation_netvars={
        "DT_BasePlayer": {
            "m_iHealth": "int",
            "m_lifeState": "int",
            "m_fFlags": "int",
            "m_vecOrigin": "Vector",
            "m_nTickBase": "int",
        },
        "DT_BaseCombatWeapon": {
            "m_iClip1": "int",
            "m_iClip2": "int",
        },
        "DT_BaseEntity": {
            "m_iTeamNum": "int",
        },
    },
)

CSGO = SourceGameProfile(
    name="Counter-Strike: Global Offensive",
    process_names=["csgo.exe"],
    client_module="client.dll",
    engine_module="engine.dll",
    interface_version="VClient018",
    is_64bit=False,
    validation_netvars={
        "DT_BasePlayer": {
            "m_iHealth": "int",
            "m_fFlags": "int",
        },
        "DT_CSPlayer": {
            "m_bHasDefuser": "int",
        },
    },
)

CS2_PLACEHOLDER = SourceGameProfile(
    name="Counter-Strike 2 (Source 2 — not yet supported)",
    process_names=["cs2.exe"],
    client_module="client.dll",
    engine_module="engine2.dll",
    interface_version="",
    is_64bit=True,
)

ALL_GAMES = [TF2, CSGO]

_PROCESS_TO_GAME: Dict[str, SourceGameProfile] = {}
for _game in ALL_GAMES:
    for _proc in _game.process_names:
        _PROCESS_TO_GAME[_proc.lower()] = _game

def identify_game(process_name: str) -> SourceGameProfile:
    key = process_name.lower()
    if key in _PROCESS_TO_GAME:
        return _PROCESS_TO_GAME[key]

    return SourceGameProfile(
        name=f"Unknown Source Game ({process_name})",
        process_names=[process_name],
        client_module="client.dll",
        engine_module="engine.dll",
        interface_version="VClient018",
        is_64bit=True,
    )

IBASECLIENTDLL_GETALLCLASSES_VTABLE_INDEX = 8

CLIENTCLASS_NETWORK_NAME_64 = 0x10
CLIENTCLASS_RECV_TABLE_64 = 0x18
CLIENTCLASS_NEXT_64 = 0x20
CLIENTCLASS_CLASSID_64 = 0x28

CLIENTCLASS_NETWORK_NAME_32 = 0x08
CLIENTCLASS_RECV_TABLE_32 = 0x0C
CLIENTCLASS_NEXT_32 = 0x10
CLIENTCLASS_CLASSID_32 = 0x14

RECVTABLE_PROPS_64 = 0x00
RECVTABLE_NPROPS_64 = 0x08
RECVTABLE_TABLENAME_64 = 0x18

RECVTABLE_PROPS_32 = 0x00
RECVTABLE_NPROPS_32 = 0x04
RECVTABLE_TABLENAME_32 = 0x0C

RECVPROP_SIZE_64 = 0x60
RECVPROP_VARNAME_64 = 0x00
RECVPROP_RECVTYPE_64 = 0x08
RECVPROP_FLAGS_64 = 0x0C
RECVPROP_STRING_BUFFER_SIZE_64 = 0x10
RECVPROP_INSIDE_ARRAY_64 = 0x14
RECVPROP_ARRAYPROP_64 = 0x20
RECVPROP_DATATABLE_64 = 0x40
RECVPROP_OFFSET_64 = 0x48
RECVPROP_ELEMENTSTRIDE_64 = 0x4C
RECVPROP_ELEMENTS_64 = 0x50
RECVPROP_PARENT_ARRAY_NAME_64 = 0x58

RECVPROP_SIZE_32 = 0x3C
RECVPROP_VARNAME_32 = 0x00
RECVPROP_RECVTYPE_32 = 0x04
RECVPROP_FLAGS_32 = 0x08
RECVPROP_STRING_BUFFER_SIZE_32 = 0x0C
RECVPROP_INSIDE_ARRAY_32 = 0x10
RECVPROP_ARRAYPROP_32 = 0x18
RECVPROP_DATATABLE_32 = 0x28
RECVPROP_OFFSET_32 = 0x2C
RECVPROP_ELEMENTSTRIDE_32 = 0x30
RECVPROP_ELEMENTS_32 = 0x34
RECVPROP_PARENT_ARRAY_NAME_32 = 0x38

SEND_PROP_TYPES = {
    0: "Int",
    1: "Float",
    2: "Vector",
    3: "VectorXY",
    4: "String",
    5: "Array",
    6: "DataTable",
    7: "Int64",
}

def prop_type_name(type_id: int) -> str:
    return SEND_PROP_TYPES.get(type_id, f"Unknown({type_id})")
