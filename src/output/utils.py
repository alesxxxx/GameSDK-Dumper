
from typing import List

def lookup_member_offset(
    classes_data: list, structs_data: list, class_name: str, member_name: str
) -> int:
    for dataset in (classes_data, structs_data):
        for entry in dataset:
            if not entry:
                continue
            for full_name, details in entry.items():
                uq = full_name.split(".")[-1] if "." in full_name else full_name
                if uq != class_name:
                    continue
                for item in details:
                    if not isinstance(item, dict):
                        continue
                    if member_name in item:
                        val = item[member_name]
                        if isinstance(val, list) and len(val) >= 2:
                            return int(val[1])
    return -1

def resolve_standard_chain(
    classes_data: list, structs_data: list
) -> dict:
    _CHAIN_LOOKUPS = [
        ("UWorld_OwningGameInstance",          "World",            "OwningGameInstance"),
        ("UGameInstance_LocalPlayers",         "GameInstance",     "LocalPlayers"),
        ("UPlayer_PlayerController",          "Player",           "PlayerController"),
        ("APlayerController_AcknowledgedPawn","PlayerController", "AcknowledgedPawn"),
        ("AController_PlayerState",           "Controller",       "PlayerState"),
        ("ACharacter_CharacterMovement",      "Character",        "CharacterMovement"),
    ]

    chain = {}
    for label, cls, member in _CHAIN_LOOKUPS:
        off = lookup_member_offset(classes_data, structs_data, cls, member)
        chain[label] = f"0x{off:X}" if off >= 0 else None
    return chain
