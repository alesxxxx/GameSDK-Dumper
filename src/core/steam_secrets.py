
from __future__ import annotations

import base64
import ctypes
import json
import os
from ctypes import wintypes
from typing import Dict

class _DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]

def _blob_from_bytes(data: bytes) -> _DATA_BLOB:
    buffer = ctypes.create_string_buffer(data)
    return _DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))

def _protect_bytes(data: bytes) -> bytes:
    if os.name != "nt":
        return data
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_blob = _blob_from_bytes(data)
    out_blob = _DATA_BLOB()
    if not crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "GameSDKKit Steam Audit",
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)

def _unprotect_bytes(data: bytes) -> bytes:
    if os.name != "nt":
        return data
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_blob = _blob_from_bytes(data)
    out_blob = _DATA_BLOB()
    if not crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)

def _settings_path() -> str:
    root = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    directory = os.path.join(root, "GameSDKKit")
    os.makedirs(directory, exist_ok=True)
    return os.path.join(directory, "steam_audit_settings.json")

def load_steam_audit_settings() -> Dict[str, str]:
    path = _settings_path()
    if not os.path.exists(path):
        return {"steam_account": "", "steam_cookie": ""}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        encoded = str(payload.get("steam_cookie_protected", "") or "")
        steam_cookie = ""
        if encoded:
            steam_cookie = _unprotect_bytes(base64.b64decode(encoded)).decode("utf-8", errors="ignore")
        return {
            "steam_account": str(payload.get("steam_account", "") or ""),
            "steam_cookie": steam_cookie,
        }
    except Exception:
        return {"steam_account": "", "steam_cookie": ""}

def save_steam_audit_settings(steam_account: str, steam_cookie: str) -> None:
    _ = steam_cookie
    path = _settings_path()
    payload = {
        "steam_account": steam_account or "",
        "steam_cookie_protected": "",
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
