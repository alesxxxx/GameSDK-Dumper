import logging
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from src.core.memory import get_module_info, get_pid_by_name, read_string, read_uint64
from src.core.scanner import resolve_rip, scan_pattern

logger = logging.getLogger(__name__)

_KEY_BUTTON_PATTERN = "48 8B 15 ?? ?? ?? ?? 48 85 D2 74 ?? 48 8B 02 48 85 C0"
_KEY_BUTTON_NAME_OFFSET = 0x08
_KEY_BUTTON_STATE_OFFSET = 0x30
_KEY_BUTTON_NEXT_OFFSET = 0x88
_MAX_BUTTONS = 128


@dataclass
class CS2ButtonResult:
    name: str
    module: str
    rva: int
    absolute: int
    found: bool = True
    error: str = ""


def _is_reasonable_button_name(value: str) -> bool:
    if not value or len(value) > 32:
        return False
    return all(ch.isalnum() or ch == "_" for ch in value)


def read_buttons_from_list(
    handle: int,
    module_base: int,
    list_head: int,
    *,
    module_name: str = "client.dll",
    max_buttons: int = _MAX_BUTTONS,
) -> List[CS2ButtonResult]:
    results: List[CS2ButtonResult] = []
    seen: set[int] = set()
    button_ptr = list_head

    while button_ptr and button_ptr not in seen and len(results) < max_buttons:
        seen.add(button_ptr)

        name_ptr = read_uint64(handle, button_ptr + _KEY_BUTTON_NAME_OFFSET)
        name = read_string(handle, name_ptr, max_len=32) if name_ptr else ""
        if _is_reasonable_button_name(name):
            state_addr = button_ptr + _KEY_BUTTON_STATE_OFFSET
            rva = state_addr - module_base
            if 0 <= rva < 0x10000000:
                results.append(
                    CS2ButtonResult(
                        name=name,
                        module=module_name,
                        rva=rva,
                        absolute=state_addr,
                    )
                )

        button_ptr = read_uint64(handle, button_ptr + _KEY_BUTTON_NEXT_OFFSET)

    return results


def find_cs2_buttons(
    handle: int,
    process_name: str = "cs2.exe",
    *,
    progress_callback: Optional[Callable[[str], None]] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> List[CS2ButtonResult]:
    def _log(msg: str) -> None:
        logger.info(msg)
        if log_fn:
            log_fn(msg)

    pid = get_pid_by_name(process_name)
    if not pid:
        raise RuntimeError(f"Process {process_name!r} not found")

    module_name = "client.dll"
    module_base, module_size = get_module_info(pid, module_name)
    if not module_base or not module_size:
        raise RuntimeError("Could not find client.dll")

    if progress_callback:
        progress_callback("Scanning client.dll for key-button list...")

    hits = scan_pattern(handle, module_base, module_size, _KEY_BUTTON_PATTERN, max_results=2)
    if not hits:
        _log("[Source2] Key-button list pattern did not match.")
        return [
            CS2ButtonResult(
                name="",
                module=module_name,
                rva=0,
                absolute=0,
                found=False,
                error="button list pattern not matched",
            )
        ]

    list_storage = resolve_rip(handle, hits[0], disp_offset=3, instruction_size=7)
    list_head = read_uint64(handle, list_storage) if list_storage else 0
    if not list_head:
        _log("[Source2] Key-button list head was null.")
        return [
            CS2ButtonResult(
                name="",
                module=module_name,
                rva=0,
                absolute=0,
                found=False,
                error="button list head null",
            )
        ]

    results = read_buttons_from_list(handle, module_base, list_head, module_name=module_name)
    results.sort(key=lambda item: item.name)
    _log(f"[Source2] Key buttons: {len(results)} discovered")
    return results


def button_map(results: List[CS2ButtonResult]) -> Dict[str, int]:
    return {r.name: r.rva for r in results if r.found and r.name}
