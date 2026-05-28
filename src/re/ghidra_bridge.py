from typing import Dict


def decompile_function_best_effort(binary_path: str, rva: int, *, timeout_secs: int = 20) -> Dict[str, object]:
    """Optional PyGhidra enrichment used by ``sigcli func --ghidra``.

    The main CLI never depends on this path.  It returns a structured error
    when PyGhidra/Ghidra is not installed or cannot analyze the target.
    """
    try:
        import pyghidra
    except ImportError as exc:
        return {"ok": False, "error": f"pyghidra is not installed: {exc}"}

    try:
        with pyghidra.open_program(binary_path) as flat_api:
            program = flat_api.getCurrentProgram()
            image_base = int(program.getImageBase().getOffset())
            addr = flat_api.toAddr(image_base + rva)
            function = program.getFunctionManager().getFunctionContaining(addr)
            if function is None:
                return {"ok": False, "error": f"no Ghidra function contains RVA 0x{rva:X}"}
            from ghidra.app.decompiler.flatapi import FlatDecompilerAPI

            decomp_api = FlatDecompilerAPI(flat_api)
            try:
                text = str(decomp_api.decompile(function, timeout_secs))
            finally:
                decomp_api.dispose()
            return {
                "ok": True,
                "function": str(function.getName()),
                "entry": f"0x{int(function.getEntryPoint().getOffset()):X}",
                "decompiled": text,
            }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
