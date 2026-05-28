# GameSDK-Kit

A cross-engine SDK analysis toolkit for **Unreal Engine 4/5**, **Unity (IL2CPP / Mono)**, and **Source Engine** games on Windows. Also includes a Source engine netvar analyzer.

Primary focus is Unreal Engine — validated against UE 4.22 through UE 5.5 across dozens of shipped titles.

---

## Supported Engines

| Engine | Format | Notes |
|---|---|---|
| Unreal Engine 4 / 5 | GNames + GObjects + GWorld + full SDK reconstruction | Primary target |
| Unity IL2CPP | global-metadata.dat parser + PE scanner | Confirmed working |
| Unity Mono | Managed assembly reflection | Confirmed working |
| Source Engine | Netvar scanner | TF2 / L4D2 (Source 1) |
| Source 2 Engine | Schema + runtime registry scanner | Counter-Strike 2 (CS2) |

---

## Kernel Mode

A kernel-mode driver (`driver/`) is included for research environments that require physical memory access outside the standard user-mode path.

> **Note:** Kernel mode is optional and environment-dependent. It is intended for authorized research and development use only. Protected targets should be treated as unsupported unless validated in an authorized test environment.

User-mode (`ReadProcessMemory`) works fine for unprotected and most standard titles.

---

## Native User-Mode Backend

The default memory backend remains Python/Win32. A C++ user-mode backend is available for faster attach/read/scatter-read/pattern-scan/RIP/fingerprint work when `bin/gamesdk_native.dll` is built.

```cmd
python -m src.ui.cli --process MyGame.exe --memory-backend native
python -m src.ui.cli --process MyGame.exe --memory-backend auto
```

`native` requests the DLL and falls back to Win32 if it is unavailable. `auto` quietly uses the DLL when present. Kernel mode still takes precedence when `--kernel` is used.

---

## Requirements

- **Python 3.10+**
- **Windows 10/11 x64**
- **psutil**
- **capstone + pefile** (signature research CLI)
- Visual Studio 2022 + WDK (only required to build the kernel driver)

---

## Quick Start

### GUI

```cmd
pip install psutil
python -m src.ui.app
```

### CLI

```cmd
python -m src.ui.cli --process Palworld-Win64-Shipping.exe
python -m src.ui.cli --process Palworld-Win64-Shipping.exe --output my_analysis/
python -m src.ui.cli --engine il2cpp --process MyUnityGame.exe
python -m src.ui.cli --engine mono --process MyUnityGame.exe
python -m src.ui.cli --engine il2cpp --process MyGame.exe --metadata path/to/global-metadata.dat
python -m src.ui.cli --process MyGame.exe --kernel
```

### CS2 Signature Research CLI

```cmd
pip install capstone pefile
python -m src.ui.sigcli validate --preset extended --module-dir "C:\Path\To\CS2\game\csgo\bin\win64"
python -m src.ui.sigcli scan --pack cs2_sigs.hpp --module-dir "C:\Path\To\CS2\game\csgo\bin\win64"
python -m src.ui.sigcli discover client.dll --module-dir "C:\Path\To\CS2\game\csgo\bin\win64" --string SubmitChatText
python -m src.ui.sigcli func client.dll --module-dir "C:\Path\To\CS2\game\csgo\bin\win64" --rva 0xC5C2A0
```

The research CLI validates built-in CS2 tables, parses `#define NAME_PATTERN "..."`
packs, scans exports such as decorated `tier0.dll` symbols, finds string xrefs,
and generates masked candidate signatures for broken patterns. PyGhidra/Ghidra
is optional and only used when `func --ghidra` is requested.

### Building the kernel driver (optional)

```cmd
Build.bat
```

Requires Visual Studio 2022 and the Windows Driver Kit. The resulting `wdfsvc64.sys` must be mapped manually via the in-house driver mapper (`gsd_mapper.exe`). See `driver/BUILD.md`.

---

## C++ SDK Integration Template

The GUI includes a **"Generate C++ Workbench"** option that outputs a standalone ImGui overlay project wired to the analyzed offsets.

> **⚠️ This is a starting point, not a finished product.**
> The generated template compiles and runs, but it will almost certainly require manual edits before it works correctly with your specific target:
> - Pointer chains are game-specific and may need adjusting
> - Analysis logic is stubbed out with placeholder values
> - Driver connection assumes `wdfsvc64.sys` is already mapped
> - Game protection behavior varies — what works on one game may not work on another
>
> Treat it as scaffolding. You will need C++ knowledge to adapt it.

---

## Output

Analysis results are written to `output/<ProcessName>/`:

| File | Contents |
|---|---|
| `OffsetsInfo.json` | GNames / GObjects / GWorld RVAs |
| `Classes.json` | All UClasses / structs with fields |
| `Enums.json` | All UEnum entries |
| `SDK/` | Generated C++ header files |
| `health.txt` | Analysis quality report |

Source 2 / CS2 analysis also writes:

| File | Contents |
|---|---|
| `cs2_schemas.hpp` | Aggregated Source 2 classes, fields, enums, and schema metadata |
| `cs2_offsets.hpp/json` | Engine global RVAs |
| `cs2_prediction.hpp/json` | Prediction functions and internal command-structure offsets |
| `cs2_buttons.hpp/json` | Runtime key-button state RVAs from the `KeyButton` list |
| `cs2_interfaces.hpp/json` | `CreateInterface` registry RVAs by module |
| `cs2_info.json` | Build number, module inventory, resolved counts, and first-class health failures |

---

## Steam Library Scanner

The GUI includes a Steam library scanner that detects which of your installed/owned games use supported engines and whether kernel mode is recommended.

> **Status:** This is a triage helper, not a guarantee. Scanning large libraries may take a long time and results should be confirmed against the target before analysis.

---

## Tested Engine Versions

Engine versions validated during development:

- Unreal Engine 5.1, 5.3, 5.4, 5.5
- Unreal Engine 4.22 through 4.27
- Unity IL2CPP (various versions)
- Unity Mono (various versions)
- Source 2 (CS2)

---

## Project Structure

```
src/
  core/         Memory, driver IPC, PE parser, diagnostics
  engines/
    ue/         Unreal Engine analyzer (GNames, GObjects, GWorld, SDK walker)
    il2cpp/     Unity IL2CPP metadata parser
    mono/       Unity Mono assembly analyzer
    source/     Source Engine netvar scanner
    source2/    Source 2 schema scanner
  ui/           GUI (app.py) and CLI (cli.py)
  output/       JSON writer, SDK generator, template generator
native/         Optional C++ user-mode memory backend DLL
driver/         Kernel driver source (KMDF, C)
```

---

## License

MIT
