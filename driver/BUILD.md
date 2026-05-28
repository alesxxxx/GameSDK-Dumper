# Building the Kernel Driver

## Prerequisites

1. **Visual Studio 2019/2022** with C++ Desktop Development workload
2. **Windows Driver Kit (WDK)** matching your VS version
   - Download from: https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
3. **Windows SDK** (usually installed with VS)

## Building wdfsvc64.sys

### Option A: Visual Studio
1. Open `driver.vcxproj` in Visual Studio
2. Select **Release | x64**
3. Build (Ctrl+Shift+B)
4. Output: `bin\wdfsvc64.sys`

### Option B: Command Line (Developer Command Prompt)
```
msbuild driver.vcxproj /p:Configuration=Release /p:Platform=x64
```

## Building the In-House Driver Mapper

1. Open `mapper\mapper.sln` in Visual Studio
2. Select **Release | x64**
3. Build
4. Output: `mapper\x64\Release\gsd_mapper.exe`

Or via command line:
```
msbuild mapper\mapper.sln /p:Configuration=Release /p:Platform=x64
```

## Loading the Driver

```
# Run as Administrator
bin\gsd_mapper.exe bin\wdfsvc64.sys
```

## Requirements for Loading

- **Secure Boot**: Must be DISABLED in BIOS
- **Hyper-V / VBS**: Should be disabled for best compatibility
- **Anti-virus**: May need exclusion for bin\ directory
- **Windows 11 24H2+**: Microsoft Driver Blocklist may block the Intel NAL driver.
  Disable it via:
  ```
  reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 0 /f
  ```
  Then reboot.

## Verifying the Driver

After loading, run the toolkit with `--kernel` flag:
```
python -m src.ui.cli --kernel -p YourGame.exe
```

If you see `[Driver] Connected`, the driver is working.

## Debug Build

To build with debug logging (shows DbgPrint output in DebugView):
```
msbuild driver.vcxproj /p:Configuration=Debug /p:Platform=x64
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| gsd_mapper fails | Secure Boot enabled | Disable in BIOS |
| gsd_mapper fails | HVCI/VBS active | Disable in Windows Security |
| gsd_mapper fails | Driver Blocklist | Disable via registry (see above) |
| Driver loaded but toolkit can't connect | Section creation failed | Check DebugView for errors |
| CR3 lookup returns 0 | Wrong EPROCESS offset | Update `EPROCESS_DTB_OFFSET` in comm.h for your Windows build |
