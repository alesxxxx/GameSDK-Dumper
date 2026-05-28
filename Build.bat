@echo off
setlocal EnableExtensions EnableDelayedExpansion
title GameSDK-Kit Build
cd /d "%~dp0"

echo.
echo   +------------------------------------------+
echo   ^|          GameSDK-Kit            ^|
echo   ^|      Multi-Engine SDK Toolkit      ^|
echo   +------------------------------------------+
echo.
echo   Build started  -  %date%  %time%
echo.

if not exist "bin" mkdir "bin"

echo   +------------------------------------------+
echo   ^|  Pre-flight Checks                      ^|
echo   +------------------------------------------+
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo   [FAIL]  Python not found.
    echo          Install Python 3.10+ from python.org and re-run.
    echo.
    pause
    exit /b 1
)
for /f "delims=" %%v in ('python --version 2^>^&1') do set "PYVER=%%v"
echo   [ OK ]  %PYVER%

python -c "import PyInstaller" >nul 2>nul
if errorlevel 1 (
    echo   [AUTO]  PyInstaller not found -- installing...
    pip install pyinstaller >nul 2>&1
    python -c "import PyInstaller" >nul 2>nul
    if errorlevel 1 (
        echo   [FAIL]  Could not install PyInstaller. Run: pip install pyinstaller
        echo.
        pause
        exit /b 1
    )
)

python -c "import dnfile" >nul 2>nul
if errorlevel 1 (
    echo   [AUTO]  dnfile not found -- installing...
    pip install dnfile >nul 2>&1
)
python -c "import capstone, pefile" >nul 2>nul
if errorlevel 1 (
    echo   [AUTO]  signature research dependencies not found -- installing...
    pip install capstone pefile >nul 2>&1
)
for /f "delims=" %%v in ('python -c "import PyInstaller; print(PyInstaller.__version__)" 2^>^&1') do set "PIVER=%%v"
echo   [ OK ]  PyInstaller v%PIVER%

set "MSBUILD="
for %%p in (
    "%ProgramFiles%\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
) do (
    if exist %%~p (
        set "MSBUILD=%%~p"
        goto :found_msbuild
    )
)
where MSBuild.exe >nul 2>nul
if not errorlevel 1 (
    for /f "delims=" %%i in ('where MSBuild.exe') do (
        set "MSBUILD=%%i"
        goto :found_msbuild
    )
)
echo   [FAIL]  MSBuild not found.
echo          Visual Studio MSBuild is required to build the native Steam ownership helper.
echo.
pause
exit /b 1

:found_msbuild
echo   [ OK ]  MSBuild found
echo          %MSBUILD%
echo.

echo   +------------------------------------------+
echo   ^|  Step 1 / 5  --  Kernel Driver          ^|
echo   +------------------------------------------+
echo.

if not exist "driver\driver.vcxproj" (
    echo   [SKIP]  driver\driver.vcxproj not found.
    echo.
    goto :skip_driver
)

echo   Compiling driver\driver.vcxproj  ^(Release x64^)
echo.
"%MSBUILD%" driver\driver.vcxproj /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo
echo.

if exist "bin\wdfsvc64.sys" (
    echo   [ OK ]  bin\wdfsvc64.sys
) else (
    echo   [FAIL]  bin\wdfsvc64.sys -- check WDK installation and MSBuild output above.
)

:skip_driver
echo.

echo   +------------------------------------------+
echo   ^|  Step 2 / 5  --  In-House Driver Mapper  ^|
echo   +------------------------------------------+
echo.

if not exist "mapper\mapper.sln" (
    echo   [SKIP]  mapper\mapper.sln not found.
    echo.
    goto :skip_mapper
)

echo   Compiling mapper\mapper.sln  ^(Release x64^)
echo.
"%MSBUILD%" mapper\mapper.sln /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo
echo.

if exist "mapper\x64\Release\gsd_mapper.exe" (
    copy /y "mapper\x64\Release\gsd_mapper.exe" "bin\gsd_mapper.exe" >nul
    echo   [ OK ]  bin\gsd_mapper.exe
) else (
    echo   [FAIL]  gsd_mapper.exe could not be built.
)

:skip_mapper
echo.

echo   +------------------------------------------+
echo   ^|  Step 3 / 5  --  Steam Ownership Helper ^|
echo   +------------------------------------------+
echo.

if exist "bin\SteamLoginHelper.exe" del /q "bin\SteamLoginHelper.exe" >nul 2>nul
if exist "bin\x86" rmdir /s /q "bin\x86" >nul 2>nul
if exist "bin\x64" rmdir /s /q "bin\x64" >nul 2>nul
if exist "bin\runtimes" rmdir /s /q "bin\runtimes" >nul 2>nul
if exist "bin\BouncyCastle.Cryptography.dll" del /q "bin\BouncyCastle.Cryptography.dll" >nul 2>nul
if exist "bin\Microsoft.Web.WebView2.Core.dll" del /q "bin\Microsoft.Web.WebView2.Core.dll" >nul 2>nul
if exist "bin\Microsoft.Web.WebView2.WinForms.dll" del /q "bin\Microsoft.Web.WebView2.WinForms.dll" >nul 2>nul
if exist "bin\Microsoft.Web.WebView2.Wpf.dll" del /q "bin\Microsoft.Web.WebView2.Wpf.dll" >nul 2>nul
if exist "bin\System.Data.SQLite.dll" del /q "bin\System.Data.SQLite.dll" >nul 2>nul

"%MSBUILD%" src\ui\SteamLoginHelper.csproj /t:Restore /v:minimal /nologo >nul 2>&1
"%MSBUILD%" src\ui\SteamLoginHelper.csproj /p:Configuration=Release /p:Platform=x86 /v:minimal /nologo

if errorlevel 1 (
    echo.
    echo   [SKIP]  SteamLoginHelper.exe could not be built.
    echo          Install the .NET Framework 4.8 Developer Pack from:
    echo          https://aka.ms/msbuild/developerpacks
    echo          The toolkit works without it -- Steam ownership checks will be disabled.
) else if exist "bin\SteamLoginHelper.exe" (
    echo   [ OK ]  bin\SteamLoginHelper.exe
)

echo.

echo   +------------------------------------------+
echo   ^|  Step 4 / 5  --  Native Reader Backend  ^|
echo   +------------------------------------------+
echo.

if not exist "native\memory_backend\gamesdk_native.vcxproj" (
    echo   [SKIP]  native\memory_backend\gamesdk_native.vcxproj not found.
    echo.
    goto :skip_native_backend
)

echo   Compiling native\memory_backend\gamesdk_native.vcxproj  ^(Release x64^)
echo.
"%MSBUILD%" native\memory_backend\gamesdk_native.vcxproj /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo
echo.

if exist "native\memory_backend\x64\Release\gamesdk_native.dll" (
    copy /y "native\memory_backend\x64\Release\gamesdk_native.dll" "bin\gamesdk_native.dll" >nul
    echo   [ OK ]  bin\gamesdk_native.dll
) else (
    echo   [SKIP]  gamesdk_native.dll could not be built. User-mode Win32 reads remain available.
)

:skip_native_backend
echo.

echo   +------------------------------------------+
echo   ^|  Step 5 / 5  --  GameSDKKit.exe      ^|
echo   +------------------------------------------+
echo.

if exist "GameSDKKit.exe" (
    echo   .  Removing old GameSDKKit.exe ...
    del "GameSDKKit.exe" >nul 2>nul
)

echo   Running PyInstaller
echo.

python -m PyInstaller --noconfirm --onefile --windowed --log-level WARN ^
    --distpath . ^
    --name "GameSDKKit" ^
    --add-data "src;src" ^
    --add-data "bin;bin" ^
    --hidden-import "src.core.memory" ^
    --hidden-import "src.core.native_backend" ^
    --hidden-import "src.core.scanner" ^
    --hidden-import "src.core.pe_parser" ^
    --hidden-import "src.engines.ue.detector" ^
    --hidden-import "src.engines.ue.gnames" ^
    --hidden-import "src.engines.ue.gobjects" ^
    --hidden-import "src.engines.ue.gworld" ^
    --hidden-import "src.engines.ue.signatures" ^
    --hidden-import "dnfile" ^
    --hidden-import "src.engines.ue.sdk_walker" ^
    --hidden-import "src.engines.il2cpp.metadata" ^
    --hidden-import "src.engines.il2cpp.pe_scanner" ^
    --hidden-import "src.engines.il2cpp.executor" ^
    --hidden-import "src.engines.il2cpp.dumper" ^
    --hidden-import "src.engines.mono.assembly_parser" ^
    --hidden-import "src.engines.mono.mono_scanner" ^
    --hidden-import "src.engines.mono.executor" ^
    --hidden-import "src.engines.mono.dumper" ^
    --hidden-import "src.core.driver" ^
    --hidden-import "src.core.diagnostics" ^
    --hidden-import "src.output.json_writer" ^
    src/ui/app.py

echo.

echo   +------------------------------------------+
echo   ^|  Build Summary                          ^|
echo   +------------------------------------------+
echo.

if exist "bin\wdfsvc64.sys" (
    echo   [ OK ]  bin\wdfsvc64.sys
) else (
    echo   [----]  bin\wdfsvc64.sys       [not built -- install VS + WDK if needed]
)

if exist "bin\gsd_mapper.exe" (
    echo   [ OK ]  bin\gsd_mapper.exe
) else (
    echo   [SKIP]  bin\gsd_mapper.exe     [not built -- check mapper\ mapper.sln and VS installation]
)

if exist "bin\SteamLoginHelper.exe" (
    echo   [ OK ]  bin\SteamLoginHelper.exe
) else (
    echo   [SKIP]  bin\SteamLoginHelper.exe  [install .NET Framework 4.8 Dev Pack to build]
)

if exist "bin\gamesdk_native.dll" (
    echo   [ OK ]  bin\gamesdk_native.dll
) else (
    echo   [SKIP]  bin\gamesdk_native.dll     [native user-mode backend unavailable]
)

if exist "GameSDKKit.exe" (
    echo   [ OK ]  GameSDKKit.exe
) else (
    echo   [FAIL]  GameSDKKit.exe             [check PyInstaller output above]
)

echo.
echo   -------------------------------------------
echo.

if exist "GameSDKKit.exe" (
    echo   Build complete.  Run GameSDKKit.exe to launch.
) else (
    echo   Build failed.  Check the PyInstaller output above for errors.
)

echo.
echo   Build ended  -  %date%  %time%

echo.
pause
