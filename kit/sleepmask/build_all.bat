@echo off
REM build_all.bat -- compile all sleep mask variants for x64 and x86.
REM
REM Can be run from anywhere. Automatically sets up MSVC environment.
REM Requires: Visual Studio 2022 + Python 3
REM
REM Output: bin\<name>.x64.bin and bin\<name>.x86.bin for each mask variant.

setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set BIN_DIR=%SCRIPT_DIR%bin
set MASKS_DIR=%SCRIPT_DIR%masks
REM Strip trailing backslash for /I (cl.exe treats \" as escaped quote)
set "INC_DIR=%SCRIPT_DIR:~0,-1%"

REM --- Detect Visual Studio installation ---
set "VCVARS="
if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat"
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
)
if "!VCVARS!"=="" (
    echo [X] ERROR: Visual Studio 2022 not detected.
    exit /b 1
)

if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

set TOTAL=0
set OK=0
set FAIL=0

echo ============================================
echo  Co2H Sleep Mask Kit -- Build All Variants
echo  Architectures: x64, x86
echo ============================================
echo.

REM ===== Pass 1: x64 ==========================================================
echo ------ x64 ------
call "!VCVARS!" amd64 >nul 2>&1
cd /d "%SCRIPT_DIR%"

for /d %%D in ("%MASKS_DIR%\*") do (
    if exist "%%D\mask.c" (
        call :build_one "%%D\mask.c" "%%~nxD" "x64" ""
    )
)
call :build_one "%SCRIPT_DIR%default_mask.c" "default" "x64" ""

echo.

REM ===== Pass 2: x86 ==========================================================
echo ------ x86 ------
call "!VCVARS!" amd64_x86 >nul 2>&1
cd /d "%SCRIPT_DIR%"

REM Pre-compile x86 CRT helpers (provides __allmul etc.)
set "HELPERS_OBJ=%BIN_DIR%\_x86_helpers.obj"
cl.exe /nologo /c /O2 /GS- /Zl /TC /Fo"!HELPERS_OBJ!" "%SCRIPT_DIR%..\x86_helpers.c" >nul 2>&1
if errorlevel 1 (
    echo [X] FAILED to compile x86_helpers.c
    set /a FAIL+=6
    goto :summary
)

for /d %%D in ("%MASKS_DIR%\*") do (
    if exist "%%D\mask.c" (
        call :build_one "%%D\mask.c" "%%~nxD" "x86" "!HELPERS_OBJ!"
    )
)
call :build_one "%SCRIPT_DIR%default_mask.c" "default" "x86" "!HELPERS_OBJ!"

REM Cleanup helpers obj
if exist "!HELPERS_OBJ!" del /q "!HELPERS_OBJ!"

:summary
echo.
echo ============================================
echo  Results: %OK%/%TOTAL% succeeded, %FAIL% failed
echo  Output:  %BIN_DIR%\
echo ============================================

if %FAIL% GTR 0 exit /b 1
exit /b 0

REM ===========================================================================
:build_one
REM %1 = source .c file
REM %2 = output name
REM %3 = arch (x64/x86)
REM %4 = extra obj to link (empty for x64)
set "SRC=%~1"
set "NAME=%~2"
set "ARCH=%~3"
set "EXTRA_OBJ=%~4"
set "OUT_NAME=!NAME!.!ARCH!"
set /a TOTAL+=1

echo [*] Building: !NAME! (!ARCH!) ...

REM Compile (/arch:IA32 for x86 prevents SSE ? SSE loads use absolute addr, not PIC)
set "ARCH_FLAG="
if "!ARCH!"=="x86" set "ARCH_FLAG=/arch:IA32"
cl.exe /nologo /c /O2 /GS- /Zl /W3 /wd4100 /wd4152 /wd4055 /TC !ARCH_FLAG! ^
    /I"%INC_DIR%" ^
    /Fo"%BIN_DIR%\!OUT_NAME!.obj" "!SRC!" >nul 2>&1
if errorlevel 1 (
    echo     [X] COMPILE FAILED: !OUT_NAME!
    set /a FAIL+=1
    goto :eof_one
)

REM Link (include extra obj for x86 math helpers)
link.exe /nologo /NODEFAULTLIB /ENTRY:sleep_mask_entry ^
    /SUBSYSTEM:CONSOLE /SECTION:.text,ER /MERGE:.rdata=.text ^
    /OUT:"%BIN_DIR%\!OUT_NAME!.exe" "%BIN_DIR%\!OUT_NAME!.obj" !EXTRA_OBJ! >nul 2>&1
if errorlevel 1 (
    echo     [X] LINK FAILED: !OUT_NAME!
    set /a FAIL+=1
    goto :eof_one
)

REM Extract .text section
python "%SCRIPT_DIR%..\extract_section.py" ^
    "%BIN_DIR%\!OUT_NAME!.exe" .text "%BIN_DIR%\!OUT_NAME!.bin" >nul 2>&1
if errorlevel 1 (
    echo     [X] EXTRACT FAILED: !OUT_NAME!
    set /a FAIL+=1
    goto :eof_one
)

for %%F in ("%BIN_DIR%\!OUT_NAME!.bin") do set "FSIZE=%%~zF"
echo     [+] OK: !FSIZE! bytes -- bin\!OUT_NAME!.bin
set /a OK+=1

:eof_one
if exist "%BIN_DIR%\!OUT_NAME!.obj" del /q "%BIN_DIR%\!OUT_NAME!.obj"
if exist "%BIN_DIR%\!OUT_NAME!.exe" del /q "%BIN_DIR%\!OUT_NAME!.exe"
goto :eof
