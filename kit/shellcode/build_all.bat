@echo off
REM build_all.bat -- compile all sc_*.c shellcodes to raw .text bytes.
REM
REM Output: bin\<name>.x64.bin and bin\<name>.x86.bin
REM
REM Flags:
REM   /c         -- compile only (we extract .text from .obj directly)
REM   /GS-       -- no stack cookies (no __security_*)
REM   /O1 /Os    -- optimize for size
REM   /Zl        -- omit default-library refs
REM   /TC        -- treat as C
REM   /Gs999999  -- disable stack probing (no __chkstk dependency)

setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set BIN_DIR=%SCRIPT_DIR%bin

REM Shared extract_section.py in kit/ root
set "EXTRACT_PY=%SCRIPT_DIR%..\extract_section.py"
if not exist "%EXTRACT_PY%" (
    echo [X] ERROR: extract_section.py not found at %EXTRACT_PY%
    exit /b 1
)

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
echo  Co2H Shellcode Kit -- Build All
echo ============================================
echo.

REM ===== x64 ==================================================================
echo ------ x64 ------
call "!VCVARS!" amd64 >nul 2>&1
cd /d "%SCRIPT_DIR%"
for /d %%D in ("%SCRIPT_DIR%sc_*") do (
    set "DIRNAME=%%~nxD"
    if exist "%%D\!DIRNAME!.c" call :build_one "%%D\!DIRNAME!.c" "!DIRNAME!" "x64"
)

echo.

REM ===== x86 ==================================================================
echo ------ x86 ------
call "!VCVARS!" amd64_x86 >nul 2>&1
cd /d "%SCRIPT_DIR%"
for /d %%D in ("%SCRIPT_DIR%sc_*") do (
    set "DIRNAME=%%~nxD"
    if exist "%%D\!DIRNAME!.c" call :build_one "%%D\!DIRNAME!.c" "!DIRNAME!" "x86"
)

echo.
echo ============================================
echo  Results: %OK%/%TOTAL% succeeded, %FAIL% failed
echo  Output:  %BIN_DIR%\
echo ============================================

if %FAIL% GTR 0 exit /b 1
exit /b 0

REM ===========================================================================
:build_one
set "SRC=%~1"
set "NAME=%~2"
set "ARCH=%~3"
set "OUT_OBJ=%BIN_DIR%\!NAME!.!ARCH!.obj"
set "OUT_BIN=%BIN_DIR%\!NAME!.!ARCH!.bin"
set /a TOTAL+=1

echo [*] Building: !NAME! (!ARCH!) ...

REM /arch:IA32 for x86 -- disable SSE (its loads are not PIC-safe)
set "ARCH_FLAG="
if "!ARCH!"=="x86" set "ARCH_FLAG=/arch:IA32"

REM Compile only -- no linking. extract_section.py understands COFF .obj.
cl.exe /nologo /c /GS- /O1 /Os /Zl /TC /Gs999999 /W3 /wd4100 !ARCH_FLAG! ^
    /Fo"!OUT_OBJ!" "!SRC!" >nul 2>&1
if errorlevel 1 (
    echo     [X] COMPILE FAILED: !NAME!.!ARCH!
    set /a FAIL+=1
    goto :eof_one
)

REM Extract .text from COFF .obj -> raw PIC blob
python "%EXTRACT_PY%" "!OUT_OBJ!" .text "!OUT_BIN!" >nul 2>&1
if errorlevel 1 (
    echo     [X] EXTRACT FAILED: !NAME!.!ARCH!
    set /a FAIL+=1
    goto :eof_one
)

for %%F in ("!OUT_BIN!") do set "FSIZE=%%~zF"
echo     [+] OK: !FSIZE! bytes -- bin\!NAME!.!ARCH!.bin
set /a OK+=1

:eof_one
if exist "!OUT_OBJ!" del /q "!OUT_OBJ!"
goto :eof
