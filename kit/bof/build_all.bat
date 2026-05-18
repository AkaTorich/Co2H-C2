@echo off
REM build_all.bat -- compile all single-file BOFs to .obj for x64 and x86.
REM
REM BOF is a COFF object file (.obj), not an executable. Beacon loader
REM parses sections, resolves relocations, and dispatches to `go()`.
REM No linking required -- just /c compile.
REM
REM Output: bin\<name>.x64.o and bin\<name>.x86.o (Cobalt Strike convention)

setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set BIN_DIR=%SCRIPT_DIR%bin
REM Strip trailing backslash for /I
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
echo  Co2H BOF Kit -- Build All
echo  Architectures: x64, x86
echo ============================================
echo.

REM ===== Pass 1: x64 ==========================================================
echo ------ x64 ------
call "!VCVARS!" amd64 >nul 2>&1
cd /d "%SCRIPT_DIR%"

for /d %%D in ("%SCRIPT_DIR%bof_*") do (
    set "DIRNAME=%%~nxD"
    if exist "%%D\!DIRNAME!.c" call :build_one "%%D\!DIRNAME!.c" "!DIRNAME!" "x64"
)

echo.

REM ===== Pass 2: x86 ==========================================================
echo ------ x86 ------
call "!VCVARS!" amd64_x86 >nul 2>&1
cd /d "%SCRIPT_DIR%"

for /d %%D in ("%SCRIPT_DIR%bof_*") do (
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
REM %1 = source .c file
REM %2 = output name (BOF base name)
REM %3 = arch (x64/x86)
set "SRC=%~1"
set "NAME=%~2"
set "ARCH=%~3"
set "OUT_OBJ=%BIN_DIR%\!NAME!.!ARCH!.o"
set /a TOTAL+=1

echo [*] Building: !NAME! (!ARCH!) ...

cl.exe /nologo /c /GS- /Zl /W3 /wd4100 /TC /O2 ^
    /I"%INC_DIR%" ^
    /Fo"!OUT_OBJ!" "!SRC!" >nul 2>&1
if errorlevel 1 (
    echo     [X] FAILED: !NAME!.!ARCH!
    set /a FAIL+=1
    goto :eof_one
)

for %%F in ("!OUT_OBJ!") do set "FSIZE=%%~zF"
echo     [+] OK: !FSIZE! bytes -- bin\!NAME!.!ARCH!.o
set /a OK+=1

:eof_one
goto :eof
