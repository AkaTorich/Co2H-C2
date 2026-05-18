@echo off
REM build.bat -- compile hash_gen.exe (x64)

setlocal

set "VCVARS="
if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat"
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
)
if "%VCVARS%"=="" (
    echo [X] Visual Studio 2022 not found.
    exit /b 1
)

call "%VCVARS%" amd64 >nul 2>&1
cd /d "%~dp0"

cl.exe /nologo /O2 /W3 hash_gen.c
if errorlevel 1 (
    echo [X] build failed
    exit /b 1
)

del /q hash_gen.obj 2>nul
echo [+] OK: hash_gen.exe
