@echo off
REM build.bat -- compile ICOPatcher.exe (x64, MSVC)

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

REM compile resource (icon)
rc.exe /nologo /fo resource.res resource.rc
if errorlevel 1 (
    echo [X] resource compile failed
    exit /b 1
)

REM compile + link
cl.exe /nologo /O2 /W3 /EHsc /MT ICOPatcher.cpp resource.res ^
    /link /SUBSYSTEM:WINDOWS user32.lib gdi32.lib comdlg32.lib shell32.lib
if errorlevel 1 (
    echo [X] build failed
    exit /b 1
)

del /q ICOPatcher.obj resource.res 2>nul
echo [+] OK: ICOPatcher.exe
