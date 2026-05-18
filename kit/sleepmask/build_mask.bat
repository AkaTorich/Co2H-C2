@echo off
REM build_mask.bat — compile a sleep mask .c file into raw PIC shellcode (mask.bin).
REM
REM Usage:  build_mask.bat [source.c]
REM         Default source: default_mask.c
REM
REM Requirements:
REM   - Visual Studio Developer Command Prompt (cl.exe + link.exe in PATH)
REM   - Python 3 (for extract_section.py)
REM
REM Output: mask.bin (raw .text bytes, ready for artifact-gen --mask)

setlocal
set SRC=%1
if "%SRC%"=="" set SRC=default_mask.c

set OBJ=%~n1.obj
if "%1"=="" set OBJ=default_mask.obj
set EXE=_mask_tmp.exe
set OUT=mask.bin

echo [*] Compiling %SRC% ...
cl.exe /nologo /c /O2 /GS- /Zl /W4 /wd4100 /TC %SRC%
if errorlevel 1 goto :fail

echo [*] Linking (extract .text) ...
link.exe /nologo /NODEFAULTLIB /ENTRY:sleep_mask_entry /SUBSYSTEM:CONSOLE ^
         /SECTION:.text,ER /MERGE:.rdata=.text /OUT:%EXE% %OBJ%
if errorlevel 1 goto :fail

echo [*] Extracting .text section to %OUT% ...
python "%~dp0..\extract_section.py" %EXE% .text %OUT%
if errorlevel 1 (
    echo [!] extract_section.py failed. Trying dumpbin fallback...
    goto :dumpbin_fallback
)

echo [+] Done: %OUT% (%~z0 bytes)
echo     Use: artifact-gen ... --mask %OUT% ...
del /q %OBJ% %EXE% 2>nul
goto :eof

:dumpbin_fallback
REM Fallback: use dumpbin to find .text RVA and size, then extract raw bytes.
echo [*] Extracting via dumpbin...
for /f "tokens=1,2,3" %%a in ('dumpbin /headers %EXE% ^| findstr /c:".text"') do (
    set TEXT_SIZE=%%a
    set TEXT_RVA=%%b
)
REM This is approximate — prefer the Python script.
echo [!] Dumpbin fallback not fully implemented. Use extract_section.py.
goto :fail

:fail
echo [!] Build failed.
del /q %OBJ% %EXE% 2>nul
exit /b 1
