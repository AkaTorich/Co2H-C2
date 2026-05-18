@echo off
rem Sweeping integration test for scelot. Run from the VS Native Tools
rem cmd matching the architecture of the freshly built scelot.exe (or
rem build a separate scelot for each arch and re-run).
rem
rem Steps:
rem   1. Builds all four test payloads.
rem   2. Generates a shellcode .bin + launcher .exe per scenario via scelot.
rem   3. Launches each and reports the exit code.
rem   4. Regenerates hello_msg five times in a row and prints SHA-256 of
rem      every output to verify polymorphism (all five must differ; the
rem      payload still launches identically).
setlocal EnableDelayedExpansion
set ROOT=%~dp0..
set SCELOT=%ROOT%\scelot.exe
set OUT=%~dp0out
if not exist "%OUT%" mkdir "%OUT%"

if not exist "%SCELOT%" (
    echo [!] %SCELOT% not built — run build\build_all.cmd first
    exit /b 1
)
where cl >nul 2>nul || (echo [!] open VS Native Tools cmd first ^(cl.exe missing^) & exit /b 1)

echo === [1] building test payloads ===
call "%~dp0payloads\hello_msg\build.cmd" || goto :fail
call "%~dp0payloads\args_echo\build.cmd" || goto :fail
call "%~dp0payloads\dll_run\build.cmd"   || goto :fail
call "%~dp0payloads\net_hello\build.cmd" || goto :fail

echo.
echo === [2] hello_msg ^(MessageBoxA, no args^) ===
"%SCELOT%" "%~dp0payloads\hello_msg\hello_msg.exe" -o "%OUT%\hello_msg.bin" --exe "%OUT%\hello_msg_run.exe" || goto :fail
"%OUT%\hello_msg_run.exe" "%OUT%\hello_msg.bin"
echo   exit=%ERRORLEVEL%

echo.
echo === [3] args_echo ^(GetCommandLine hook^) ===
"%SCELOT%" "%~dp0payloads\args_echo\args_echo.exe" -o "%OUT%\args_echo.bin" --args "args_echo.exe alpha beta gamma" --exe "%OUT%\args_echo_run.exe" || goto :fail
"%OUT%\args_echo_run.exe" "%OUT%\args_echo.bin"
echo   exit=%ERRORLEVEL%

echo.
echo === [4] dll_run ^(DLL export with args^) ===
"%SCELOT%" "%~dp0payloads\dll_run\dll_run.dll" -o "%OUT%\dll_run.bin" -e Run --args "hello from scelot" --exe "%OUT%\dll_run_run.exe" || goto :fail
"%OUT%\dll_run_run.exe" "%OUT%\dll_run.bin"
echo   exit=%ERRORLEVEL%

echo.
echo === [5] NetHello ^(in-memory CLR hosting^) ===
"%SCELOT%" "%~dp0payloads\net_hello\NetHello.exe" -o "%OUT%\nethello.bin" --args "alpha beta" --exe "%OUT%\nethello_run.exe" || goto :fail
"%OUT%\nethello_run.exe" "%OUT%\nethello.bin"
echo   exit=%ERRORLEVEL%

echo.
echo === [6] polymorphism: 5x SHA-256 of regenerated hello_msg.bin ===
for /L %%i in (1,1,5) do (
    "%SCELOT%" "%~dp0payloads\hello_msg\hello_msg.exe" -o "%OUT%\poly_%%i.bin" >nul || goto :fail
    for /f "tokens=*" %%h in ('certutil -hashfile "%OUT%\poly_%%i.bin" SHA256 ^| findstr /R "^[0-9a-f]"') do (
        echo   poly_%%i: %%h
    )
)

echo.
echo === [7] polymorphism: each regenerated bin still launches ===
for /L %%i in (1,1,5) do (
    "%OUT%\hello_msg_run.exe" "%OUT%\poly_%%i.bin"
    echo   poly_%%i exit=!ERRORLEVEL!
)

echo.
echo === all done ===
exit /b 0

:fail
echo.
echo === FAILED ===
exit /b 1
