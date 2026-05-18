@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"
set ROOT=%~dp0..
set SCELOT=%ROOT%\scelot.exe
set OUT=%~dp0out
if not exist "%OUT%" mkdir "%OUT%"

set HELLO=%~dp0..\build\tests\out\hello_msg.exe
set ARGS=%~dp0..\build\tests\out\args_echo.exe
set DLL=%~dp0..\build\tests\out\dll_run.dll
set NETEXE=%~dp0payloads\net_hello\NetHello.exe

echo === [1] hello_msg ===
"%SCELOT%" "%HELLO%" -o "%OUT%\hello_msg.bin" --exe "%OUT%\hello_msg_run.exe" --exit return
echo gen_exit=!ERRORLEVEL!

echo === [2] args_echo ===
"%SCELOT%" "%ARGS%" -o "%OUT%\args_echo.bin" --args "args_echo.exe alpha beta gamma" --exe "%OUT%\args_echo_run.exe" --exit return
echo gen_exit=!ERRORLEVEL!

echo === [3] dll_run ===
"%SCELOT%" "%DLL%" -o "%OUT%\dll_run.bin" -e Run --args "hello from scelot" --exe "%OUT%\dll_run_run.exe" --exit return
echo gen_exit=!ERRORLEVEL!

echo === [4] NetHello ===
"%SCELOT%" "%NETEXE%" -o "%OUT%\nethello.bin" --args "alpha beta" --exe "%OUT%\nethello_run.exe" --exit return
echo gen_exit=!ERRORLEVEL!

echo === [5] polymorphism: 5x SHA256 of regenerated hello_msg.bin ===
for /L %%i in (1,1,5) do (
    "%SCELOT%" "%HELLO%" -o "%OUT%\poly_%%i.bin" --exit return >nul
    for /f "skip=1 tokens=*" %%h in ('certutil -hashfile "%OUT%\poly_%%i.bin" SHA256 ^| findstr /R "^[0-9a-f ]"') do (
        echo   poly_%%i: %%h
    )
)

echo === [6] sizes ===
dir /b /s "%OUT%\*.bin"
exit /b 0
